import asyncio
import hashlib
import ipaddress
import socket
import time
import zlib
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from app import models as m
from app.services import redaction as redact
from app.services.scope import PolicyError, Scope
from app.services.store import event, evidence


class NetworkRun:
    """One shared gate for HTTP, redirects, DNS, TLS and address resolution."""

    def __init__(self, db, assessment_id, scope: Scope, transport=None, resolver=None):
        self.db = db
        self.assessment_id = assessment_id
        self.scope = scope
        self.config = scope.config
        self.transport = transport
        self.resolver = resolver
        self.count = 0
        self.started = time.monotonic()
        self.last_send = 0.0
        self.lock = asyncio.Lock()
        self.addresses = {}

    def time_limit(self):
        remaining = self.config.max_duration_seconds - (time.monotonic() - self.started)
        if remaining <= 0:
            raise PolicyError("RUN_TIMEOUT", "Execution duration limit reached")
        return min(self.config.timeout_seconds, remaining)

    def log(self, code, url, message):
        ev = evidence(
            self.db, self.assessment_id, code, url, message, {"destination": redact.url(url), "code": code}
        )
        event(
            self.db, self.assessment_id, code, message, {"evidence_id": ev.id, "destination": redact.url(url)}
        )
        self.db.commit()
        return ev

    async def reserve(self, url, kind):
        self.scope.network_allowed(url)
        async with self.lock:
            if self.count >= self.config.max_requests:
                raise PolicyError("BUDGET_EXHAUSTED", "Shared network request budget exhausted")
            wait = max(0, 1 / self.config.rate_per_second - (time.monotonic() - self.last_send))
            if time.monotonic() - self.started + wait >= self.config.max_duration_seconds:
                raise PolicyError("RUN_TIMEOUT", "Execution duration limit reached")
            if wait:
                await asyncio.sleep(wait)
            self.count += 1
            self.last_send = time.monotonic()
            event(
                self.db,
                self.assessment_id,
                "NETWORK_ATTEMPT",
                f"{kind} authorized by central policy",
                {
                    "url": redact.url(url),
                    "operation": kind,
                    "request_number": self.count,
                    "elapsed_seconds": round(self.last_send - self.started, 4),
                },
            )
            self.db.commit()

    async def resolve(self, url):
        self.scope.network_allowed(url)
        parsed = urlsplit(url)
        host = parsed.hostname
        if host in self.addresses:
            return self.addresses[host]
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            result = [self.scope.address(str(literal))]
        else:
            await self.reserve(url, "ADDRESS_RESOLUTION")
            async with asyncio.timeout(self.time_limit()):
                if self.resolver:
                    values = await self.resolver(host)
                else:
                    values = [
                        v[4][0]
                        for v in await asyncio.get_running_loop().getaddrinfo(
                            host,
                            parsed.port or (443 if parsed.scheme == "https" else 80),
                            type=socket.SOCK_STREAM,
                        )
                    ]
            if not values:
                raise PolicyError("DNS_EMPTY", "No addresses returned for the scoped hostname")
            # Reject mixed public/private answers instead of choosing a convenient safe address.
            result = sorted({self.scope.address(v) for v in values})
        self.addresses[host] = result
        return result

    async def request(self, url, method="GET", headers=None):
        if method not in ("GET", "HEAD", "OPTIONS"):
            self.log("METHOD_BLOCKED", url, "Only read-only GET, HEAD, and OPTIONS are allowed")
            return None
        if headers and any(
            k.lower() in ("host", "connection", "transfer-encoding", "content-length") for k in headers
        ):
            self.log("HEADER_BLOCKED", url, "Caller cannot override transport authority or framing headers")
            return None
        current = url
        for hop in range(self.config.max_redirects + 1):
            try:
                current = self.scope.validate(current)
                addresses = await self.resolve(current)
                await self.reserve(current, f"HTTP_{method}")
            except (PolicyError, TimeoutError, OSError) as exc:
                code = exc.code if isinstance(exc, PolicyError) else "RESOLUTION_FAILED"
                self.log(
                    code,
                    current,
                    str(exc) if isinstance(exc, PolicyError) else "Address resolution failed or timed out",
                )
                return None
            parsed = urlsplit(current)
            authority = f"[{addresses[0]}]" if ":" in addresses[0] else addresses[0]
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            pinned = urlunsplit((parsed.scheme, f"{authority}:{port}", parsed.path, parsed.query, ""))
            request_headers = {
                "Host": parsed.netloc,
                "User-Agent": "WebScope/1.0 (authorized assessment)",
                "Accept-Encoding": "identity",
                **(headers or {}),
            }
            request_data = {
                "method": method,
                "url": redact.url(current),
                "headers": redact.headers(request_headers.items()),
                "query": redact.clean(dict(parse_qsl(parsed.query))),
                "body_metadata": {"sent": False},
                "timestamp": m.now(),
            }
            req_ev = evidence(
                self.db,
                self.assessment_id,
                "HTTP_REQUEST",
                current,
                f"{method} request",
                request_data,
                f"{method} {redact.url(current)} HTTP/1.1\n"
                + "\n".join(f"{k}: {v}" for k, v in request_data["headers"].items()),
            )
            self.db.commit()
            started = time.monotonic()
            try:
                async with asyncio.timeout(self.time_limit()):
                    async with httpx.AsyncClient(
                        transport=self.transport,
                        follow_redirects=False,
                        trust_env=False,
                        timeout=self.config.timeout_seconds,
                    ) as client:
                        async with client.stream(
                            method,
                            pinned,
                            headers=request_headers,
                            extensions={"sni_hostname": parsed.hostname},
                        ) as response:
                            chunks, size, truncated = [], 0, False
                            cached_response = response.is_stream_consumed
                            stream = (
                                response.aiter_bytes(chunk_size=8192)
                                if cached_response
                                else response.aiter_raw(chunk_size=8192)
                            )
                            async for chunk in stream:
                                remaining = self.config.max_body_bytes - size
                                chunks.append(chunk[:remaining])
                                size += min(len(chunk), remaining)
                                if len(chunk) > remaining or size >= self.config.max_body_bytes:
                                    truncated = True
                                    break
                            raw_body = b"".join(chunks)
                            wire_hash = None if cached_response else hashlib.sha256(raw_body).hexdigest()
                            encoding = response.headers.get("content-encoding", "").lower()
                            if encoding in ("gzip", "deflate") and not cached_response:
                                decoder = zlib.decompressobj(
                                    16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
                                )
                                raw_body = decoder.decompress(raw_body, self.config.max_body_bytes)
                                truncated = truncated or bool(decoder.unconsumed_tail) or not decoder.eof
                            elif encoding not in ("", "identity", "gzip", "deflate"):
                                raw_body = b"[Unsupported content encoding: body omitted]"
                                self.log(
                                    "ENCODING_UNSUPPORTED",
                                    current,
                                    "Unsupported content encoding; body was not analyzed",
                                )
                            content_type = response.headers.get("content-type", "")
                            textual = any(
                                v in content_type for v in ("text", "json", "xml", "javascript", "form")
                            )
                            safe_body = (
                                redact.body(raw_body.decode("utf-8", errors="replace"), content_type)
                                if textual
                                else "[Binary body omitted]"
                            )
                            location = response.headers.get("location")
                            result = {
                                "status_code": response.status_code,
                                "headers": redact.headers(response.headers.multi_items()),
                                "content_type": content_type,
                                "content_length": len(raw_body),
                                "wire_content_length": size,
                                "declared_content_length": response.headers.get("content-length"),
                                "body_hash": hashlib.sha256(raw_body).hexdigest(),
                                "body": safe_body,
                                "wire_body_hash": wire_hash,
                                "content_encoding": encoding or "identity",
                                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                                "redirect": redact.url(urljoin(current, location)) if location else None,
                                "truncated": truncated,
                                "hop": hop,
                            }
                            cookies = response.headers.get_list("set-cookie")
                res_ev = evidence(
                    self.db,
                    self.assessment_id,
                    "HTTP_RESPONSE",
                    current,
                    f"HTTP {result['status_code']} response",
                    result,
                    f"HTTP/1.1 {result['status_code']}\n"
                    + "\n".join(f"{k}: {v}" for k, v in result["headers"].items())
                    + "\n\n"
                    + safe_body,
                )
                tx = m.HTTPTransaction(
                    assessment_id=self.assessment_id,
                    evidence_id=res_ev.id,
                    request_evidence_id=req_ev.id,
                    method=method,
                    url=redact.url(current),
                    status_code=result["status_code"],
                    elapsed_ms=result["elapsed_ms"],
                    request=request_data,
                    response=redact.clean(result),
                )
                self.db.add(tx)
                self.db.flush()
                event(
                    self.db,
                    self.assessment_id,
                    "HTTP_COLLECTED",
                    f"HTTP {result['status_code']} collected",
                    {"evidence_id": res_ev.id, "transaction_id": tx.id},
                )
                self.db.commit()
                if location and response.status_code in (301, 302, 303, 307, 308):
                    destination = urljoin(current, location)
                    try:
                        self.scope.validate(destination)
                    except PolicyError:
                        self.log(
                            "REDIRECT_BLOCKED", destination, "Redirect destination blocked by scope policy"
                        )
                        return tx
                    if hop >= self.config.max_redirects:
                        self.log("REDIRECT_LIMIT", destination, "Redirect hop limit reached")
                        return tx
                    current = destination
                    continue
                tx._cookies = [redact.cookie_header(v) for v in cookies]
                return tx
            except (httpx.HTTPError, TimeoutError, OSError, ValueError, zlib.error, PolicyError) as exc:
                code = (
                    "HTTP_TIMEOUT"
                    if isinstance(exc, (TimeoutError, httpx.TimeoutException))
                    else "HTTP_FAILED"
                )
                error = {
                    "error": code,
                    "error_type": type(exc).__name__,
                    "body": "",
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                }
                ev = evidence(self.db, self.assessment_id, code, current, "HTTP collection failed", error)
                self.db.add(
                    m.HTTPTransaction(
                        assessment_id=self.assessment_id,
                        evidence_id=ev.id,
                        request_evidence_id=req_ev.id,
                        method=method,
                        url=redact.url(current),
                        status_code=None,
                        elapsed_ms=error["elapsed_ms"],
                        request=request_data,
                        response=error,
                    )
                )
                event(self.db, self.assessment_id, code, "HTTP collection failed", {"evidence_id": ev.id})
                self.db.flush()
                self.db.commit()
                return None
        return None
