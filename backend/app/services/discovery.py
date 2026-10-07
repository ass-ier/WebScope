import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit
from xml.etree import ElementTree

from bs4 import BeautifulSoup
from sqlalchemy import select

from app import models as m
from app.services.redaction import clean, url as redact_url
from app.services.scope import PolicyError, canonical_url
from app.services.store import event, evidence


def endpoint(db, assessment_id, scope, url, source, evidence_id, method="GET", parameters=None, details=None):
    try:
        normalized = canonical_url(url)
    except PolicyError as exc:
        event(db, assessment_id, "ENDPOINT_REJECTED", str(exc), {"source": source, "url": redact_url(url)})
        return None
    normalized = redact_url(normalized)
    existing = db.scalar(
        select(m.Endpoint).where(
            m.Endpoint.assessment_id == assessment_id,
            m.Endpoint.url == normalized,
            m.Endpoint.method == method,
        )
    )
    if existing:
        return existing
    try:
        scope.validate(normalized)
        in_scope = True
    except PolicyError:
        in_scope = False
    params = (
        parameters
        if parameters is not None
        else [{"name": k, "in": "query", "observed": True} for k, _ in parse_qsl(urlsplit(normalized).query)]
    )
    item = m.Endpoint(
        assessment_id=assessment_id,
        evidence_id=evidence_id,
        url=normalized,
        method=method,
        source=source,
        parameters=clean(params),
        details=clean(details or {}),
        in_scope=in_scope,
    )
    db.add(item)
    db.flush()
    event(
        db,
        assessment_id,
        "ENDPOINT_DISCOVERED",
        f"Endpoint inventoried from {source}",
        {"endpoint_id": item.id, "evidence_id": evidence_id, "in_scope": in_scope},
    )
    return item


def harvest(db, assessment_id, scope, tx):
    result = tx.response
    body = result.get("body", "")
    content_type = result.get("content_type", "")
    base = tx.url
    root = endpoint(db, assessment_id, scope, base, "HTTP", tx.evidence_id, tx.method)
    root.content_type = content_type
    root.authentication = (
        "CHALLENGE_OBSERVED"
        if tx.status_code == 401
        else "FORBIDDEN_OBSERVED"
        if tx.status_code == 403
        else "NOT_CHALLENGED"
    )
    if result.get("headers", {}).get("allow"):
        root.details = {**root.details, "allowed_methods_observed": result["headers"]["allow"]}
    tx.endpoint_id = root.id
    candidates = []
    source_id = tx.evidence_id
    if "html" in content_type:
        html = evidence(
            db,
            assessment_id,
            "HTML",
            base,
            "Collected HTML (redacted)",
            {"source_evidence_id": tx.evidence_id},
            body,
        )
        source_id = html.id
        soup = BeautifulSoup(body, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "iframe", "img", "form"], limit=1000):
            name = tag.name
            attr = "action" if name == "form" else "href" if name in ("a", "link") else "src"
            href = tag.get(attr)
            if (
                not isinstance(href, str)
                or not href.strip()
                or href.startswith(("#", "mailto:", "tel:", "data:", "javascript:"))
            ):
                continue
            method = str(tag.get("method", "GET")).upper() if name == "form" else "GET"
            if method not in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"):
                method = "GET"
            params = (
                [
                    {
                        "name": el.get("name"),
                        "in": "query" if method == "GET" else "body",
                        "type": el.get("type", "text"),
                    }
                    for el in tag.find_all(["input", "select", "textarea"])
                    if el.get("name")
                ]
                if name == "form"
                else None
            )
            kind = (
                "form"
                if name == "form"
                else "script"
                if name == "script"
                else "resource"
                if name in ("img", "link")
                else "page"
            )
            candidates.append(
                (
                    urljoin(base, href),
                    method,
                    "FORM" if name == "form" else "HTML",
                    params,
                    {
                        "source_url": base,
                        "kind": kind,
                        "relation": "loads" if kind in ("script", "resource") else "links_to",
                    },
                )
            )
        if scope.config.javascript:
            for script in soup.find_all("script", src=False, limit=200):
                candidates.extend(js_candidates(script.get_text(), base))
    elif "javascript" in content_type and scope.config.javascript:
        js = evidence(
            db,
            assessment_id,
            "JAVASCRIPT",
            base,
            "Collected JavaScript (never executed)",
            {"source_evidence_id": tx.evidence_id},
            body,
        )
        source_id = js.id
        candidates.extend(js_candidates(body, base))
    elif urlsplit(base).path.endswith("/robots.txt"):
        for match in re.finditer(r"(?im)^(?:allow|disallow|sitemap):\s*(\S+)", body):
            if "*" not in match[1]:
                candidates.append(
                    (
                        urljoin(base, match[1]),
                        "GET",
                        "ROBOTS",
                        None,
                        {"source_url": base, "relation": "mentions"},
                    )
                )
    elif "xml" in content_type or urlsplit(base).path.endswith("/sitemap.xml"):
        try:
            if "<!DOCTYPE" in body.upper() or "<!ENTITY" in body.upper():
                raise ValueError("DTD and entity declarations are prohibited")
            document = ElementTree.fromstring(body)
            for el in document.iter():
                if el.tag.split("}")[-1] == "loc" and el.text and len(candidates) < 1000:
                    candidates.append(
                        (
                            urljoin(base, el.text.strip()),
                            "GET",
                            "SITEMAP",
                            None,
                            {"source_url": base, "relation": "lists"},
                        )
                    )
        except (ElementTree.ParseError, ValueError) as exc:
            event(db, assessment_id, "SITEMAP_PARSE_FAILED", str(exc), {"evidence_id": tx.evidence_id})
    found = []
    for url, method, source, params, details in candidates[:1000]:
        item = endpoint(db, assessment_id, scope, url, source, source_id, method, params, details)
        if item:
            found.append(item)
    return found


def js_candidates(body, base):
    result = []
    pattern = r"""(?:fetch\s*\(|axios\.(?:get|post|put|delete)\s*\(|url\s*:)\s*["']([^"'`\s]+)["']"""
    for match in re.finditer(pattern, body):
        # Inventory only: even apparent GET calls in target JS are not executed.
        method_match = re.search(r"axios\.(post|put|delete)", match[0])
        method = method_match[1].upper() if method_match else "GET"
        result.append(
            (
                urljoin(base, match[1]),
                method,
                "JAVASCRIPT",
                None,
                {"source_url": base, "kind": "api", "relation": "references", "execution": "NEVER"},
            )
        )
    for match in re.finditer(r"(?m)[#@]\s*sourceMappingURL=(\S+)", body):
        result.append(
            (
                urljoin(base, match[1]),
                "GET",
                "JAVASCRIPT",
                None,
                {"source_url": base, "kind": "source_map", "relation": "references"},
            )
        )
    return result


def import_openapi(db, assessment_id, scope, document):
    if len(json.dumps(document)) > 2_000_000:
        raise ValueError("OpenAPI document exceeds 2 MB")
    if not str(document.get("openapi", "")).startswith("3.") or not isinstance(document.get("paths"), dict):
        raise ValueError("An OpenAPI 3.x document with a paths object is required")
    if not isinstance(document.get("components", {}), dict) or not isinstance(
        document.get("security", []), list
    ):
        raise ValueError("OpenAPI components must be an object and security must be an array")
    refs = []

    def inspect(value, depth=0):
        if depth > 30:
            raise ValueError("OpenAPI nesting exceeds 30 levels")
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref":
                    if not isinstance(item, str) or not item.startswith("#/"):
                        raise ValueError("Remote and file OpenAPI references are prohibited")
                    refs.append(item)
                inspect(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                inspect(item, depth + 1)

    inspect(document)

    resolved_nodes = 0

    def resolve(value, seen=()):
        nonlocal resolved_nodes
        resolved_nodes += 1
        if resolved_nodes > 20000:
            raise ValueError("OpenAPI reference expansion exceeds the 20,000-node limit")
        if isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if ref in seen or len(seen) >= 20:
                return {"$ref": ref, "resolution": "recursive schema retained"}
            current = document
            try:
                for part in ref[2:].split("/"):
                    current = current[part.replace("~1", "/").replace("~0", "~")]
            except (KeyError, TypeError) as exc:
                raise ValueError("OpenAPI local reference does not exist") from exc
            return resolve(current, (*seen, ref))
        if isinstance(value, dict):
            return {k: resolve(v, seen) for k, v in value.items()}
        if isinstance(value, list):
            return [resolve(v, seen) for v in value]
        return value

    resolved = resolve(document)
    ev = evidence(
        db,
        assessment_id,
        "ENDPOINT",
        scope.target,
        "Imported OpenAPI specification (inventory only)",
        {"document": resolved, "local_references": refs},
    )

    def server_bases(servers):
        if not isinstance(servers, list) or len(servers) > 20:
            raise ValueError("OpenAPI servers must be an array of at most 20 entries")
        bases = []
        for server in servers or [{"url": scope.target}]:
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                raise ValueError("Each OpenAPI server requires a URL string")
            variables = server.get("variables", {})
            if not isinstance(variables, dict):
                raise ValueError("OpenAPI server variables must be an object")
            base = urljoin(scope.target, server["url"])
            for key, value in variables.items():
                if not isinstance(value, dict) or not isinstance(value.get("default"), (str, int, float)):
                    raise ValueError("OpenAPI server variables require scalar defaults")
                base = base.replace("{" + key + "}", str(value["default"]))
            if "{" in base or "}" in base or urlsplit(base).query or urlsplit(base).fragment:
                raise ValueError("Unresolved or query-bearing OpenAPI server URLs are unsupported")
            bases.append(canonical_url(base))
        return bases

    default_servers = resolved.get("servers", [])
    server_bases(default_servers)
    schemes = resolved.get("components", {}).get("securitySchemes", {})
    if not isinstance(schemes, dict):
        raise ValueError("OpenAPI securitySchemes must be an object")
    count = 0
    for path, operations in resolved["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            raise ValueError("Invalid OpenAPI path item")
        for method, operation in operations.items():
            if method.lower() not in ("get", "head", "options", "post", "put", "patch", "delete"):
                continue
            if not isinstance(operation, dict):
                raise ValueError("Invalid OpenAPI operation")
            security = operation.get("security", resolved.get("security", []))
            inherited_params, operation_params = (
                operations.get("parameters", []),
                operation.get("parameters", []),
            )
            if (
                not isinstance(inherited_params, list)
                or not isinstance(operation_params, list)
                or not isinstance(security, list)
            ):
                raise ValueError("Invalid OpenAPI parameters or security requirements")
            params = inherited_params + operation_params
            if not all(isinstance(p, dict) for p in params):
                raise ValueError("Each OpenAPI parameter must be an object")
            if not all(isinstance(s, dict) for s in security) or not isinstance(
                operation.get("responses", {}), dict
            ):
                raise ValueError("Invalid OpenAPI security requirement or response object")
            servers = operation.get("servers", operations.get("servers", default_servers))
            for base in server_bases(servers):
                if count >= 1000:
                    raise ValueError("OpenAPI import is limited to 1000 endpoint operations")
                item = endpoint(
                    db,
                    assessment_id,
                    scope,
                    base.rstrip("/") + path,
                    "OPENAPI",
                    ev.id,
                    method.upper(),
                    params,
                    {
                        "kind": "api",
                        "operation_id": operation.get("operationId"),
                        "security": security,
                        "security_schemes": schemes,
                        "responses": operation.get("responses", {}),
                        "request_body": operation.get("requestBody"),
                        "execution": "NEVER",
                        "source_url": scope.target,
                    },
                )
                if item:
                    item.authentication = (
                        "DECLARED_REQUIRED" if security and {} not in security else "NONE_DECLARED"
                    )
                    count += 1
    event(
        db,
        assessment_id,
        "OPENAPI_IMPORTED",
        f"Imported {count} operations without requests",
        {"evidence_id": ev.id},
    )
    return {"imported": count, "evidence_id": ev.id}
