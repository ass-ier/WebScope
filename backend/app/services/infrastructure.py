import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy import select

from app import models as m
from app.services.scope import PolicyError
from app.services.store import event, evidence

DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")


async def collect_dns(run, resolver=None):
    url = run.scope.target
    host = urlsplit(url).hostname
    try:
        ipaddress.ip_address(host)
        run.log("DNS_NOT_APPLICABLE", url, "DNS record discovery is not applicable to an IP-literal target")
        return
    except ValueError:
        pass
    resolver = resolver or dns.asyncresolver.Resolver()
    resolver.lifetime = run.config.timeout_seconds
    for kind in DNS_TYPES:
        try:
            await run.reserve(url, f"DNS_{kind}")
            async with asyncio.timeout(run.time_limit()):
                answer = await run.operation(
                    resolver.resolve(host, kind, search=False, raise_on_no_answer=False)
                )
            records = [v.to_text() for v in answer] if answer.rrset else []
            ttl = answer.rrset.ttl if answer.rrset else None
            resolver_name = str(
                getattr(answer, "nameserver", None) or ",".join(map(str, resolver.nameservers))
            )
            data = {
                "hostname": host,
                "record_type": kind,
                "ttl": ttl,
                "resolver": resolver_name,
                "records": records,
                "timestamp": m.now(),
                "observation": "Development hostname indicator"
                if any(marker in " ".join(records).lower() for marker in ("dev.", "staging.", "test."))
                else "Records observed; unusual values alone are not vulnerabilities",
            }
            previous = run.db.scalars(
                select(m.DNSRecord)
                .where(
                    m.DNSRecord.assessment_id == run.assessment_id,
                    m.DNSRecord.hostname == host,
                    m.DNSRecord.record_type == kind,
                )
                .order_by(m.DNSRecord.created_at.desc())
            ).first()
            data["record_set_comparison"] = (
                "changed since prior collection; rotation or timing may explain this"
                if previous and sorted(previous.records) != sorted(records)
                else "unchanged"
                if previous
                else "first observation"
            )
            if kind == "CNAME":
                data["outside_scope_alias"] = any(
                    record.rstrip(".").lower() not in run.scope.allowed for record in records
                )
                data["alias_policy"] = "Aliases do not authorize collection of their destination hostname"
            ev = evidence(run.db, run.assessment_id, "DNS_RESPONSE", url, f"DNS {kind} observation", data)
            run.db.add(
                m.DNSRecord(
                    assessment_id=run.assessment_id,
                    evidence_id=ev.id,
                    hostname=host,
                    record_type=kind,
                    ttl=ttl,
                    resolver=resolver_name,
                    records=ev.data["records"],
                )
            )
            event(
                run.db, run.assessment_id, "DNS_DISCOVERED", f"DNS {kind} collected", {"evidence_id": ev.id}
            )
            run.db.commit()
        except (dns.exception.DNSException, TimeoutError, OSError, PolicyError) as exc:
            code = exc.code if isinstance(exc, PolicyError) else "DNS_FAILED"
            run.log(code, url, f"DNS {kind}: {type(exc).__name__}")
            if isinstance(exc, PolicyError):
                break


def hostname_matches(cert, host):
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        address = ipaddress.ip_address(host)
        return address in sans.get_values_for_type(x509.IPAddress)
    except ValueError:
        names = sans.get_values_for_type(x509.DNSName)
    return any(
        host == name.lower()
        or (name.startswith("*.") and host.endswith(name[1:].lower()) and host.count(".") == name.count("."))
        for name in names
    )


def certificate_details(der, host):
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    try:
        sans = [
            str(v.value) for v in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ]
    except x509.ExtensionNotFound:
        sans = []
    instant = datetime.now(timezone.utc)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "sans": sans,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "expired": cert.not_valid_after_utc < instant,
        "not_yet_valid": cert.not_valid_before_utc > instant,
        "hostname_matches": hostname_matches(cert, host),
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": cert.signature_hash_algorithm.name
        if cert.signature_hash_algorithm
        else "intrinsic",
        "public_key_type": type(key).__name__,
        "public_key_bits": getattr(key, "key_size", None),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }


def handshake(address, port, host, timeout, verify):
    context = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    with socket.create_connection((address, port), timeout=timeout) as connection:
        connection.settimeout(max(0.01, timeout - (time.monotonic() - started)))
        with context.wrap_socket(connection, server_hostname=host) as tls:
            leaf = tls.getpeercert(binary_form=True)
            chain_method = getattr(tls, "get_unverified_chain", None)
            if not chain_method:
                chain_method = getattr(tls._sslobj, "get_unverified_chain", None)
            certificates = chain_method() if chain_method else [leaf]
            chain = []
            for certificate in certificates:
                if isinstance(certificate, bytes):
                    chain.append(certificate)
                else:
                    pem = certificate.public_bytes()
                    chain.append(ssl.PEM_cert_to_DER_cert(pem))
            return {
                "leaf": leaf,
                "chain": chain,
                "chain_collection": "peer-supplied"
                if chain_method
                else "leaf-only (runtime API unavailable)",
                "tls_version": tls.version(),
                "cipher": list(tls.cipher() or []),
            }


async def collect_tls(run, connector=handshake):
    target = run.scope.target
    parts = urlsplit(target)
    if parts.scheme != "https":
        run.log("TLS_NOT_APPLICABLE", target, "TLS collection requires an explicitly configured HTTPS target")
        return
    try:
        addresses = await run.resolve(target)
        await run.reserve(target, "TLS_VERIFIED_HANDSHAKE")
        verified, verification_error = True, None
        try:
            result = await run.operation(
                asyncio.to_thread(
                    connector, addresses[0], parts.port or 443, parts.hostname, run.time_limit(), True
                )
            )
        except ssl.SSLCertVerificationError as exc:
            verified, verification_error = False, exc.verify_message
            run.log("TLS_VERIFICATION_FAILED", target, f"Certificate validation failed: {verification_error}")
            await run.reserve(target, "TLS_CERTIFICATE_INSPECTION")
            result = await run.operation(
                asyncio.to_thread(
                    connector, addresses[0], parts.port or 443, parts.hostname, run.time_limit(), False
                )
            )
        details = certificate_details(result["leaf"], parts.hostname)
        details.update({k: v for k, v in result.items() if k not in ("leaf", "chain")})
        details.update(
            {
                "verified": verified,
                "verification_error": verification_error,
                "chain": [certificate_details(v, parts.hostname) for v in result["chain"]],
                "protocol_scope": "Only the negotiated protocol was observed; no protocol enumeration",
            }
        )
        ev = evidence(
            run.db,
            run.assessment_id,
            "TLS_CERTIFICATE",
            target,
            "TLS certificate and negotiated protocol",
            details,
        )
        run.db.add(
            m.TLSCertificate(
                assessment_id=run.assessment_id, evidence_id=ev.id, hostname=parts.hostname, details=ev.data
            )
        )
        event(run.db, run.assessment_id, "TLS_ANALYZED", "TLS observation collected", {"evidence_id": ev.id})
        run.db.commit()
    except (PolicyError, OSError, ValueError, TimeoutError) as exc:
        run.log(
            exc.code if isinstance(exc, PolicyError) else "TLS_FAILED",
            target,
            str(exc) if isinstance(exc, PolicyError) else f"TLS collection failed: {type(exc).__name__}",
        )
