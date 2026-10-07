import json
import re
from urllib.parse import urlsplit

from sqlalchemy import select

from app import models as m
from app.services import redaction
from app.services.store import event, evidence, rows

HEADER_RULES = [
    (
        "WS-HDR-001",
        "content-security-policy",
        "MEDIUM",
        "Constrain script/resource origins with a tested Content-Security-Policy.",
    ),
    (
        "WS-SEC-001",
        "strict-transport-security",
        "LOW",
        "Enable HSTS on HTTPS after confirming all required hosts support HTTPS.",
    ),
    ("WS-HDR-003", "x-content-type-options", "LOW", "Set X-Content-Type-Options: nosniff."),
    (
        "WS-HDR-004",
        "x-frame-options",
        "LOW",
        "Use CSP frame-ancestors or X-Frame-Options to restrict framing.",
    ),
    (
        "WS-HDR-005",
        "referrer-policy",
        "LOW",
        "Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.",
    ),
    (
        "WS-HDR-006",
        "permissions-policy",
        "INFO",
        "Restrict browser features that this application does not require.",
    ),
    (
        "WS-HDR-007",
        "cross-origin-opener-policy",
        "INFO",
        "Consider same-origin opener isolation where compatible.",
    ),
    (
        "WS-HDR-008",
        "cross-origin-resource-policy",
        "INFO",
        "Choose a resource policy appropriate to intended cross-origin use.",
    ),
]


def rule_definitions():
    definitions = [
        (rid, f"Missing {header}", "Headers", severity, "HIGH", advice)
        for rid, header, severity, advice in HEADER_RULES
    ] + [
        (
            "WS-HDR-009",
            "Permissive Content-Security-Policy",
            "Headers",
            "LOW",
            "MEDIUM",
            "Review unsafe-inline, unsafe-eval and wildcard sources; test a tighter policy.",
        ),
        (
            "WS-CK-001",
            "Session-like cookie without Secure",
            "Cookies",
            "MEDIUM",
            "MEDIUM",
            "Set Secure on session cookies and serve the application over HTTPS.",
        ),
        (
            "WS-CK-002",
            "Session-like cookie without HttpOnly",
            "Cookies",
            "LOW",
            "MEDIUM",
            "Set HttpOnly unless client-side access is explicitly required.",
        ),
        (
            "WS-CK-003",
            "Cookie SameSite requires review",
            "Cookies",
            "LOW",
            "MEDIUM",
            "Choose Lax or Strict where possible; SameSite=None requires Secure.",
        ),
        (
            "WS-CK-004",
            "Broad cookie domain or path",
            "Cookies",
            "LOW",
            "MEDIUM",
            "Restrict Domain and Path to the minimum application scope.",
        ),
        (
            "WS-CORS-001",
            "Wildcard CORS origin observed",
            "CORS",
            "INFO",
            "HIGH",
            "Confirm that this resource is intentionally public; wildcard alone is not a vulnerability.",
        ),
        (
            "WS-CORS-002",
            "Wildcard origin with credentials",
            "CORS",
            "LOW",
            "HIGH",
            "Use an explicit trusted origin allowlist. Browsers reject wildcard credentialed responses.",
        ),
        (
            "WS-CORS-003",
            "Potential unsafe credentialed origin reflection",
            "CORS",
            "HIGH",
            "MEDIUM",
            "Validate Origin against an exact trusted allowlist; manually verify sensitive authenticated impact.",
        ),
        (
            "WS-DISC-001",
            "Potential source-control metadata exposure",
            "Disclosure",
            "MEDIUM",
            "MEDIUM",
            "Remove source-control metadata from the public web root.",
        ),
        (
            "WS-DISC-002",
            "Potential environment-file exposure",
            "Disclosure",
            "HIGH",
            "MEDIUM",
            "Deny public access to environment files; investigate exposure and rotate affected secrets if confirmed.",
        ),
        (
            "WS-DISC-003",
            "Directory listing observed",
            "Disclosure",
            "LOW",
            "HIGH",
            "Disable unintended directory indexes.",
        ),
        (
            "WS-DISC-004",
            "Verbose server error observed",
            "Disclosure",
            "LOW",
            "MEDIUM",
            "Return generic errors externally and retain diagnostics only in restricted logs.",
        ),
        (
            "WS-DISC-005",
            "Source map reference exposed",
            "Disclosure",
            "INFO",
            "HIGH",
            "Review production source maps for unintended source or metadata disclosure.",
        ),
        (
            "WS-DISC-006",
            "Server technology banner disclosed",
            "Disclosure",
            "INFO",
            "HIGH",
            "Minimize unnecessary version banners; a banner does not prove a vulnerable version.",
        ),
        (
            "WS-API-001",
            "Sensitive-looking response fields",
            "API",
            "LOW",
            "LOW",
            "Review authorization and data minimization for the observed response fields.",
        ),
        (
            "WS-TLS-001",
            "Expired TLS certificate",
            "TLS",
            "MEDIUM",
            "HIGH",
            "Renew the certificate and verify the full deployment chain.",
        ),
        (
            "WS-TLS-002",
            "TLS certificate hostname mismatch",
            "TLS",
            "MEDIUM",
            "HIGH",
            "Deploy a certificate whose subject alternative names cover the target hostname.",
        ),
        (
            "WS-TLS-003",
            "TLS certificate validation failed",
            "TLS",
            "LOW",
            "HIGH",
            "Verify trust, certificate validity, and intermediate-chain deployment.",
        ),
        (
            "WS-TLS-004",
            "Weak negotiated TLS or certificate algorithm",
            "TLS",
            "MEDIUM",
            "HIGH",
            "Use TLS 1.2+ and modern certificate signatures/key sizes.",
        ),
    ]
    for rid, title, category, severity, confidence, remediation in definitions:
        yield dict(
            id=rid,
            version="1.0.0",
            name=title,
            category=category,
            description=title,
            severity=severity,
            confidence=confidence,
            required_evidence=["TLS_CERTIFICATE" if category == "TLS" else "HTTP_RESPONSE"],
            request_type="GET (explicit opt-in)" if rid == "WS-CORS-003" else "NONE (collected evidence)",
            safety_level="SAFE_READ_ONLY" if rid == "WS-CORS-003" else "PASSIVE",
            remediation=remediation,
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )


def seed_rules(db):
    for rule in rule_definitions():
        if not db.get(m.DetectionRule, rule["id"]):
            db.add(m.DetectionRule(**rule))
    db.flush()


def finding(db, assessment_id, rule_id, ev, rationale, endpoint_id=None, title=None):
    rule = db.get(m.DetectionRule, rule_id)
    title = title or rule.name
    existing = db.scalar(
        select(m.Finding).where(
            m.Finding.rule_id == rule_id, m.Finding.evidence_id == ev.id, m.Finding.title == title
        )
    )
    if existing:
        return existing
    facts = {
        "severity": rule.severity,
        "confidence": rule.confidence,
        "rationale": rationale,
        "rule_id": rule.id,
        "rule_version": rule.version,
        "evidence_id": ev.id,
        "classification": "OBSERVATION" if rule.severity == "INFO" else "POTENTIAL_WEAKNESS",
    }
    item = m.Finding(
        assessment_id=assessment_id,
        evidence_id=ev.id,
        endpoint_id=endpoint_id,
        rule_id=rule.id,
        rule_version=rule.version,
        title=title,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        rationale=redaction.text(rationale),
        impact="Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.",
        remediation=rule.remediation,
        references=rule.references,
        affected_asset=ev.source,
        automated=facts,
    )
    db.add(item)
    db.flush()
    db.add(m.FindingEvidence(finding_id=item.id, evidence_id=ev.id, assessment_id=assessment_id))
    event(
        db,
        assessment_id,
        "FINDING_GENERATED",
        f"{rule.id}: {title}",
        {"finding_id": item.id, "evidence_id": ev.id},
    )
    return item


def parse_cookie(value):
    parts = value.split(";")
    first = parts[0].split("=", 1)
    if len(first) != 2 or not first[0].strip():
        return None
    attributes = {
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "expires": None,
        "max-age": None,
        "value": redaction.MASK,
    }
    for part in parts[1:]:
        key, _, val = part.strip().partition("=")
        key = key.lower()
        if key in attributes:
            attributes[key] = True if key in ("secure", "httponly") else redaction.text(val)
    return first[0].strip(), attributes


def analyze_http(db, assessment, tx):
    if tx.status_code is None:
        return
    ev = db.get(m.Evidence, tx.evidence_id)
    headers, body = tx.response.get("headers", {}), tx.response.get("body", "")
    html = "html" in tx.response.get("content_type", "")
    parts = urlsplit(tx.url)
    existing_headers = {
        x.name
        for x in db.scalars(
            select(m.SecurityHeaderObservation).where(
                m.SecurityHeaderObservation.assessment_id == assessment.id,
                m.SecurityHeaderObservation.evidence_id == ev.id,
            )
        )
    }
    for rid, name, _, _ in HEADER_RULES:
        present = name in headers
        contextual = html and tx.status_code < 400
        if name == "strict-transport-security":
            contextual = parts.scheme == "https"
        if name == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            contextual = False
        rationale = (
            f"{name} {'present' if present else 'absent'} on {tx.status_code} {parts.scheme.upper()} response. "
            + (
                "Review in application context; absence does not demonstrate exploitability."
                if contextual
                else "Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable."
            )
        )
        if name not in existing_headers:
            db.add(
                m.SecurityHeaderObservation(
                    assessment_id=assessment.id,
                    evidence_id=ev.id,
                    name=name,
                    present=present,
                    value=headers.get(name, ""),
                    rationale=rationale,
                )
            )
            evidence(
                db,
                assessment.id,
                "HEADER",
                tx.url,
                f"Header observation: {name}",
                {
                    "name": name,
                    "present": present,
                    "value": headers.get(name, ""),
                    "source_evidence_id": ev.id,
                },
            )
        if not present and contextual:
            finding(db, assessment.id, rid, ev, rationale, tx.endpoint_id)
    csp = headers.get("content-security-policy", "")
    if html and any(marker in csp for marker in ("'unsafe-inline'", "'unsafe-eval'", " *")):
        finding(
            db,
            assessment.id,
            "WS-HDR-009",
            ev,
            f"Observed CSP includes permissive sources: {csp}",
            tx.endpoint_id,
        )
    cookies_exist = bool(
        db.scalar(
            select(m.Cookie.id).where(m.Cookie.assessment_id == assessment.id, m.Cookie.evidence_id == ev.id)
        )
    )
    for raw in headers.get("set-cookie", "").splitlines():
        cookie = parse_cookie(raw)
        if not cookie:
            if raw:
                event(
                    db,
                    assessment.id,
                    "COOKIE_PARSE_FAILED",
                    "Malformed cookie omitted",
                    {"evidence_id": ev.id},
                )
            continue
        name, attrs = cookie
        if not cookies_exist:
            db.add(m.Cookie(assessment_id=assessment.id, evidence_id=ev.id, name=name, attributes=attrs))
            evidence(
                db,
                assessment.id,
                "COOKIE",
                tx.url,
                f"Cookie attributes: {name}",
                {"name": name, "attributes": attrs, "source_evidence_id": ev.id},
            )
        session_like = bool(re.search(r"session|sid|auth", name, re.I))
        if session_like and not attrs["secure"]:
            finding(
                db,
                assessment.id,
                "WS-CK-001",
                ev,
                f"Cookie {name} has a session-like name and no Secure attribute. "
                "The name is a heuristic, not proof of authentication use.",
                tx.endpoint_id,
                f"Cookie {name}: Secure absent",
            )
        if session_like and not attrs["httponly"]:
            finding(
                db,
                assessment.id,
                "WS-CK-002",
                ev,
                f"Cookie {name} has no HttpOnly attribute; actual use requires analyst verification.",
                tx.endpoint_id,
                f"Cookie {name}: HttpOnly absent",
            )
        if not attrs["samesite"] or (str(attrs["samesite"]).lower() == "none" and not attrs["secure"]):
            finding(
                db,
                assessment.id,
                "WS-CK-003",
                ev,
                f"Cookie {name}: SameSite={attrs['samesite']}, Secure={attrs['secure']}. "
                "Browser defaults and cross-site requirements affect risk.",
                tx.endpoint_id,
                f"Cookie {name}: SameSite review",
            )
        if attrs["domain"] and str(attrs["domain"]).lstrip(".") != parts.hostname:
            finding(
                db,
                assessment.id,
                "WS-CK-004",
                ev,
                f"Cookie {name} declares Domain={attrs['domain']} and Path={attrs['path']}.",
                tx.endpoint_id,
                f"Cookie {name}: broad scope",
            )
    origin, credentials = (
        headers.get("access-control-allow-origin"),
        headers.get("access-control-allow-credentials"),
    )
    if origin:
        prior = db.scalar(
            select(m.Evidence.id).where(
                m.Evidence.assessment_id == assessment.id,
                m.Evidence.type == "CORS_OBSERVATION",
                m.Evidence.data["source_evidence_id"].as_string() == ev.id,
            )
        )
        if not prior:
            evidence(
                db,
                assessment.id,
                "CORS_OBSERVATION",
                tx.url,
                "Contextual CORS observation",
                {
                    "origin": origin,
                    "allow_credentials": credentials,
                    "methods": headers.get("access-control-allow-methods"),
                    "headers": headers.get("access-control-allow-headers"),
                    "source_evidence_id": ev.id,
                    "request_origin": tx.request["headers"].get("origin"),
                    "vary": headers.get("vary"),
                },
            )
        if origin == "*":
            rid = "WS-CORS-002" if credentials == "true" else "WS-CORS-001"
            finding(
                db,
                assessment.id,
                rid,
                ev,
                f"ACAO=*, ACAC={credentials}. "
                "Wildcard public resources may be intentional; browsers reject wildcard credentialed reads.",
                tx.endpoint_id,
            )
        elif (
            origin == "https://webscope.invalid"
            and tx.request["headers"].get("origin") == origin
            and credentials == "true"
        ):
            finding(
                db,
                assessment.id,
                "WS-CORS-003",
                ev,
                "The explicit safe Origin probe was reflected with credentials enabled. "
                "No credentials were sent and no authenticated data access was demonstrated.",
                tx.endpoint_id,
            )
    signatures = [
        (
            "WS-DISC-003",
            bool(re.search(r"<title>\s*Index of|Directory listing for", body, re.I)),
            "Directory index marker in collected response.",
        ),
        (
            "WS-DISC-004",
            bool(
                re.search(
                    r"Traceback \(most recent call last\)|SQLSTATE|Exception in thread|Stack trace:", body
                )
            ),
            "Diagnostic stack/error marker in collected response.",
        ),
        (
            "WS-DISC-005",
            "sourceMappingURL=" in body,
            "Source map reference in collected JavaScript; referenced map is not automatically fetched.",
        ),
        (
            "WS-DISC-006",
            bool(headers.get("server") or headers.get("x-powered-by")),
            "Self-reported server/runtime banner observed; no vulnerable-version claim.",
        ),
    ]
    safe_path = parts.path in assessment.config.get("safe_paths", [])
    if safe_path and 200 <= tx.status_code < 300:
        signatures += [
            (
                "WS-DISC-001",
                "/.git" in parts.path
                and bool(re.search(r"ref:\s*refs/|Index of\s*/?\.git|repositoryformatversion", body)),
                "Configured source-control path returned a source-control signature, not merely HTTP 200.",
            ),
            (
                "WS-DISC-002",
                parts.path.endswith(".env") and bool(re.search(r"(?m)^[A-Z][A-Z0-9_]*\s*=", body)),
                "Explicitly configured environment-file path returned configuration-shaped text; values were redacted.",
            ),
        ]
    for rid, triggered, why in signatures:
        if triggered:
            finding(db, assessment.id, rid, ev, why, tx.endpoint_id)
    if "json" in tx.response.get("content_type", ""):
        try:
            data = json.loads(body)
            schema = (
                {str(k): type(v).__name__ for k, v in data.items()}
                if isinstance(data, dict)
                else {"root": type(data).__name__}
            )
            if tx.endpoint_id:
                item = db.get(m.Endpoint, tx.endpoint_id)
                item.details = {
                    **item.details,
                    "response_schema_observed": schema,
                    "status": tx.status_code,
                    "allowed_methods_observed": headers.get("allow"),
                    "error_response": tx.status_code >= 400,
                }
            if any(redaction.sensitive(k) for k in schema):
                finding(
                    db,
                    assessment.id,
                    "WS-API-001",
                    ev,
                    "Response includes sensitive-looking field names: "
                    + ", ".join(k for k in schema if redaction.sensitive(k))
                    + ". Values are redacted; field names alone do not prove unauthorized disclosure.",
                    tx.endpoint_id,
                )
        except (ValueError, RecursionError):
            event(
                db,
                assessment.id,
                "JSON_PARSE_FAILED",
                "Malformed or excessively nested JSON retained as redacted text",
                {"evidence_id": ev.id},
            )


def analyze(db, assessment):
    seed_rules(db)
    for tx in rows(db, m.HTTPTransaction, assessment.id):
        analyze_http(db, assessment, tx)
    for cert in rows(db, m.TLSCertificate, assessment.id):
        data, ev = cert.details, db.get(m.Evidence, cert.evidence_id)
        checks = [
            ("WS-TLS-001", data["expired"], f"Certificate notAfter={data['not_after']}."),
            (
                "WS-TLS-002",
                not data["hostname_matches"],
                "Target hostname does not match observed subject alternative names.",
            ),
            ("WS-TLS-003", not data["verified"], f"Trust validation failed: {data['verification_error']}."),
            (
                "WS-TLS-004",
                data.get("tls_version") in ("TLSv1", "TLSv1.1")
                or data["signature_hash"] in ("sha1", "md5")
                or ("RSA" in data["public_key_type"] and data["public_key_bits"] < 2048),
                "A weak negotiated protocol, signature hash, or RSA key size was observed.",
            ),
        ]
        for rid, triggered, why in checks:
            if triggered:
                finding(db, assessment.id, rid, ev, why)
    event(
        db,
        assessment.id,
        "PASSIVE_ANALYSIS_COMPLETED",
        "Deterministic analysis of persisted evidence; no requests issued",
    )
    db.flush()


def risk(assessment, item):
    severity = item.analyst_severity or item.severity
    confidence = item.analyst_confidence or item.confidence
    config = assessment.config
    weight = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[severity]
    score = weight * {"LOW": 0.5, "MEDIUM": 0.75, "HIGH": 1}[confidence]
    exposure = config.get("exposure", "INTERNAL")
    importance = config.get("asset_importance", "STANDARD")
    auth = config.get("authentication_context", "UNKNOWN")
    if weight:
        score += 0.5 if exposure == "INTERNET" else 0
        score += 0.5 if importance == "PRODUCTION" else 0
        score += 0.25 if auth == "NOT_REQUIRED" else 0
    score = round(min(score, 4), 2)
    automated = (
        "CRITICAL"
        if score >= 3.75
        else "HIGH"
        if score >= 2.75
        else "MEDIUM"
        if score >= 1.75
        else "LOW"
        if score > 0
        else "INFO"
    )
    return {
        "factors": {
            "severity": severity,
            "confidence": confidence,
            "exposure": exposure,
            "asset_importance": importance,
            "authentication_context": auth,
            "potential_impact": item.impact,
        },
        "score": score,
        "automated_priority": automated,
        "priority": item.priority_override or automated,
        "override_reason": item.override_reason,
        "explanation": "Severity weight 0-4 x confidence (LOW .5, MEDIUM .75, HIGH 1), plus internet .5, "
        "production .5 and no authentication .25 for non-informational findings; capped at 4. "
        "Thresholds: LOW >0, MEDIUM >=1.75, HIGH >=2.75, CRITICAL >=3.75. "
        "Impact is described, not given an invented independent score. Overrides never alter original facts.",
    }
