import re

from bs4 import BeautifulSoup
from sqlalchemy import select

from app import models as m
from app.services.store import evidence


def fingerprint(db, assessment_id, tx):
    body = tx.response.get("body", "")
    headers = tx.response.get("headers", {})
    observations = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    for name, category, banner in (
        ("nginx", "Web Server", server),
        ("Apache", "Web Server", server),
        ("Express", "Backend", powered),
        ("PHP", "Runtime", powered),
    ):
        if name.lower() in banner.lower():
            match = re.search(re.escape(name) + r"/([\d.]+)", banner, re.I)
            observations.append(
                (
                    name,
                    category,
                    match[1] if match else None,
                    "MEDIUM",
                    f"Self-reported HTTP banner contains {name}; banners can be spoofed",
                )
            )
    patterns = [
        ("React", "Frontend", r"(?:react(?:[.-](?:dom|production|min))?\.js|data-reactroot)", "MEDIUM"),
        ("Next.js", "Frontend", r"(?:/_next/|__NEXT_DATA__)", "HIGH"),
        ("Vue.js", "Frontend", r"(?:vue(?:\.runtime)?(?:\.min)?\.js|data-v-[a-f0-9]{6,})", "MEDIUM"),
        ("Angular", "Frontend", r"ng-version\s*=", "HIGH"),
        ("WordPress", "CMS", r"/wp-content/", "MEDIUM"),
        ("jQuery", "JavaScript libraries", r"jquery(?:[-.][\d.]+)?(?:\.min)?\.js", "MEDIUM"),
        ("Google Analytics", "Analytics", r"(?:googletagmanager\.com|google-analytics\.com)", "MEDIUM"),
    ]
    for name, category, pattern, confidence in patterns:
        match = re.search(pattern, body, re.I)
        if match:
            observations.append(
                (name, category, None, confidence, f"Observed markup/asset marker: {match[0]}")
            )
    if "html" in tx.response.get("content_type", ""):
        soup = BeautifulSoup(body, "html.parser")
        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if generator and generator.get("content"):
            observations.append(
                (str(generator["content"])[:100], "CMS", None, "LOW", "Self-reported generator metadata")
            )
    for name, marker, category in [
        ("Cloudflare", "cf-ray", "CDN"),
        ("ModSecurity", "x-mod-security", "Security tooling"),
    ]:
        if marker in headers:
            observations.append((name, category, None, "MEDIUM", f"Response header {marker} is present"))
    if re.search(r"(?:SQLSTATE|PostgreSQL|MySQL)", body):
        observations.append(
            (
                "SQL database indicator",
                "Database indicators",
                None,
                "LOW",
                "Database-like error text; does not establish a specific database or a vulnerability",
            )
        )
    for name, category, version, confidence, rationale in observations:
        exists = db.scalar(
            select(m.Technology).where(
                m.Technology.assessment_id == assessment_id,
                m.Technology.name == name,
                m.Technology.evidence_id == tx.evidence_id,
            )
        )
        if exists:
            continue
        ev = evidence(
            db,
            assessment_id,
            "TECHNOLOGY_OBSERVATION",
            tx.url,
            f"Technology indicator: {name}",
            {
                "name": name,
                "confidence": confidence,
                "rationale": rationale,
                "source_evidence_id": tx.evidence_id,
            },
        )
        db.add(
            m.Technology(
                assessment_id=assessment_id,
                evidence_id=ev.id,
                name=name,
                category=category,
                version=version,
                confidence=confidence,
                rationale=rationale,
                endpoint_id=tx.endpoint_id,
            )
        )
