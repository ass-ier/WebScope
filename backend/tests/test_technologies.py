import httpx
import pytest

from app import models as m
from app.services.assessments import scope_for
from app.services.discovery import harvest
from app.services.network import NetworkRun
from app.services.store import rows
from app.services.technology import fingerprint


@pytest.mark.parametrize(
    "headers,body,name,category,confidence",
    [
        ({"server": "nginx/1.24"}, "", "nginx", "Web Server", "MEDIUM"),
        ({"server": "Apache/2.4"}, "", "Apache", "Web Server", "MEDIUM"),
        ({"x-powered-by": "PHP/8.3"}, "", "PHP", "Runtime", "MEDIUM"),
        ({"x-powered-by": "Express"}, "", "Express", "Backend", "MEDIUM"),
        ({}, '<script src="/react.production.js"></script>', "React", "Frontend", "MEDIUM"),
        ({}, '<script src="/_next/chunk.js"></script>', "Next.js", "Frontend", "HIGH"),
        ({}, '<script src="/vue.min.js"></script>', "Vue.js", "Frontend", "MEDIUM"),
        ({}, '<div ng-version="18"></div>', "Angular", "Frontend", "HIGH"),
        ({}, '<link href="/wp-content/theme.css">', "WordPress", "CMS", "MEDIUM"),
        ({}, '<script src="/jquery-3.7.1.min.js"></script>', "jQuery", "JavaScript libraries", "MEDIUM"),
        ({}, '<link href="/bootstrap.min.css">', "Bootstrap", "Frontend", "MEDIUM"),
        (
            {},
            '<script src="https://google-analytics.com/marker"></script>',
            "Google Analytics",
            "Analytics",
            "MEDIUM",
        ),
        ({"cf-ray": "synthetic"}, "", "Cloudflare", "CDN", "MEDIUM"),
        ({"x-mod-security": "synthetic"}, "", "ModSecurity", "Security tooling", "MEDIUM"),
        ({}, "SQLSTATE synthetic error", "SQL database indicator", "Database indicators", "LOW"),
        ({"set-cookie": "laravel_session=TEST_SECRET; Secure"}, "", "Laravel", "Backend", "MEDIUM"),
        ({"set-cookie": "csrftoken=TEST_SECRET; Secure"}, "", "Django indicator", "Backend", "LOW"),
    ],
)
async def test_all_fingerprint_mechanisms_preserve_confidence_and_source(
    db, make_assessment, headers, body, name, category, confidence
):
    item = make_assessment()
    run = NetworkRun(
        db,
        item.id,
        scope_for(db, item),
        httpx.MockTransport(
            lambda r: httpx.Response(200, text=body, headers={"content-type": "text/html", **headers})
        ),
    )
    tx = await run.request("http://127.0.0.1:9998/")
    harvest(db, item.id, run.scope, tx)
    fingerprint(db, item.id, tx)
    observed = next(t for t in rows(db, m.Technology, item.id) if t.name == name)
    assert observed.category == category and observed.confidence == confidence
    ev = db.get(m.Evidence, observed.evidence_id)
    assert ev.data["source_evidence_id"] == tx.evidence_id
    assert observed.rationale and observed.endpoint_id
    assert "TEST_SECRET" not in str(ev.data)
    fingerprint(db, item.id, tx)
    assert len([t for t in rows(db, m.Technology, item.id) if t.name == name]) == 1
