import csv
import io
import json

import httpx
import pytest
from pypdf import PdfReader

from app import models as m
from app.schemas import SafeChecks
from app.services import assessments
from app.services.analysis import analyze
from app.services.store import rows


async def collect_fixture(db, item):
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(
                200,
                headers=[
                    ("Content-Type", "text/html"),
                    ("Server", "nginx/1.24"),
                    ("Set-Cookie", "session=COOKIE_SENTINEL_91; Path=/; SameSite=None"),
                    ("Set-Cookie", "prefs=COOKIE_SENTINEL_92; Secure; HttpOnly; SameSite=Lax"),
                    ("X-Api-Key", "HEADER_SENTINEL_93"),
                ],
                text="""<html><a href="/api/data?token=QUERY_SENTINEL_94">API</a>
               <a href="/admin/private">Excluded</a><a href="http://evil.test/">External</a>
               <script src="/react.production.js"></script>
               <form method="post" action="/submit"><input name="password" value="FORM_SENTINEL_95"></form></html>""",
            )
        if path == "/robots.txt":
            return httpx.Response(200, text="Disallow: /admin/private\nAllow: /catalog")
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                headers={"content-type": "application/xml"},
                text="<urlset><url><loc>/shop</loc></url></urlset>",
            )
        if path == "/react.production.js":
            return httpx.Response(
                200, headers={"content-type": "application/javascript"}, text='fetch("/api/users");'
            )
        if path == "/.env":
            return httpx.Response(200, text="API_KEY=ENV_SENTINEL_97\nAPP_NAME=fixture")
        if path == "/cors":
            return httpx.Response(
                200,
                json={"public": True},
                headers={
                    "access-control-allow-origin": "https://webscope.invalid",
                    "access-control-allow-credentials": "true",
                },
            )
        return httpx.Response(
            200,
            json={"access_token": "BODY_SENTINEL_96", "users": []},
            headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        )

    return await assessments.collect(db, item, transport=httpx.MockTransport(handler))


async def test_discovery_evidence_rules_and_passive_idempotency(db, make_assessment, monkeypatch):
    item = make_assessment(max_requests=15)
    await collect_fixture(db, item)
    assert item.status == "COMPLETED"
    endpoints = rows(db, m.Endpoint, item.id)
    assert {"HTML", "FORM", "ROBOTS", "SITEMAP", "JAVASCRIPT"} <= {e.source for e in endpoints}
    assert any(e.method == "POST" for e in endpoints)
    txs = rows(db, m.HTTPTransaction, item.id)
    assert not any("/admin" in t.url or "evil.test" in t.url or "/submit" in t.url for t in txs)
    assert any(t.name == "React" for t in rows(db, m.Technology, item.id))
    findings = rows(db, m.Finding, item.id)
    assert all(f.evidence_id and f.rule_version and f.status == "NEW" for f in findings)
    before = (len(findings), len(rows(db, m.Evidence, item.id)), len(txs))

    def no_network(*args, **kwargs):
        raise AssertionError("Passive analysis attempted network traffic")

    monkeypatch.setattr("socket.create_connection", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    monkeypatch.setattr("httpx.AsyncClient.send", no_network)
    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", no_network)
    analyze(db, item)
    assert before == (
        len(rows(db, m.Finding, item.id)),
        len(rows(db, m.Evidence, item.id)),
        len(rows(db, m.HTTPTransaction, item.id)),
    )


async def test_full_api_investigation_exports_redaction(client, db, payload):
    created = client.post("/api/assessments", json=payload)
    assert created.status_code == 201, created.text
    aid = created.json()["id"]
    assert client.post(f"/api/assessments/{aid}/validate", json={}).status_code == 200
    item = db.get(m.Assessment, aid)
    await collect_fixture(db, item)
    found = client.get(f"/api/assessments/{aid}/findings").json()
    fid, eid = found[0]["id"], found[0]["evidence_id"]
    original = found[0]["automated"]
    update = client.patch(
        f"/api/findings/{fid}",
        json={
            "status": "CONFIRMED",
            "analyst_assessment": "Confirmed configuration observation in owned fixture.",
            "priority_override": "HIGH",
            "override_reason": "Production deployment priority for this test.",
            "analyst_severity": "MEDIUM",
        },
    )
    assert update.status_code == 200, update.text
    assert update.json()["automated"] == original
    assert update.json()["risk"]["priority"] == "HIGH"
    assert (
        client.post(
            f"/api/findings/{fid}/notes", json={"content": "Reproduce with API_KEY=NOTE_SENTINEL_98"}
        ).status_code
        == 201
    )
    case = client.post(
        f"/api/assessments/{aid}/cases",
        json={
            "title": "=DANGEROUS_FORMULA()",
            "finding_ids": [fid],
            "evidence_ids": [eid],
            "assigned_analyst": "Fixture Analyst",
        },
    )
    assert case.status_code == 201, case.text
    cid = case.json()["id"]
    for status in ("INVESTIGATING", "REMEDIATION", "VERIFICATION", "CLOSED"):
        assert client.patch(f"/api/cases/{cid}", json={"status": status}).status_code == 200
    assert (
        client.post(f"/api/cases/{cid}/notes", json={"content": "Case verification complete."}).status_code
        == 201
    )
    seen = [
        client.get(f"/api/evidence/{eid}").text,
        client.get(f"/api/assessments/{aid}/graph").text,
        client.get(f"/api/findings/{fid}").text,
    ]
    for format, dataset in (
        ("json", "assessment"),
        ("markdown", "assessment"),
        ("pdf", "assessment"),
        ("csv", "endpoints"),
        ("csv", "findings"),
        ("csv", "technologies"),
        ("csv", "evidence"),
    ):
        response = client.post(f"/api/assessments/{aid}/reports", json={"format": format, "dataset": dataset})
        assert response.status_code == 201, response.text
        download = client.get(f"/api/reports/{response.json()['id']}/download")
        assert download.status_code == 200
        if format == "pdf":
            reader = PdfReader(io.BytesIO(download.content))
            output = "\n".join(page.extract_text() for page in reader.pages)
            for heading in (
                "Scope",
                "Methodology",
                "Automated Findings",
                "Analyst Conclusions",
                "Assessment Timeline",
            ):
                assert heading in output
        else:
            output = download.content.decode("utf-8-sig")
            if format == "json":
                snapshot = json.loads(output)
                assert snapshot["case_findings"][0]["finding_id"] == fid
                assert snapshot["risk"][fid]["priority"] == "HIGH"
            if format == "csv":
                parsed = list(csv.DictReader(io.StringIO(output)))
                assert parsed and "id" in parsed[0]
        seen.append(output)
    combined = "\n".join(
        seen
        + [
            client.get(f"/api/assessments/{aid}/{name}").text
            for name in ("evidence", "timeline", "transactions", "endpoints", "technologies", "notes")
        ]
    )
    for secret in (
        "COOKIE_SENTINEL_91",
        "COOKIE_SENTINEL_92",
        "HEADER_SENTINEL_93",
        "QUERY_SENTINEL_94",
        "FORM_SENTINEL_95",
        "BODY_SENTINEL_96",
        "NOTE_SENTINEL_98",
    ):
        assert secret not in combined
    assert "SameSite" in combined and "HttpOnly" in combined
    assert client.patch(f"/api/assessments/{aid}", json={"status": "ARCHIVED"}).status_code == 200
    assert client.delete(f"/api/assessments/{aid}").status_code == 204
    assert client.get(f"/api/evidence/{eid}").status_code == 404


async def test_safe_checks_optin_and_signatures(db, make_assessment):
    item = make_assessment(safe_paths=["/.env", "/cors"], max_requests=2)
    called = []

    def handler(request):
        called.append(request.url.path)
        if request.url.path == "/.env":
            return httpx.Response(200, text="API_KEY=ENV_SENTINEL_97")
        return httpx.Response(
            200,
            json={"public": True},
            headers={
                "access-control-allow-origin": "https://webscope.invalid",
                "access-control-allow-credentials": "true",
            },
        )

    with pytest.raises(ValueError, match="confirmation"):
        await assessments.collect(db, item, SafeChecks(confirm=False), transport=httpx.MockTransport(handler))
    assert called == []
    await assessments.collect(
        db,
        item,
        SafeChecks(confirm=True, cors_origin="https://webscope.invalid"),
        transport=httpx.MockTransport(handler),
    )
    assert called == ["/.env", "/cors"]
    rules = {f.rule_id for f in rows(db, m.Finding, item.id)}
    assert {"WS-DISC-002", "WS-CORS-003"} <= rules
    assert "ENV_SENTINEL_97" not in str([e.data for e in rows(db, m.Evidence, item.id)])


def test_api_boundary_authorization_and_validation(client, payload):
    assert (
        client.post("/api/assessments", json=payload, headers={"Origin": "https://evil.test"}).status_code
        == 403
    )
    assert client.post("/api/assessments", json=payload, headers={"Host": "evil.test"}).status_code == 403
    assert (
        client.post("/api/assessments", json=payload, headers={"X-WebScope-Request": ""}).status_code == 403
    )
    assert (
        client.post("/api/assessments", json=payload, headers={"Sec-Fetch-Site": "cross-site"}).status_code
        == 403
    )
    assert (
        client.post("/api/assessments", json=payload, headers={"Content-Type": "text/plain"}).status_code
        == 415
    )
    payload["authorized"] = False
    result = client.post("/api/assessments", json=payload)
    aid = result.json()["id"]
    assert client.post(f"/api/assessments/{aid}/validate", json={}).status_code == 400
    assert client.post(f"/api/assessments/{aid}/discover", json={}).status_code == 400
    assert client.delete(f"/api/assessments/{aid}").status_code == 409
    invalid = client.post("/api/assessments", json={"password": "VALIDATION_SENTINEL"})
    assert invalid.status_code == 422 and "VALIDATION_SENTINEL" not in invalid.text


def test_openapi_import_local_refs_methods_and_no_network(client, payload, monkeypatch):
    aid = client.post("/api/assessments", json=payload).json()["id"]

    def no_network(*args, **kwargs):
        raise AssertionError("OpenAPI import must not fetch")

    monkeypatch.setattr("socket.getaddrinfo", no_network)
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/items": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/Limit"}],
                    "responses": {"200": {"description": "OK"}},
                },
                "delete": {"security": [{"bearer": []}], "responses": {}},
            }
        },
        "components": {"parameters": {"Limit": {"name": "limit", "in": "query"}}},
    }
    imported = client.post(f"/api/assessments/{aid}/openapi", json={"document": document})
    assert imported.status_code == 200 and imported.json()["imported"] == 2
    endpoints = client.get(f"/api/assessments/{aid}/endpoints").json()
    assert {e["method"] for e in endpoints} == {"GET", "DELETE"}
    assert endpoints[0]["parameters"][0]["name"] == "limit"
    assert endpoints[1]["authentication"] == "DECLARED_REQUIRED"
    document["paths"]["/api/items"]["get"]["parameters"] = [{"$ref": "http://evil.test/openapi.json"}]
    assert client.post(f"/api/assessments/{aid}/openapi", json={"document": document}).status_code == 400


def test_settings_and_scope_reauthorization(client, payload):
    aid = client.post("/api/assessments", json=payload).json()["id"]
    assert (
        client.patch(
            f"/api/assessments/{aid}", json={"scope": {"allowed_hosts": ["127.0.0.1", "localhost"]}}
        ).status_code
        == 400
    )
    assert client.patch("/api/settings", json={"max_requests": 50}).status_code == 200
    assert client.get("/api/settings").json()["max_requests"] == 50
    assert client.patch("/api/settings", json={"max_requests": 100000}).status_code == 422
