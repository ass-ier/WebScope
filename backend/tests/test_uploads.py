import copy
import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app import models as m
from app.db import session_factory
from test_temporary_workspaces import start


def har():
    return {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-10-07T12:00:00Z",
                    "time": 12.5,
                    "request": {
                        "method": "GET",
                        "url": "https://owned.example/?token=QUERY_UPLOAD_SECRET",
                        "headers": [{"name": "Authorization", "value": "Bearer AUTH_UPLOAD_SECRET"}],
                        "queryString": [{"name": "token", "value": "QUERY_UPLOAD_SECRET"}],
                        "postData": {"text": "password=BODY_UPLOAD_SECRET"},
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {
                                "name": "Set-Cookie",
                                "value": "session=COOKIE_UPLOAD_SECRET; Secure; SameSite=Lax",
                            },
                            {"name": "Set-Cookie", "value": "prefs=PREF_UPLOAD_SECRET; Path=/"},
                        ],
                        "content": {
                            "mimeType": "text/html",
                            "text": '<html><a href="/api/list">API</a><input name=password value=FORM_UPLOAD_SECRET></html>',
                        },
                    },
                }
            ],
        }
    }


def test_har_upload_redaction_analysis_and_no_requests(hosted, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Data imports must not network")

    monkeypatch.setattr("socket.getaddrinfo", no_network)
    monkeypatch.setattr("httpx.AsyncClient.send", no_network)
    start(hosted)
    response = hosted.post(
        "/api/imports",
        json={"format": "har", "name": "Owned HAR capture", "document": har(), "consent": True},
    )
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["data_origin"] == "UPLOADED" and item["counts"]["transactions"] == 1
    assert item["counts"]["findings"] > 0
    aid = item["id"]
    seen = ""
    for collection in ("evidence", "endpoints", "transactions", "timeline", "findings", "graph"):
        seen += hosted.get(f"/api/assessments/{aid}/{collection}").text
    report = hosted.post(f"/api/assessments/{aid}/reports", json={"format": "json"}).json()
    seen += hosted.get(f"/api/reports/{report['id']}/download").text
    for name in ("QUERY", "AUTH", "BODY", "COOKIE", "PREF", "FORM"):
        assert f"{name}_UPLOAD_SECRET" not in seen
    assert "SameSite=Lax" in seen
    assert "NETWORK_ATTEMPT" not in hosted.get(f"/api/assessments/{aid}/timeline").text


def test_openapi_upload_requires_target_and_refuses_remote_refs(hosted):
    start(hosted)
    payload = {
        "format": "openapi",
        "name": "API",
        "consent": True,
        "document": {"openapi": "3.0.3", "paths": {"/items": {"post": {"responses": {}}}}},
    }
    assert hosted.post("/api/imports", json=payload).status_code == 400
    payload["target"] = "https://owned.example/"
    response = hosted.post("/api/imports", json=payload)
    assert response.status_code == 201, response.text
    endpoints = hosted.get(f"/api/assessments/{response.json()['id']}/endpoints").json()
    assert endpoints[0]["method"] == "POST"
    payload["document"]["paths"]["/items"] = {"$ref": "https://outside.example/schema"}
    assert hosted.post("/api/imports", json=payload).status_code == 400


@pytest.mark.parametrize(
    "mutation", ["duplicate", "cross-assessment", "missing-evidence", "invalid-response", "invalid-status"]
)
def test_invalid_snapshot_rolls_back_entire_import(hosted, mutation):
    start(hosted)
    document = json.loads((Path(__file__).parents[2] / "docs/example/assessment.json").read_text())
    if mutation == "duplicate":
        document["evidence"].append(copy.deepcopy(document["evidence"][0]))
    elif mutation == "cross-assessment":
        document["evidence"][0]["assessment_id"] = "somebody-else"
    elif mutation == "missing-evidence":
        document["findings"][0]["evidence_id"] = "not-in-upload"
    elif mutation == "invalid-response":
        document["transactions"][0]["response"]["body"] = {}
    else:
        document["findings"][0]["status"] = "INVALID"
    before = hosted.get("/api/assessments").json()
    result = hosted.post(
        "/api/imports", json={"format": "webscope", "name": "Invalid", "document": document, "consent": True}
    )
    assert result.status_code == 400, result.text
    assert len(hosted.get("/api/assessments").json()) == len(before)


@pytest.mark.parametrize(
    "change", ["userinfo", "invalid-method", "invalid-status", "base64", "headers", "response-shape"]
)
def test_invalid_har_inputs_fail_explicitly(hosted, change):
    start(hosted)
    document = har()
    entry = document["log"]["entries"][0]
    if change == "userinfo":
        entry["request"]["url"] = "http://name:pass@owned.example/"
    elif change == "invalid-method":
        entry["request"]["method"] = "CONNECT"
    elif change == "invalid-status":
        entry["response"]["status"] = -100
    elif change == "base64":
        entry["response"]["content"].update(encoding="base64", text="not base64!")
    elif change == "headers":
        entry["request"]["headers"] = [{"name": "X", "value": {}}]
    else:
        entry["response"] = []
    response = hosted.post(
        "/api/imports", json={"format": "har", "name": "Invalid", "document": document, "consent": True}
    )
    assert response.status_code == 400, response.text


def test_import_consent_size_complexity_and_no_partial_records(hosted, engine):
    start(hosted)
    payload = {"format": "har", "name": "Upload", "document": har()}
    assert hosted.post("/api/imports", json=payload).status_code == 400
    payload["consent"] = True
    payload["document"]["padding"] = "x" * 2_000_000
    assert hosted.post("/api/imports", json=payload).status_code in (400, 413)
    deep = {}
    current = deep
    for _ in range(45):
        current["x"] = {}
        current = current["x"]
    payload["document"] = deep
    assert hosted.post("/api/imports", json=payload).status_code == 400
    with session_factory(engine)() as db:
        assert db.scalar(select(func.count()).select_from(m.Assessment)) == 2


def test_hosted_restart_clears_temporary_data(engine):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_temporary_workspaces import HEADERS, HOSTED

    with TestClient(create_app(engine, HOSTED), base_url="https://webscope.test", headers=HEADERS) as first:
        start(first)
        token = first.cookies.get("webscope_workspace")
    with TestClient(
        create_app(engine, HOSTED), base_url="https://webscope.test", headers=HEADERS
    ) as reopened:
        reopened.cookies.set("webscope_workspace", token)
        assert reopened.get("/api/assessments").status_code == 401
    with session_factory(engine)() as db:
        assert db.scalar(select(func.count()).select_from(m.WorkspaceSession)) == 0
        assert db.scalar(select(func.count()).select_from(m.Assessment)) == 0


def test_workspace_storage_quota_rolls_back_upload(engine):
    from dataclasses import replace
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_temporary_workspaces import HEADERS, HOSTED

    with TestClient(
        create_app(engine, replace(HOSTED, max_storage_bytes=1_000_000)),
        base_url="https://webscope.test",
        headers=HEADERS,
    ) as client:
        start(client)
        document = har()
        entry = document["log"]["entries"][0]
        entry["response"]["content"]["text"] = "<html>" + "a" * 100_000 + "</html>"
        document["log"]["entries"] = [copy.deepcopy(entry) for _ in range(6)]
        result = client.post(
            "/api/imports",
            json={"format": "har", "name": "Too much storage", "document": document, "consent": True},
        )
        assert result.status_code == 413, result.text
        assert len(client.get("/api/assessments").json()) == 2


def test_large_unbroken_text_redaction_remains_bounded():
    import time
    from app.services import redaction

    started = time.monotonic()
    body = "<html>" + "a" * 262144 + "\nAPI_KEY=BOUNDED_SECRET</html>"
    safe = redaction.text(body)
    assert "BOUNDED_SECRET" not in safe
    assert time.monotonic() - started < 1
