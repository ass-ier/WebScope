import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import models as m
from app.db import session_factory
from app.deployment import Deployment
from app.main import create_app
from app.services.workspaces import COOKIE, cleanup

HEADERS = {
    "Content-Type": "application/json",
    "X-WebScope-Request": "workstation",
    "Origin": "https://webscope.test",
}
HOSTED = Deployment(
    mode="hosted", public_origin="https://webscope.test", allowed_hosts=("webscope.test", "api.webscope.test")
)


def start(client):
    response = client.post("/api/session", json={})
    assert response.status_code == 200, response.text
    return response


def test_anonymous_session_has_complete_synthetic_data_and_no_signin(hosted):
    assert hosted.get("/api/assessments").status_code == 401
    response = start(hosted)
    data = response.json()
    assert data["temporary"] and not data["network_enabled"]
    assert "24 hours" in data["retention_notice"] and "Closing a tab" in data["retention_notice"]
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "Max-Age" not in cookie and "expires=" not in cookie.lower()
    assessments = hosted.get("/api/assessments").json()
    assert len(assessments) == 2
    web = next(a for a in assessments if a["counts"]["endpoints"] > 0)
    assert web["data_origin"] == "SYNTHETIC" and web["config"]["mode"] == "PASSIVE"
    assert web["counts"]["endpoints"] == 22 and web["counts"]["findings"] == 44
    assert web["counts"]["evidence"] == 139 and web["counts"]["cases"] == 1
    infra = next(a for a in assessments if a["id"] != web["id"])
    assert len(hosted.get(f"/api/assessments/{infra['id']}/dns").json()) == 7
    assert len(hosted.get(f"/api/assessments/{infra['id']}/tls").json()) == 1
    assert start(hosted).json()["expires_at"] == data["expires_at"]
    assert len(hosted.get("/api/assessments").json()) == 2


def test_no_network_even_with_authorization_on_hosted(hosted, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Hosted sessions must never network to a target")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("httpx.AsyncClient.send", forbidden)
    start(hosted)
    aid = hosted.get("/api/assessments").json()[0]["id"]
    response = hosted.post(f"/api/assessments/{aid}/discover", json={})
    assert response.status_code == 400 and "import-only" in response.text
    assert hosted.post(f"/api/assessments/{aid}/analyze", json={}).status_code == 200


def test_two_sessions_cannot_access_ids_rules_reports_or_settings(engine):
    app = create_app(engine, HOSTED)
    with (
        TestClient(app, base_url="https://webscope.test", headers=HEADERS) as alice,
        TestClient(app, base_url="https://webscope.test", headers=HEADERS) as bob,
    ):
        start(alice)
        aid = next(a["id"] for a in alice.get("/api/assessments").json() if a["counts"]["endpoints"])
        fid = alice.get(f"/api/assessments/{aid}/findings").json()[0]["id"]
        eid = alice.get(f"/api/findings/{fid}").json()["evidence_id"]
        tid = alice.get(f"/api/assessments/{aid}/transactions").json()[0]["id"]
        cid = alice.get(f"/api/assessments/{aid}/cases").json()[0]["id"]
        report = alice.post(f"/api/assessments/{aid}/reports", json={"format": "json"}).json()
        start(bob)
        assert aid not in [a["id"] for a in bob.get("/api/assessments").json()]
        for route in (
            f"/assessments/{aid}",
            f"/assessments/{aid}/evidence",
            f"/assessments/{aid}/graph",
            f"/findings/{fid}",
            f"/evidence/{eid}",
            f"/evidence/{eid}/image",
            f"/transactions/{tid}",
            f"/cases/{cid}",
            f"/reports/{report['id']}/download",
        ):
            assert bob.get("/api" + route).status_code == 404, route
        assert bob.patch(f"/api/findings/{fid}", json={"status": "REVIEWING"}).status_code == 404
        assert bob.post(f"/api/evidence/{eid}/capture", json={}).status_code == 404
        assert bob.post(f"/api/assessments/{aid}/reports", json={"format": "json"}).status_code == 404
        assert aid not in bob.get("/api/rules").text
        alice.patch("/api/settings", json={"max_requests": 77})
        assert bob.get("/api/settings").json()["max_requests"] == 30


def test_end_session_deletes_data_and_revokes_copied_cookie(hosted, engine):
    start(hosted)
    token = hosted.cookies.get(COOKIE)
    aid = hosted.get("/api/assessments").json()[0]["id"]
    assert hosted.delete("/api/session").status_code == 204
    assert hosted.get("/api/assessments").status_code == 401
    hosted.cookies.set(COOKIE, token)
    assert hosted.get(f"/api/assessments/{aid}").status_code == 401
    with session_factory(engine)() as db:
        assert db.scalar(select(func.count()).select_from(m.WorkspaceSession)) == 0
        assert db.scalar(select(func.count()).select_from(m.Assessment)) == 0
        assert db.scalar(select(func.count()).select_from(m.Evidence)) == 0
        assert not list(db.scalars(select(m.DetectionRule).where(m.DetectionRule.id.startswith("IMPORT-"))))


def test_expiry_blocks_access_before_cleanup_and_cleanup_deletes(hosted, engine):
    start(hosted)
    with session_factory(engine)() as db:
        workspace = db.scalars(select(m.WorkspaceSession)).one()
        workspace.expires_at = int(time.time()) - 1
        db.commit()
    assert hosted.get("/api/assessments").status_code == 401
    assert hosted.get("/api/session").json()["session_active"] is False
    with session_factory(engine)() as db:
        assert cleanup(db) == 1
        assert not list(db.scalars(select(m.Assessment)))


def test_boundary_and_capacity_are_fail_closed(engine):
    app = create_app(engine, replace(HOSTED, max_sessions=1))
    with TestClient(app, base_url="https://webscope.test", headers=HEADERS) as client:
        assert (
            client.post("/api/session", json={}, headers={"Origin": "https://evil.test"}).status_code == 403
        )
        assert client.post("/api/session", json={}, headers={"Host": "evil.test"}).status_code == 403
        assert client.post("/api/session", json={}, headers={"X-WebScope-Request": ""}).status_code == 403
        start(client)
        client.cookies.clear()
        assert client.post("/api/session", json={}).status_code == 503


def test_hosted_environment_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBSCOPE_DEPLOYMENT", "hosted")
    monkeypatch.delenv("WEBSCOPE_PUBLIC_ORIGIN", raising=False)
    with pytest.raises(ValueError, match="HTTPS frontend"):
        Deployment.from_env()
    monkeypatch.setenv("WEBSCOPE_PUBLIC_ORIGIN", "https://workstation.vercel.app")
    monkeypatch.setenv("WEBSCOPE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "api.onrender.com")
    config = Deployment.from_env()
    assert config.hosted and "api.onrender.com" in config.allowed_hosts
    monkeypatch.setenv("WEBSCOPE_ALLOWED_HOSTS", "*.vercel.app")
    with pytest.raises(ValueError, match="exact hostnames"):
        Deployment.from_env()


def test_snapshot_upload_reids_redacts_and_stays_private(hosted):
    start(hosted)
    source = json.loads((Path(__file__).parents[2] / "docs/example/assessment.json").read_text())
    response = hosted.post(
        "/api/imports",
        json={"format": "webscope", "name": "My uploaded assessment", "document": source, "consent": True},
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["id"] != source["assessment"]["id"] and data["data_origin"] == "UPLOADED"
    assert data["counts"]["findings"] == 44 and data["counts"]["cases"] == 1
    assert not data["authorized"] and data["config"]["mode"] == "PASSIVE"
    imported = hosted.get(f"/api/assessments/{data['id']}/evidence").json()
    assert imported[0]["collector"] == "webscope/unverified-import"
    assert not {e["id"] for e in imported}.intersection(e["id"] for e in source["evidence"])
