import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app import models as m
from app.db import make_engine
from app.main import create_app
from app.services.analysis import finding, seed_rules
from app.services.store import evidence, record


def seed_finding(db, aid):
    seed_rules(db)
    ev = evidence(db, aid, "HTTP_RESPONSE", "http://127.0.0.1/", "Fixture response", {"status_code": 200})
    item = finding(db, aid, "WS-HDR-001", ev, "Fixture is missing CSP.")
    db.commit()
    return item, ev


def test_findings_require_same_assessment_evidence_at_database_level(db, make_assessment):
    a, b = make_assessment(), make_assessment()
    original, ev = seed_finding(db, a.id)
    other = evidence(db, b.id, "HTTP_RESPONSE", "http://127.0.0.1/", "Other assessment", {})
    db.commit()
    fields = {k: v for k, v in record(original).items() if k not in ("id", "created_at")}
    for evidence_id in (None, "missing-evidence", other.id):
        with pytest.raises(IntegrityError):
            db.add(m.Finding(**{**fields, "evidence_id": evidence_id, "title": "Different observation"}))
            db.commit()
        db.rollback()
    with pytest.raises(IntegrityError):
        db.add(m.FindingEvidence(finding_id=original.id, evidence_id=other.id, assessment_id=a.id))
        db.commit()
    db.rollback()
    with pytest.raises(IntegrityError):
        db.execute(delete(m.Evidence).where(m.Evidence.id == ev.id))
        db.commit()
    db.rollback()
    assert db.get(m.Finding, original.id) is not None
    assert db.get(m.Evidence, ev.id) is not None


def test_source_and_automated_facts_immutable_at_database_level(db, make_assessment):
    item = make_assessment()
    found, ev = seed_finding(db, item.id)
    with pytest.raises(IntegrityError, match="immutable"):
        db.execute(update(m.Evidence).where(m.Evidence.id == ev.id).values(raw="replacement"))
        db.commit()
    db.rollback()
    with pytest.raises(IntegrityError, match="immutable"):
        db.execute(update(m.Finding).where(m.Finding.id == found.id).values(severity="CRITICAL"))
        db.commit()
    db.rollback()
    db.execute(
        update(m.Finding)
        .where(m.Finding.id == found.id)
        .values(analyst_severity="HIGH", analyst_assessment="Manual reassessment")
    )
    db.commit()
    db.expire_all()
    assert db.get(m.Finding, found.id).severity == "MEDIUM"
    assert db.get(m.Finding, found.id).analyst_severity == "HIGH"


def test_case_cross_assessment_links_rejected(client, db, payload):
    a = client.post("/api/assessments", json=payload).json()["id"]
    b = client.post("/api/assessments", json=payload).json()["id"]
    found, ev = seed_finding(db, b)
    response = client.post(
        f"/api/assessments/{a}/cases", json={"title": "Invalid links", "finding_ids": [found.id]}
    )
    assert response.status_code == 400
    case = m.Case(assessment_id=a, title="Direct DB case", scope={})
    db.add(case)
    db.commit()
    with pytest.raises(IntegrityError):
        db.add(m.CaseEvidence(case_id=case.id, evidence_id=ev.id, assessment_id=a))
        db.commit()
    db.rollback()


def test_workflow_persists_after_database_reopen(client, db, engine, payload):
    aid = client.post("/api/assessments", json=payload).json()["id"]
    found, ev = seed_finding(db, aid)
    assert (
        client.post(
            f"/api/findings/{found.id}/notes", json={"content": "Persistent analyst conclusion."}
        ).status_code
        == 201
    )
    case = client.post(
        f"/api/assessments/{aid}/cases",
        json={"title": "Persistent case", "finding_ids": [found.id], "evidence_ids": [ev.id]},
    ).json()
    report = client.post(f"/api/assessments/{aid}/reports", json={"format": "json"}).json()
    reopened_engine = make_engine(str(engine.url))
    with TestClient(create_app(reopened_engine)) as reopened:
        detail = reopened.get(f"/api/findings/{found.id}").json()
        assert detail["notes"][0]["content"] == "Persistent analyst conclusion."
        assert reopened.get(f"/api/cases/{case['id']}").json()["evidence"][0]["id"] == ev.id
        export = reopened.get(f"/api/reports/{report['id']}/download")
        assert json.loads(export.content)["assessment"]["id"] == aid


def test_reclassification_and_case_lifecycle_guards(client, db, payload):
    aid = client.post("/api/assessments", json=payload).json()["id"]
    found, ev = seed_finding(db, aid)
    assert client.patch(f"/api/findings/{found.id}", json={"status": "CONFIRMED"}).status_code == 400
    assert (
        client.patch(f"/api/findings/{found.id}", json={"priority_override": "CRITICAL"}).status_code == 400
    )
    assert client.patch(f"/api/findings/{found.id}", json={"severity": "CRITICAL"}).status_code == 422
    case = client.post(f"/api/assessments/{aid}/cases", json={"title": "Case"}).json()
    assert client.patch(f"/api/cases/{case['id']}", json={"status": "CLOSED"}).status_code == 400


def test_missing_header_context_and_risk_are_not_confirmed_vulnerabilities(db, make_assessment):
    from app.services.analysis import risk

    item = make_assessment()
    found, ev = seed_finding(db, item.id)
    assert found.status == "NEW" and found.automated["classification"] == "POTENTIAL_WEAKNESS"
    result = risk(item, found)
    assert result["score"] == 2
    assert result["automated_priority"] == "MEDIUM"
    assert len(result["factors"]) == 6
    assert db.scalar(select(m.Finding).where(m.Finding.id == found.id)).evidence_id == ev.id


def test_evidence_lineage_and_redacted_capture(client, db, payload):
    import base64
    import io
    from PIL import Image

    aid = client.post("/api/assessments", json=payload).json()["id"]
    found, ev = seed_finding(db, aid)
    captured = client.post(f"/api/evidence/{ev.id}/capture", json={})
    assert captured.status_code == 201, captured.text
    item = captured.json()
    assert item["type"] == "SCREENSHOT" and item["data"]["source_evidence_id"] == ev.id
    image = client.get(f"/api/evidence/{item['id']}/image")
    assert image.content == base64.b64decode(item["data"]["image_base64"])
    assert Image.open(io.BytesIO(image.content)).size[0] == 1100
    detail = client.get(f"/api/evidence/{item['id']}").json()
    assert detail["lineage"][0]["parent_id"] == ev.id
    assert detail["findings"][0]["id"] == found.id
    assert client.post(f"/api/evidence/{item['id']}/capture", json={}).status_code == 400
    assert client.get(f"/api/evidence/{ev.id}/image").status_code == 404
    with pytest.raises(IntegrityError):
        db.execute(delete(m.Evidence).where(m.Evidence.id == ev.id))
        db.commit()
    db.rollback()
