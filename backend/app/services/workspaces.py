import hashlib
import secrets
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import String, cast, delete, func, or_, select

from app import models as m

COOKIE = "webscope_workspace"
RETENTION = (
    "Temporary workspace: no account and no recovery. Export anything you want to keep. "
    "End session deletes this workspace immediately. Otherwise it expires 24 hours after creation "
    "and is removed by the cleanup worker, which runs every minute while the service is running. "
    "A hosted restart or redeploy clears sessions earlier. "
    "Closing a tab or browser does not guarantee immediate server deletion."
)


def remove_assessment(db, assessment):
    aid = assessment.id
    for model in (m.CaseFinding, m.CaseEvidence, m.AnalystNote, m.FindingEvidence, m.Finding, m.EvidenceLink):
        db.execute(delete(model).where(model.assessment_id == aid))
    db.delete(assessment)
    db.flush()
    db.execute(delete(m.DetectionRule).where(m.DetectionRule.id.like(f"IMPORT-{aid}-%")))


def remove_workspace(db, workspace):
    for assessment in db.scalars(select(m.Assessment).where(m.Assessment.owner_id == workspace.id)):
        remove_assessment(db, assessment)
    db.delete(workspace)
    db.flush()


def cleanup(db, all_sessions=False):
    query = select(m.WorkspaceSession)
    if not all_sessions:
        query = query.where(m.WorkspaceSession.expires_at <= int(time.time()))
    expired = list(db.scalars(query))
    for workspace in expired:
        remove_workspace(db, workspace)
    db.commit()
    return len(expired)


def lookup(db, token):
    if not token or len(token) > 128:
        return None
    return db.scalar(
        select(m.WorkspaceSession).where(
            m.WorkspaceSession.token_hash == hashlib.sha256(token.encode()).hexdigest(),
            m.WorkspaceSession.expires_at > int(time.time()),
        )
    )


def begin(db, deployment):
    # Caller obtains BEGIN IMMEDIATE before checking quotas or loading fixtures.
    if db.scalar(select(func.count()).select_from(m.WorkspaceSession)) >= deployment.max_sessions:
        raise HTTPException(
            503,
            "Temporary workspace capacity reached. Try later; expired sessions are cleared automatically.",
        )
    token = secrets.token_urlsafe(32)
    workspace = m.WorkspaceSession(
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=int(time.time()) + deployment.session_hours * 3600,
    )
    db.add(workspace)
    db.flush()
    return workspace, token


def usage(db, owner_id):
    owned = select(m.Assessment.id).where(m.Assessment.owner_id == owner_id)
    evidence_bytes = db.scalar(
        select(
            func.coalesce(
                func.sum(func.length(m.Evidence.raw) + func.length(cast(m.Evidence.data, String))), 0
            )
        ).where(m.Evidence.assessment_id.in_(owned))
    )
    report_bytes = db.scalar(
        select(func.coalesce(func.sum(func.length(m.Report.content)), 0)).where(
            m.Report.assessment_id.in_(owned)
        )
    )
    return int(evidence_bytes + report_bytes)


def enforce_quota(db):
    owner = db.info.get("owner_id")
    deployment = db.info.get("deployment")
    if owner and deployment and usage(db, owner) > deployment.max_storage_bytes:
        raise HTTPException(
            413,
            "Temporary workspace storage limit reached (20 MB). Delete an assessment or end this session.",
        )


def visible_rules(db, assessment_id=None):
    findings = select(m.Finding.rule_id)
    if assessment_id:
        findings = findings.where(m.Finding.assessment_id == assessment_id)
    else:
        findings = findings.join(m.Assessment, m.Assessment.id == m.Finding.assessment_id).where(
            m.Assessment.owner_id == db.info.get("owner_id")
        )
    return list(
        db.scalars(
            select(m.DetectionRule).where(
                or_(~m.DetectionRule.id.startswith("IMPORT-"), m.DetectionRule.id.in_(findings))
            )
        )
    )


def status(workspace, deployment):
    return {
        "mode": deployment.mode,
        "temporary": workspace is not None,
        "session_active": workspace is not None,
        "expires_at": datetime.fromtimestamp(workspace.expires_at, timezone.utc).isoformat()
        if workspace
        else None,
        "network_enabled": deployment.network_enabled,
        "retention_notice": RETENTION,
        "max_upload_bytes": 2_000_000,
        "max_storage_bytes": deployment.max_storage_bytes,
        "max_assessments": deployment.max_assessments,
        "formats": ["webscope", "har", "openapi"],
    }
