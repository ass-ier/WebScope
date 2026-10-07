from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def uid():
    return str(uuid4())


def now():
    return datetime.now(timezone.utc).isoformat()


class Identity:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[str] = mapped_column(String, default=now)


class Assessment(Identity, Base):
    __tablename__ = "assessments"
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="DRAFT")
    updated_at: Mapped[str] = mapped_column(String, default=now, onupdate=now)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    authorized_at: Mapped[str | None] = mapped_column(String)
    __table_args__ = (
        CheckConstraint("status IN ('DRAFT','READY','RUNNING','COMPLETED','FAILED','ARCHIVED')"),
    )


class Target(Identity, Base):
    __tablename__ = "targets"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), unique=True)
    url: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str] = mapped_column(String)
    validated_at: Mapped[str | None] = mapped_column(String)


class ScopeRule(Identity, Base):
    __tablename__ = "scope_rules"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(Text)
    __table_args__ = (CheckConstraint("kind IN ('ALLOW_HOST','EXCLUDE_HOST','EXCLUDE_PATH')"),)


class Evidence(Identity, Base):
    __tablename__ = "evidence"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON)
    raw: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64))
    collector: Mapped[str] = mapped_column(String, default="webscope/1.0")
    __table_args__ = (UniqueConstraint("id", "assessment_id"),)


class EvidenceLink(Base):
    __tablename__ = "evidence_links"
    parent_id: Mapped[str] = mapped_column(String, primary_key=True)
    child_id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String)
    relation: Mapped[str] = mapped_column(String, default="derived_from")
    __table_args__ = (
        ForeignKeyConstraint(["parent_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
        ForeignKeyConstraint(
            ["child_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"], ondelete="CASCADE"
        ),
        CheckConstraint("parent_id != child_id"),
    )


class Observed(Identity):
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str] = mapped_column(String(36))


def observed_constraints(*extra):
    return (
        ForeignKeyConstraint(
            ["evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"], ondelete="CASCADE"
        ),
        UniqueConstraint("id", "assessment_id"),
        *extra,
    )


class Host(Observed, Base):
    __tablename__ = "hosts"
    hostname: Mapped[str] = mapped_column(String)
    addresses: Mapped[list] = mapped_column(JSON, default=list)
    __table_args__ = observed_constraints(UniqueConstraint("assessment_id", "hostname"))


class DNSRecord(Observed, Base):
    __tablename__ = "dns_records"
    hostname: Mapped[str] = mapped_column(String)
    record_type: Mapped[str] = mapped_column(String)
    ttl: Mapped[int | None] = mapped_column(Integer)
    resolver: Mapped[str] = mapped_column(String)
    records: Mapped[list] = mapped_column(JSON)
    __table_args__ = observed_constraints()


class TLSCertificate(Observed, Base):
    __tablename__ = "tls_certificates"
    hostname: Mapped[str] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSON)
    __table_args__ = observed_constraints()


class Endpoint(Observed, Base):
    __tablename__ = "endpoints"
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String, default="GET")
    source: Mapped[str] = mapped_column(String)
    content_type: Mapped[str] = mapped_column(String, default="")
    authentication: Mapped[str] = mapped_column(String, default="UNKNOWN")
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = observed_constraints(UniqueConstraint("assessment_id", "url", "method"))


class Technology(Observed, Base):
    __tablename__ = "technologies"
    name: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)
    rationale: Mapped[str] = mapped_column(Text)
    endpoint_id: Mapped[str | None] = mapped_column(String)
    __table_args__ = observed_constraints(
        ForeignKeyConstraint(["endpoint_id", "assessment_id"], ["endpoints.id", "endpoints.assessment_id"]),
        UniqueConstraint("assessment_id", "name", "evidence_id"),
    )


class HTTPTransaction(Observed, Base):
    __tablename__ = "http_transactions"
    request_evidence_id: Mapped[str] = mapped_column(String)
    endpoint_id: Mapped[str | None] = mapped_column(String)
    method: Mapped[str] = mapped_column(String)
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer)
    elapsed_ms: Mapped[float] = mapped_column(Float)
    request: Mapped[dict] = mapped_column(JSON)
    response: Mapped[dict] = mapped_column(JSON)
    __table_args__ = observed_constraints(
        ForeignKeyConstraint(
            ["request_evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]
        ),
        ForeignKeyConstraint(["endpoint_id", "assessment_id"], ["endpoints.id", "endpoints.assessment_id"]),
    )


class Cookie(Observed, Base):
    __tablename__ = "cookies"
    name: Mapped[str] = mapped_column(String)
    attributes: Mapped[dict] = mapped_column(JSON)
    __table_args__ = observed_constraints()


class SecurityHeaderObservation(Observed, Base):
    __tablename__ = "security_headers"
    name: Mapped[str] = mapped_column(String)
    present: Mapped[bool] = mapped_column(Boolean)
    value: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    __table_args__ = observed_constraints()


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    version: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)
    required_evidence: Mapped[list] = mapped_column(JSON)
    request_type: Mapped[str] = mapped_column(String)
    safety_level: Mapped[str] = mapped_column(String)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON)


class Finding(Identity, Base):
    __tablename__ = "findings"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str] = mapped_column(String, nullable=False)
    endpoint_id: Mapped[str | None] = mapped_column(String)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"))
    rule_version: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="NEW")
    description: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON)
    affected_asset: Mapped[str] = mapped_column(Text)
    automated: Mapped[dict] = mapped_column(JSON)
    analyst_assessment: Mapped[str] = mapped_column(Text, default="")
    analyst_severity: Mapped[str | None] = mapped_column(String)
    analyst_confidence: Mapped[str | None] = mapped_column(String)
    priority_override: Mapped[str | None] = mapped_column(String)
    override_reason: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (
        ForeignKeyConstraint(["evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
        ForeignKeyConstraint(["endpoint_id", "assessment_id"], ["endpoints.id", "endpoints.assessment_id"]),
        UniqueConstraint("id", "assessment_id"),
        UniqueConstraint("rule_id", "evidence_id", "title"),
        CheckConstraint("severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')"),
        CheckConstraint("confidence IN ('LOW','MEDIUM','HIGH')"),
        CheckConstraint(
            "status IN ('NEW','REVIEWING','CONFIRMED','FALSE_POSITIVE','NEEDS_VERIFICATION','DISMISSED')"
        ),
    )


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String)
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "assessment_id"], ["findings.id", "findings.assessment_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(["evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
    )


class AnalystNote(Identity, Base):
    __tablename__ = "analyst_notes"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str | None] = mapped_column(String)
    case_id: Mapped[str | None] = mapped_column(String)
    author: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[str] = mapped_column(String)
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "assessment_id"], ["findings.id", "findings.assessment_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["case_id", "assessment_id"], ["cases.id", "cases.assessment_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(["evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
    )


class TimelineEvent(Identity, Base):
    __tablename__ = "timeline_events"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    event: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Case(Identity, Base):
    __tablename__ = "cases"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String, default="OPEN")
    priority: Mapped[str] = mapped_column(String, default="MEDIUM")
    assigned_analyst: Mapped[str] = mapped_column(String, default="")
    __table_args__ = (
        UniqueConstraint("id", "assessment_id"),
        CheckConstraint("status IN ('OPEN','INVESTIGATING','REMEDIATION','VERIFICATION','CLOSED')"),
    )


class CaseFinding(Base):
    __tablename__ = "case_findings"
    case_id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String)
    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "assessment_id"], ["cases.id", "cases.assessment_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(["finding_id", "assessment_id"], ["findings.id", "findings.assessment_id"]),
    )


class CaseEvidence(Base):
    __tablename__ = "case_evidence"
    case_id: Mapped[str] = mapped_column(String, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String)
    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "assessment_id"], ["cases.id", "cases.assessment_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(["evidence_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
    )


class Report(Identity, Base):
    __tablename__ = "reports"
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String)
    dataset: Mapped[str] = mapped_column(String)
    filename: Mapped[str] = mapped_column(String)
    mime_type: Mapped[str] = mapped_column(String)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    sha256: Mapped[str] = mapped_column(String)


class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    values: Mapped[dict] = mapped_column(JSON)
