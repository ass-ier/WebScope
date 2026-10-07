from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
FindingStatus = Literal["NEW", "REVIEWING", "CONFIRMED", "FALSE_POSITIVE", "NEEDS_VERIFICATION", "DISMISSED"]
CaseStatus = Literal["OPEN", "INVESTIGATING", "REMEDIATION", "VERIFICATION", "CLOSED"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Configuration(StrictModel):
    mode: Literal["PASSIVE", "SAFE_HTTP"] = "PASSIVE"
    max_requests: int = Field(default=30, ge=1, le=200)
    rate_per_second: float = Field(default=2, ge=0.1, le=10)
    timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    max_body_bytes: int = Field(default=262144, ge=512, le=2097152)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_depth: int = Field(default=1, ge=0, le=3)
    max_duration_seconds: float = Field(default=120, ge=1, le=600)
    links: bool = True
    javascript: bool = True
    robots: bool = True
    sitemap: bool = True
    availability: bool = False
    methods: bool = False
    dns: bool = False
    tls: bool = True
    allow_private_network: bool = False
    allowed_ports: list[int] = Field(default_factory=list, max_length=10)
    safe_paths: list[str] = Field(default_factory=list, max_length=20)
    exposure: Literal["INTERNAL", "INTERNET"] = "INTERNAL"
    asset_importance: Literal["LOW", "STANDARD", "PRODUCTION"] = "STANDARD"
    authentication_context: Literal["UNKNOWN", "REQUIRED", "NOT_REQUIRED"] = "UNKNOWN"

    @model_validator(mode="after")
    def valid_paths(self):
        if any(not 1 <= port <= 65535 for port in self.allowed_ports):
            raise ValueError("Allowed ports must be between 1 and 65535")
        if any(not p.startswith("/") or p.startswith("//") or "?" in p or "#" in p for p in self.safe_paths):
            raise ValueError("Safe paths must be absolute paths without a host, query, or fragment")
        return self


class ScopeInput(StrictModel):
    allowed_hosts: list[str] = Field(min_length=1, max_length=30)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=30)
    excluded_paths: list[str] = Field(default_factory=list, max_length=50)


class AssessmentCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=10000)
    target: str = Field(max_length=4096)
    scope: ScopeInput
    config: Configuration = Field(default_factory=Configuration)
    authorized: bool = False
    authorization_note: str = Field(default="", max_length=4000)


class AssessmentUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10000)
    status: Literal["DRAFT", "READY", "ARCHIVED"] | None = None
    config: Configuration | None = None
    scope: ScopeInput | None = None
    authorized: bool | None = None
    authorization_note: str | None = Field(default=None, max_length=4000)


class NoteCreate(StrictModel):
    author: str = Field(default="Local analyst", min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=20000)


class FindingUpdate(StrictModel):
    status: FindingStatus | None = None
    analyst_assessment: str | None = Field(default=None, max_length=20000)
    analyst_severity: Severity | None = None
    analyst_confidence: Confidence | None = None
    priority_override: Severity | None = None
    override_reason: str | None = Field(default=None, max_length=10000)


class EndpointCreate(StrictModel):
    url: str = Field(max_length=4096)
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    parameters: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class OpenAPIImport(StrictModel):
    document: dict[str, Any]


class SafeChecks(StrictModel):
    confirm: bool = False
    cors_origin: Literal["https://webscope.invalid"] | None = None


class CaseCreate(StrictModel):
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=10000)
    priority: Severity = "MEDIUM"
    assigned_analyst: str = Field(default="", max_length=100)
    finding_ids: list[str] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)


class CaseUpdate(StrictModel):
    status: CaseStatus | None = None
    title: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10000)
    priority: Severity | None = None
    assigned_analyst: str | None = Field(default=None, max_length=100)
    finding_ids: list[str] | None = Field(default=None, max_length=200)
    evidence_ids: list[str] | None = Field(default=None, max_length=200)


class ReportCreate(StrictModel):
    format: Literal["markdown", "json", "csv", "pdf"]
    dataset: Literal["assessment", "endpoints", "findings", "technologies", "evidence"] = "assessment"


class Record(BaseModel):
    """Explicit serialization envelope for heterogeneous persisted observations."""

    model_config = ConfigDict(extra="allow")
    id: str
    created_at: str | None = None


class AssessmentView(Record):
    name: str
    description: str
    status: str
    target: str
    scope: ScopeInput
    config: Configuration
    authorized: bool
    authorization_note: str
    counts: dict[str, int]
    severity_counts: dict[str, int]


class ErrorView(BaseModel):
    detail: str
