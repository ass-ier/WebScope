import os
import base64
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select

from app import models as m
from app.db import database_url, make_engine, session_factory
from app.schemas import (
    AssessmentCreate,
    AssessmentUpdate,
    AssessmentView,
    CaseCreate,
    CaseUpdate,
    Configuration,
    EndpointCreate,
    FindingUpdate,
    NoteCreate,
    OpenAPIImport,
    Record,
    ReportCreate,
    SafeChecks,
)
from app.services import assessments, redaction, reporting
from app.services.analysis import analyze, risk, seed_rules
from app.services.capture import capture
from app.services.discovery import endpoint, import_openapi
from app.services.graph import graph
from app.services.scope import Scope
from app.services.store import add_note, event, evidence, record, rows


def create_app(engine=None):
    testing = engine is not None
    engine = engine or make_engine(database_url())
    factory = session_factory(engine)

    @asynccontextmanager
    async def lifespan(app):
        with factory() as db:
            seed_rules(db)
            for item in db.scalars(select(m.Assessment).where(m.Assessment.status == "RUNNING")):
                item.status = "FAILED"
                event(
                    db,
                    item.id,
                    "EXECUTION_INTERRUPTED",
                    "Previous process stopped during execution; run was not resumed",
                )
            db.commit()
        yield
        engine.dispose()

    app = FastAPI(title="WebScope", version="1.0.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.sessions = factory

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = (
            request.headers.get("host", "").split(":")[0]
            if not request.headers.get("host", "").startswith("[")
            else "[::1]"
        )
        allowed_hosts = {"127.0.0.1", "localhost", "[::1]"} | ({"testserver"} if testing else set())
        if host not in allowed_hosts:
            return JSONResponse({"detail": "Invalid local workstation Host"}, status_code=403)
        origin = request.headers.get("origin")
        permitted_origins = {
            f"{request.url.scheme}://{request.headers.get('host')}",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        }
        if origin and origin not in permitted_origins:
            return JSONResponse({"detail": "Cross-origin workstation access is prohibited"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site workstation access is prohibited"}, status_code=403)
        if request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("x-webscope-request") != "workstation":
                return JSONResponse({"detail": "Missing workstation request header"}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "JSON Content-Type is required"}, status_code=415)
        if request.method in ("POST", "PATCH", "PUT"):
            size, chunks = 0, []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 2_100_000:
                    return JSONResponse({"detail": "Request body exceeds 2.1 MB limit"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.exception_handler(ValueError)
    async def value_error(request, exc):
        return JSONResponse({"detail": redaction.text(str(exc))}, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            {
                "detail": "Invalid request: "
                + "; ".join(".".join(str(x) for x in e["loc"]) + ": " + e["msg"] for e in exc.errors())
            },
            status_code=422,
        )

    def database():
        with factory() as db:
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def get(db, model, id):
        item = db.get(model, id)
        if item is None:
            raise HTTPException(404, "Record not found")
        return item

    def editable(db, id):
        item = get(db, m.Assessment, id)
        if item.status in ("RUNNING", "ARCHIVED"):
            raise HTTPException(409, "Running or archived assessment is read-only")
        return item

    def require_members(db, model, ids, aid):
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate relationship IDs are not allowed")
        for id in ids:
            item = get(db, model, id)
            if item.assessment_id != aid:
                raise ValueError("Cross-assessment relationships are prohibited")

    def finding_view(db, item):
        assessment = get(db, m.Assessment, item.assessment_id)
        links = list(db.scalars(select(m.FindingEvidence).where(m.FindingEvidence.finding_id == item.id)))
        evs = [get(db, m.Evidence, link.evidence_id) for link in links]
        if not any(e.id == item.evidence_id for e in evs):
            evs.insert(0, get(db, m.Evidence, item.evidence_id))
        ev_ids = [e.id for e in evs]
        txs = list(
            db.scalars(
                select(m.HTTPTransaction).where(
                    m.HTTPTransaction.assessment_id == item.assessment_id,
                    m.HTTPTransaction.evidence_id.in_(ev_ids),
                )
            )
        )
        return {
            **record(item),
            "evidence": [record(e) for e in evs],
            "transactions": [record(t) for t in txs],
            "rule": record(get(db, m.DetectionRule, item.rule_id)),
            "notes": [
                record(n)
                for n in db.scalars(select(m.AnalystNote).where(m.AnalystNote.finding_id == item.id))
            ],
            "risk": risk(assessment, item),
        }

    def case_view(db, item):
        finds = list(db.scalars(select(m.CaseFinding).where(m.CaseFinding.case_id == item.id)))
        evs = list(db.scalars(select(m.CaseEvidence).where(m.CaseEvidence.case_id == item.id)))
        return {
            **record(item),
            "findings": [record(get(db, m.Finding, f.finding_id)) for f in finds],
            "evidence": [record(get(db, m.Evidence, e.evidence_id)) for e in evs],
            "notes": [
                record(n) for n in db.scalars(select(m.AnalystNote).where(m.AnalystNote.case_id == item.id))
            ],
            "timeline": [
                record(t)
                for t in rows(db, m.TimelineEvent, item.assessment_id)
                if t.data.get("case_id") == item.id
            ],
        }

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": "1.0.0",
            "mode": "local-first",
            "external_intelligence": "not installed",
        }

    @app.get("/api/assessments", response_model=list[AssessmentView])
    def list_assessments(db=Depends(database)):
        return [
            assessments.overview(db, item)
            for item in db.scalars(select(m.Assessment).order_by(m.Assessment.created_at.desc()))
        ]

    @app.post("/api/assessments", response_model=AssessmentView, status_code=201)
    def create_assessment(payload: AssessmentCreate, db=Depends(database)):
        return assessments.overview(db, assessments.create(db, payload))

    @app.get("/api/assessments/{id}", response_model=AssessmentView)
    def get_assessment(id: str, db=Depends(database)):
        return assessments.overview(db, get(db, m.Assessment, id))

    @app.patch("/api/assessments/{id}", response_model=AssessmentView)
    def update_assessment(id: str, payload: AssessmentUpdate, db=Depends(database)):
        item = get(db, m.Assessment, id)
        if item.status == "RUNNING":
            raise HTTPException(409, "Cannot edit an executing assessment")
        if item.status == "ARCHIVED" and payload.status != "DRAFT":
            raise HTTPException(409, "Restore the archived assessment to DRAFT before editing")
        values = payload.model_dump(exclude_unset=True)
        if any(value is None for value in values.values()):
            raise ValueError("Assessment fields cannot be null")
        current_scope = assessments.scope_for(db, item)
        config = payload.config or current_scope.config
        rules = payload.scope or current_scope.rules
        changing_scope = payload.scope is not None or (
            payload.config is not None
            and payload.config.allow_private_network != current_scope.config.allow_private_network
        )
        if changing_scope and not (
            payload.authorized and payload.authorization_note and payload.authorization_note.strip()
        ):
            raise ValueError("Scope/network-policy changes require explicit reauthorization and a statement")
        authorized = payload.authorized if payload.authorized is not None else item.authorized
        statement = (
            payload.authorization_note if payload.authorization_note is not None else item.authorization_note
        )
        if authorized and not statement.strip():
            raise ValueError("Authorization requires a statement")
        scope = Scope(current_scope.target, rules, config, authorized)
        scope.validate(scope.target)
        for path in config.safe_paths:
            p = urlsplit(scope.target)
            scope.validate(f"{p.scheme}://{p.netloc}{path}")
        for key in ("name", "description", "status", "authorized", "authorization_note"):
            if key in values:
                setattr(item, key, redaction.clean(values[key]))
        if payload.config:
            item.config = config.model_dump()
        if payload.scope:
            assessments.save_scope(db, item.id, rules)
        if payload.authorized is not None:
            item.authorized_at = m.now() if payload.authorized else None
        if changing_scope or payload.authorized is False or payload.status == "DRAFT":
            assessments.target_for(db, item.id).validated_at = None
            item.status = "DRAFT"
        if payload.status == "READY":
            assessments.validate(db, item)
        event(
            db,
            item.id,
            "ASSESSMENT_UPDATED",
            "Assessment policy or metadata updated",
            {"fields": list(values), "reauthorized": changing_scope},
        )
        return assessments.overview(db, item)

    @app.delete("/api/assessments/{id}", status_code=204)
    def delete_assessment(id: str, db=Depends(database)):
        item = get(db, m.Assessment, id)
        if item.status != "ARCHIVED":
            raise HTTPException(409, "Archive an assessment before permanent deletion")
        # Remove restrictive dependent links before cascading the owned assessment.
        db.execute(delete(m.CaseFinding).where(m.CaseFinding.assessment_id == id))
        db.execute(delete(m.CaseEvidence).where(m.CaseEvidence.assessment_id == id))
        db.execute(delete(m.AnalystNote).where(m.AnalystNote.assessment_id == id))
        db.execute(delete(m.FindingEvidence).where(m.FindingEvidence.assessment_id == id))
        db.execute(delete(m.Finding).where(m.Finding.assessment_id == id))
        db.execute(delete(m.EvidenceLink).where(m.EvidenceLink.assessment_id == id))
        db.delete(item)
        db.flush()
        return Response(status_code=204)

    @app.post("/api/assessments/{id}/validate", response_model=AssessmentView)
    def validate(id: str, db=Depends(database)):
        return assessments.overview(db, assessments.validate(db, get(db, m.Assessment, id)))

    @app.post("/api/assessments/{id}/discover", response_model=AssessmentView)
    async def discover(id: str, db=Depends(database)):
        item = await assessments.collect(db, editable(db, id))
        if item.status == "FAILED":
            raise HTTPException(
                502, "No successful collection. Inspect the persisted evidence and timeline for failures."
            )
        return assessments.overview(db, item)

    @app.post("/api/assessments/{id}/checks", response_model=AssessmentView)
    async def checks(id: str, payload: SafeChecks, db=Depends(database)):
        item = await assessments.collect(db, editable(db, id), checks=payload)
        if item.status == "FAILED":
            raise HTTPException(
                502, "Safe checks collected no successful responses. Inspect evidence and timeline."
            )
        return assessments.overview(db, item)

    @app.post("/api/assessments/{id}/analyze", response_model=AssessmentView)
    def analyze_assessment(id: str, db=Depends(database)):
        item = editable(db, id)
        analyze(db, item)
        return assessments.overview(db, item)

    @app.get("/api/assessments/{id}/graph")
    def get_graph(id: str, db=Depends(database)):
        get(db, m.Assessment, id)
        return graph(db, id)

    @app.get("/api/assessments/{id}/controls")
    def get_controls(id: str, db=Depends(database)):
        get(db, m.Assessment, id)
        return {
            "headers": [record(r) for r in rows(db, m.SecurityHeaderObservation, id)],
            "cookies": [record(r) for r in rows(db, m.Cookie, id)],
            "cors": [record(r) for r in rows(db, m.Evidence, id) if r.type == "CORS_OBSERVATION"],
        }

    @app.get("/api/assessments/{id}/{collection}", response_model=list[Record])
    def get_collection(id: str, collection: str, db=Depends(database)):
        get(db, m.Assessment, id)
        datasets = {**reporting.DATASETS, "timeline": m.TimelineEvent}
        if collection not in datasets:
            raise HTTPException(404, "Unknown collection")
        return [record(r) for r in rows(db, datasets[collection], id)]

    @app.post("/api/assessments/{id}/endpoints", response_model=Record, status_code=201)
    def manual_endpoint(id: str, payload: EndpointCreate, db=Depends(database)):
        item = editable(db, id)
        scope = assessments.scope_for(db, item)
        scope.validate(payload.url)
        ev = evidence(
            db, id, "ENDPOINT", payload.url, "Analyst-supplied endpoint (not executed)", payload.model_dump()
        )
        return record(
            endpoint(
                db,
                id,
                scope,
                payload.url,
                "MANUAL",
                ev.id,
                payload.method,
                payload.parameters,
                {"execution": "NEVER", "kind": "endpoint"},
            )
        )

    @app.post("/api/assessments/{id}/openapi")
    def openapi(id: str, payload: OpenAPIImport, db=Depends(database)):
        return import_openapi(db, id, assessments.scope_for(db, editable(db, id)), payload.document)

    @app.get("/api/findings/{id}", response_model=Record)
    def get_finding(id: str, db=Depends(database)):
        return finding_view(db, get(db, m.Finding, id))

    @app.patch("/api/findings/{id}", response_model=Record)
    def update_finding(id: str, payload: FindingUpdate, db=Depends(database)):
        item = get(db, m.Finding, id)
        editable(db, item.assessment_id)
        changes = payload.model_dump(exclude_unset=True)
        if changes.get("status", item.status) is None or changes.get("analyst_assessment", "") is None:
            raise ValueError("Status and analyst assessment cannot be null")
        reasoning = payload.override_reason if payload.override_reason is not None else item.override_reason
        conclusion = (
            payload.analyst_assessment if payload.analyst_assessment is not None else item.analyst_assessment
        )
        if (
            any(
                changes.get(k) is not None
                for k in ("priority_override", "analyst_severity", "analyst_confidence")
            )
            and not (reasoning or conclusion).strip()
        ):
            raise ValueError("Reclassification or priority override requires an explanation")
        if changes.get("status") in ("CONFIRMED", "FALSE_POSITIVE", "DISMISSED") and not conclusion.strip():
            raise ValueError("A final analyst disposition requires a written conclusion")
        if changes.get("override_reason", "") is None:
            raise ValueError("Override reason cannot be null")
        if "priority_override" in changes and changes["priority_override"] is None:
            changes["override_reason"] = ""
        for key, value in changes.items():
            setattr(item, key, redaction.clean(value))
        event(
            db,
            item.assessment_id,
            "FINDING_CONFIRMED" if item.status == "CONFIRMED" else "ANALYST_REVIEWED_FINDING",
            "Analyst updated finding assessment; original automated facts retained",
            {"finding_id": id, "changes": changes},
        )
        return finding_view(db, item)

    @app.post("/api/findings/{id}/notes", response_model=Record, status_code=201)
    def finding_note(id: str, payload: NoteCreate, db=Depends(database)):
        item = get(db, m.Finding, id)
        editable(db, item.assessment_id)
        return record(add_note(db, item.assessment_id, payload, finding_id=id))

    @app.post("/api/assessments/{id}/notes", response_model=Record, status_code=201)
    def assessment_note(id: str, payload: NoteCreate, db=Depends(database)):
        editable(db, id)
        return record(add_note(db, id, payload))

    @app.get("/api/evidence/{id}", response_model=Record)
    def get_evidence(id: str, db=Depends(database)):
        item = get(db, m.Evidence, id)
        related_ids = {id}
        for link in rows(db, m.EvidenceLink, item.assessment_id):
            if link.child_id == id:
                related_ids.add(link.parent_id)
        return {
            **record(item),
            "lineage": [
                record(r)
                for r in rows(db, m.EvidenceLink, item.assessment_id)
                if id in (r.parent_id, r.child_id)
            ],
            "findings": [
                record(r) for r in rows(db, m.Finding, item.assessment_id) if r.evidence_id in related_ids
            ],
            "endpoints": [
                record(r) for r in rows(db, m.Endpoint, item.assessment_id) if r.evidence_id in related_ids
            ],
            "transactions": [
                record(r)
                for r in rows(db, m.HTTPTransaction, item.assessment_id)
                if related_ids.intersection((r.evidence_id, r.request_evidence_id))
            ],
        }

    @app.post("/api/evidence/{id}/capture", response_model=Record, status_code=201)
    def capture_evidence(id: str, db=Depends(database)):
        item = get(db, m.Evidence, id)
        editable(db, item.assessment_id)
        if item.type == "SCREENSHOT":
            raise ValueError("Capture the source evidence, not another screenshot")
        return record(capture(db, item))

    @app.get("/api/evidence/{id}/image")
    def evidence_image(id: str, db=Depends(database)):
        item = get(db, m.Evidence, id)
        if item.type != "SCREENSHOT":
            raise HTTPException(404, "This evidence is not an image")
        return Response(
            base64.b64decode(item.data["image_base64"]),
            media_type="image/png",
            headers={"Content-Disposition": f'inline; filename="evidence-{id}.png"'},
        )

    @app.get("/api/transactions/{id}", response_model=Record)
    def get_transaction(id: str, db=Depends(database)):
        item = get(db, m.HTTPTransaction, id)
        return {
            **record(item),
            "evidence": [
                record(get(db, m.Evidence, e)) for e in (item.request_evidence_id, item.evidence_id)
            ],
        }

    @app.get("/api/cases", response_model=list[Record])
    def list_cases(db=Depends(database)):
        return [record(r) for r in db.scalars(select(m.Case))]

    @app.post("/api/assessments/{id}/cases", response_model=Record, status_code=201)
    def create_case(id: str, payload: CaseCreate, db=Depends(database)):
        assessment = editable(db, id)
        require_members(db, m.Finding, payload.finding_ids, id)
        require_members(db, m.Evidence, payload.evidence_ids, id)
        item = m.Case(
            assessment_id=id,
            title=redaction.text(payload.title),
            description=redaction.text(payload.description),
            scope=assessments.scope_for(db, assessment).rules.model_dump(),
            priority=payload.priority,
            assigned_analyst=redaction.text(payload.assigned_analyst),
        )
        db.add(item)
        db.flush()
        for fid in payload.finding_ids:
            db.add(m.CaseFinding(case_id=item.id, finding_id=fid, assessment_id=id))
        for eid in payload.evidence_ids:
            db.add(m.CaseEvidence(case_id=item.id, evidence_id=eid, assessment_id=id))
        db.flush()
        event(db, id, "CASE_CREATED", "Assessment investigation case opened", {"case_id": item.id})
        return case_view(db, item)

    @app.get("/api/cases/{id}", response_model=Record)
    def get_case(id: str, db=Depends(database)):
        return case_view(db, get(db, m.Case, id))

    @app.patch("/api/cases/{id}", response_model=Record)
    def update_case(id: str, payload: CaseUpdate, db=Depends(database)):
        item = get(db, m.Case, id)
        editable(db, item.assessment_id)
        changes = payload.model_dump(exclude_unset=True)
        if any(v is None for v in changes.values()):
            raise ValueError("Case fields cannot be null")
        transitions = {
            "OPEN": {"INVESTIGATING"},
            "INVESTIGATING": {"OPEN", "REMEDIATION"},
            "REMEDIATION": {"INVESTIGATING", "VERIFICATION"},
            "VERIFICATION": {"REMEDIATION", "CLOSED"},
            "CLOSED": {"INVESTIGATING"},
        }
        if (
            payload.status
            and payload.status != item.status
            and payload.status not in transitions[item.status]
        ):
            raise ValueError(f"Invalid case transition from {item.status} to {payload.status}")
        for key, model, field, entity in (
            ("finding_ids", m.CaseFinding, "finding_id", m.Finding),
            ("evidence_ids", m.CaseEvidence, "evidence_id", m.Evidence),
        ):
            if key in changes:
                ids = changes.pop(key)
                require_members(db, entity, ids, item.assessment_id)
                db.execute(delete(model).where(model.case_id == id))
                for value in ids:
                    db.add(model(**{"case_id": id, field: value, "assessment_id": item.assessment_id}))
        for key, value in changes.items():
            setattr(item, key, redaction.clean(value))
        db.flush()
        event(
            db,
            item.assessment_id,
            "CASE_UPDATED",
            f"Case status: {item.status}",
            {"case_id": item.id, "changes": changes},
        )
        return case_view(db, item)

    @app.post("/api/cases/{id}/notes", response_model=Record, status_code=201)
    def case_note(id: str, payload: NoteCreate, db=Depends(database)):
        item = get(db, m.Case, id)
        editable(db, item.assessment_id)
        return record(add_note(db, item.assessment_id, payload, case_id=id))

    @app.post("/api/assessments/{id}/reports", response_model=Record, status_code=201)
    def report(id: str, payload: ReportCreate, db=Depends(database)):
        item = get(db, m.Assessment, id)
        if item.status == "RUNNING":
            raise HTTPException(409, "Wait for the active collection before generating a report")
        return record(reporting.generate(db, item, payload))

    @app.get("/api/reports/{id}/download")
    def download(id: str, db=Depends(database)):
        item = get(db, m.Report, id)
        return Response(
            item.content,
            media_type=item.mime_type,
            headers={"Content-Disposition": f'attachment; filename="{item.filename}"'},
        )

    @app.get("/api/settings", response_model=Configuration)
    def get_settings(db=Depends(database)):
        item = db.get(m.Settings, 1)
        return item.values if item else Configuration().model_dump()

    @app.patch("/api/settings", response_model=Configuration)
    def update_settings(payload: Configuration, db=Depends(database)):
        item = db.get(m.Settings, 1)
        if item:
            item.values = payload.model_dump()
        else:
            db.add(m.Settings(id=1, values=payload.model_dump()))
        return payload

    @app.get("/api/rules", response_model=list[Record])
    def rules(db=Depends(database)):
        return [record(r) for r in db.scalars(select(m.DetectionRule))]

    frontend = Path(os.environ.get("WEBSCOPE_FRONTEND_DIR", "../frontend/dist"))
    if frontend.is_dir():

        class SPAFiles(StaticFiles):
            async def get_response(self, path, scope):
                try:
                    return await super().get_response(path, scope)
                except HTTPException as exc:
                    if exc.status_code != 404:
                        raise
                    return await super().get_response("index.html", scope)

        app.mount("/", SPAFiles(directory=frontend, html=True), name="frontend")
    return app
