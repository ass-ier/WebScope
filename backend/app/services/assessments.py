from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update

from app import models as m
from app.schemas import Configuration, ScopeInput
from app.services import redaction
from app.services.analysis import analyze, seed_rules
from app.services.discovery import harvest
from app.services.infrastructure import collect_dns, collect_tls
from app.services.network import NetworkRun
from app.services.scope import Scope
from app.services.store import event, evidence, record, rows
from app.services.technology import fingerprint


def target_for(db, assessment_id):
    return db.scalar(select(m.Target).where(m.Target.assessment_id == assessment_id))


def scope_for(db, assessment):
    rules = rows(db, m.ScopeRule, assessment.id)
    return Scope(
        target_for(db, assessment.id).url,
        ScopeInput(
            allowed_hosts=[r.value for r in rules if r.kind == "ALLOW_HOST"],
            excluded_hosts=[r.value for r in rules if r.kind == "EXCLUDE_HOST"],
            excluded_paths=[r.value for r in rules if r.kind == "EXCLUDE_PATH"],
        ),
        Configuration(**assessment.config),
        assessment.authorized,
    )


def save_scope(db, assessment_id, rules):
    db.execute(delete(m.ScopeRule).where(m.ScopeRule.assessment_id == assessment_id))
    for kind, values in (
        ("ALLOW_HOST", rules.allowed_hosts),
        ("EXCLUDE_HOST", rules.excluded_hosts),
        ("EXCLUDE_PATH", rules.excluded_paths),
    ):
        for value in dict.fromkeys(values):
            db.add(m.ScopeRule(assessment_id=assessment_id, kind=kind, value=value))
    db.flush()


def create(db, payload):
    owner_id = db.info.get("owner_id")
    deployment = db.info.get("deployment")
    if owner_id and deployment:
        count = db.scalar(
            select(func.count()).select_from(m.Assessment).where(m.Assessment.owner_id == owner_id)
        )
        if count >= deployment.max_assessments:
            raise ValueError(
                f"Workspace assessment limit reached ({deployment.max_assessments}); archive and delete unused assessments"
            )
    if payload.authorized and not payload.authorization_note.strip():
        raise ValueError("Explicit authorization requires a non-empty authorization statement")
    scope = Scope(payload.target, payload.scope, payload.config, payload.authorized)
    scope.validate(payload.target)
    if redaction.url(scope.target) != scope.target:
        raise ValueError("Targets must not contain credential-bearing queries or fragments")
    for path in payload.config.safe_paths:
        scope.validate(scope.target.split("://")[0] + "://" + urlsplit(scope.target).netloc + path)
    item = m.Assessment(
        owner_id=owner_id,
        name=redaction.text(payload.name),
        description=redaction.text(payload.description),
        config=payload.config.model_dump(),
        authorized=payload.authorized,
        authorization_note=redaction.text(payload.authorization_note),
        authorized_at=m.now() if payload.authorized else None,
    )
    db.add(item)
    db.flush()
    db.add(m.Target(assessment_id=item.id, url=scope.target, hostname=urlsplit(scope.target).hostname))
    save_scope(db, item.id, payload.scope)
    event(db, item.id, "ASSESSMENT_CREATED", "Assessment created in DRAFT")
    if item.authorized:
        event(
            db,
            item.id,
            "AUTHORIZATION_RECORDED",
            "Analyst explicitly authorized the defined target and scope",
            {"statement": item.authorization_note},
        )
    seed_rules(db)
    return item


def overview(db, item):
    scope = scope_for(db, item)
    findings = rows(db, m.Finding, item.id)
    endpoints = rows(db, m.Endpoint, item.id)
    counts = {
        name: len(rows(db, model, item.id))
        for name, model in (
            ("hosts", m.Host),
            ("technologies", m.Technology),
            ("transactions", m.HTTPTransaction),
            ("evidence", m.Evidence),
            ("cases", m.Case),
        )
    }
    counts.update(
        endpoints=len(endpoints),
        findings=len(findings),
        apis=sum(1 for e in endpoints if e.details.get("kind") == "api" or "/api" in urlsplit(e.url).path),
    )
    return {
        **record(item),
        "target": scope.target,
        "scope": scope.rules.model_dump(),
        "counts": counts,
        "severity_counts": {
            severity: sum(
                1
                for f in findings
                if (f.analyst_severity or f.severity) == severity
                and f.status not in ("FALSE_POSITIVE", "DISMISSED")
            )
            for severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        },
    }


def validate(db, assessment):
    if assessment.status in ("RUNNING", "ARCHIVED"):
        raise ValueError("Running or archived assessments cannot be validated")
    scope = scope_for(db, assessment)
    scope.validate(scope.target)
    if not assessment.authorized or not assessment.authorization_note.strip():
        raise ValueError("Record explicit authorization before validating this target")
    target_for(db, assessment.id).validated_at = m.now()
    assessment.status = "READY"
    event(
        db,
        assessment.id,
        "TARGET_VALIDATED",
        "Target syntax, scope and authorization validated without network traffic",
    )
    return assessment


async def collect(db, assessment, checks=None, transport=None, resolver=None):
    if db.info.get("deployment") and not db.info["deployment"].network_enabled:
        raise ValueError(
            "Hosted workspaces are import-only. Collect authorized target data with the local workstation, then upload it."
        )
    scope = scope_for(db, assessment)
    if (
        assessment.status not in ("READY", "COMPLETED", "FAILED")
        or not target_for(db, assessment.id).validated_at
    ):
        raise ValueError("Validate the target before collection; archived or running assessments cannot run")
    scope.network_allowed(scope.target)
    if checks is not None and (not checks.confirm or not scope.config.safe_paths):
        raise ValueError("Safe checks require explicit confirmation and at least one configured safe path")
    changed = db.execute(
        update(m.Assessment)
        .where(m.Assessment.id == assessment.id, m.Assessment.status != "RUNNING")
        .values(status="RUNNING")
    )
    if changed.rowcount != 1:
        raise ValueError("This assessment already has an active execution")
    event(
        db,
        assessment.id,
        "EXECUTION_STARTED",
        "Explicit safe checks started" if checks else "Controlled discovery started",
    )
    db.commit()
    run = NetworkRun(db, assessment.id, scope, transport=transport, resolver=resolver)
    initial_evidence_ids = {e.id for e in rows(db, m.Evidence, assessment.id)}
    completed = False
    try:
        if checks is None:
            if scope.config.dns:
                await collect_dns(run)
            if scope.config.tls:
                await collect_tls(run)
            queue = [(scope.target, 0, "GET")]
            parts = urlsplit(scope.target)
            origin = f"{parts.scheme}://{parts.netloc}"
            if scope.config.robots:
                queue.append((origin + "/robots.txt", 0, "GET"))
            if scope.config.sitemap:
                queue.append((origin + "/sitemap.xml", 0, "GET"))
            if scope.config.methods:
                queue.append((scope.target, 0, "OPTIONS"))
            if scope.config.availability:
                host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
                queue.extend([(f"http://{host}/", 0, "HEAD"), (f"https://{host}/", 0, "HEAD")])
        else:
            parts = urlsplit(scope.target)
            queue = [(f"{parts.scheme}://{parts.netloc}{path}", 0, "GET") for path in scope.config.safe_paths]
            event(
                db,
                assessment.id,
                "SECURITY_CHECK_EXECUTED",
                "Only explicit configured paths will be requested",
                {"safe_paths": scope.config.safe_paths, "cors_probe": bool(checks.cors_origin)},
            )
        seen = set()
        while queue and not run.exhausted:
            url, depth, method = queue.pop(0)
            if (url, method) in seen:
                continue
            seen.add((url, method))
            tx = await run.request(
                url,
                method=method,
                headers={"Origin": checks.cors_origin} if checks and checks.cors_origin else None,
            )
            if not tx:
                continue
            discovered = harvest(db, assessment.id, scope, tx)
            fingerprint(db, assessment.id, tx)
            if checks is None and scope.config.links and depth < scope.config.max_depth:
                for item in discovered:
                    # Never follow form actions, robots disallows, JS APIs or imported endpoints.
                    if (
                        item.in_scope
                        and item.method == "GET"
                        and item.source == "HTML"
                        and item.details.get("kind") in ("page", "script")
                    ):
                        if item.details.get("kind") != "script" or scope.config.javascript:
                            queue.append((item.url, depth + 1, "GET"))
        if queue:
            code = "BUDGET_EXHAUSTED" if run.count >= scope.config.max_requests else "RUN_TIMEOUT"
            run.log(code, scope.target, "Discovery stopped at the shared execution request or duration limit")
        for host in {urlsplit(scope.target).hostname, *run.addresses}:
            host_row = db.scalar(
                select(m.Host).where(m.Host.assessment_id == assessment.id, m.Host.hostname == host)
            )
            if not host_row:
                ev = evidence(
                    db,
                    assessment.id,
                    "ENDPOINT",
                    scope.target,
                    "Scoped discovered host",
                    {"hostname": host, "addresses": run.addresses.get(host, [])},
                )
                db.add(
                    m.Host(
                        assessment_id=assessment.id,
                        evidence_id=ev.id,
                        hostname=host,
                        addresses=run.addresses.get(host, []),
                    )
                )
            else:
                host_row.addresses = sorted(set(host_row.addresses + run.addresses.get(host, [])))
        analyze(db, assessment)
        new_events = [e for e in rows(db, m.Evidence, assessment.id) if e.id not in initial_evidence_ids]
        collected = any(e.type in ("HTTP_RESPONSE", "DNS_RESPONSE", "TLS_CERTIFICATE") for e in new_events)
        assessment.status = "COMPLETED" if collected else "FAILED"
        event(
            db,
            assessment.id,
            "EXECUTION_COMPLETED" if collected else "EXECUTION_FAILED",
            "Collection finished; inspect recorded errors and limit events for coverage gaps",
            {
                "network_operations": run.count,
                "remaining_queue": len(queue),
                "successful_collection": collected,
            },
        )
        db.commit()
        completed = True
        return assessment
    finally:
        if not completed:
            db.rollback()
            assessment = db.get(m.Assessment, assessment.id)
            assessment.status = "FAILED"
            event(
                db,
                assessment.id,
                "EXECUTION_FAILED",
                "Execution interrupted by an unexpected error; no success claimed",
            )
            db.commit()
