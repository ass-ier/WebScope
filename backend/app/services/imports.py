import base64
import binascii
import hashlib
import io
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from PIL import Image, UnidentifiedImageError
from pydantic import ValidationError, create_model
from sqlalchemy import JSON, select

from app import models as m
from app.schemas import AssessmentCreate, Configuration, DataImport, ScopeInput
from app.services import assessments, redaction
from app.services.analysis import analyze, seed_rules
from app.services.discovery import harvest, import_openapi
from app.services.store import event, evidence
from app.services.technology import fingerprint
from app.services.scope import canonical_url

DATASETS = {
    "hosts": m.Host,
    "dns": m.DNSRecord,
    "tls": m.TLSCertificate,
    "endpoints": m.Endpoint,
    "technologies": m.Technology,
    "transactions": m.HTTPTransaction,
    "cookies": m.Cookie,
    "security_headers": m.SecurityHeaderObservation,
    "findings": m.Finding,
    "cases": m.Case,
    "notes": m.AnalystNote,
    "timeline": m.TimelineEvent,
    "finding_evidence": m.FindingEvidence,
    "case_findings": m.CaseFinding,
    "case_evidence": m.CaseEvidence,
}
REFERENCE_FIELDS = {
    "evidence_id": "evidence",
    "request_evidence_id": "evidence",
    "endpoint_id": "endpoints",
    "finding_id": "findings",
    "case_id": "cases",
}
ENUMS = {
    "severity": {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
    "confidence": {"LOW", "MEDIUM", "HIGH"},
    "method": {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},
}


def bounded_document(document):
    nodes = 0

    def walk(value, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 40000 or depth > 40:
            raise ValueError("Upload exceeds the 40-level or 40,000-value complexity limit")
        if isinstance(value, dict):
            for key, item in value.items():
                if len(key) > 4096:
                    raise ValueError("Upload contains an oversized field name")
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(document)
    encoded = json.dumps(document, ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > 2_000_000:
        raise ValueError("Upload exceeds 2 MB. Export a smaller capture or assessment.")
    return hashlib.sha256(encoded).hexdigest()


def rows(document, name, maximum=2500):
    values = document.get(name, [])
    if not isinstance(values, list) or len(values) > maximum or not all(isinstance(v, dict) for v in values):
        raise ValueError(f"{name} must be an array of at most {maximum} objects")
    return values


def safe_png(data):
    value = data.get("image_base64")
    if not isinstance(value, str) or len(value) > 1_500_000 or data.get("media_type") != "image/png":
        raise ValueError("Screenshot evidence must contain a bounded PNG image")
    try:
        content = base64.b64decode(value, validate=True)
        with Image.open(io.BytesIO(content)) as image:
            if image.format != "PNG" or image.width * image.height > 2_000_000:
                raise ValueError("Screenshot PNG exceeds supported dimensions")
            image.load()
            safe = io.BytesIO()
            image.convert("RGB").save(safe, format="PNG")
            return {
                **data,
                "image_base64": base64.b64encode(safe.getvalue()).decode(),
                "width": image.width,
                "height": image.height,
            }
    except (binascii.Error, UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Invalid screenshot PNG") from exc


def model_fields(model, row):
    fields = {}
    for column in model.__table__.columns:
        if column.name in ("id", "assessment_id"):
            continue
        value_type = column.type.python_type
        if isinstance(column.type, JSON):
            value_type = (
                list
                if column.name in ("addresses", "records", "parameters", "references", "required_evidence")
                else dict
            )
        if column.nullable:
            value_type = value_type | None
        fields[column.name] = (value_type, None if column.nullable else ...)
    schema = create_model(
        f"Imported{model.__name__}", __config__={"extra": "forbid", "strict": True}, **fields
    )
    candidate = {key: value for key, value in row.items() if key not in ("id", "assessment_id")}
    try:
        result = schema.model_validate(candidate).model_dump()
    except ValidationError as exc:
        raise ValueError(
            f"Invalid {model.__name__} record; required fields or field types do not match a WebScope export"
        ) from exc
    for key, value in result.items():
        if isinstance(value, str) and len(value) > 100_000:
            raise ValueError(f"{model.__name__} contains an oversized text field")
        if key in ENUMS and value not in ENUMS[key]:
            raise ValueError(f"Invalid {model.__name__} {key}")
        if key in ("references", "addresses", "records", "required_evidence") and not all(
            isinstance(v, str) for v in value
        ):
            raise ValueError(f"{model.__name__} {key} must contain strings")
    if "created_at" in result:
        try:
            datetime.fromisoformat(result["created_at"])
        except ValueError as exc:
            raise ValueError("Invalid imported timestamp") from exc
    return redaction.clean(result)


def remap_json(value, mapping):
    if isinstance(value, dict):
        return {key: remap_json(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [remap_json(item, mapping) for item in value]
    if isinstance(value, str):
        if value in mapping:
            return mapping[value]
        for prefix in ("finding:", "case:", "assessment:", "webscope:evidence:"):
            if value.startswith(prefix) and value[len(prefix) :] in mapping:
                return prefix + mapping[value[len(prefix) :]]
    return value


def validate_observation(name, values):
    if name == "transactions":
        request, response = values["request"], values["response"]
        for data in (request, response):
            headers = data.get("headers", {})
            if not isinstance(headers, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
            ):
                raise ValueError("Imported HTTP headers must contain string values")
        if (
            "headers" not in request
            or not isinstance(response.get("body", ""), str)
            or not isinstance(response.get("content_type", ""), str)
        ):
            raise ValueError("Imported HTTP request/response shape is invalid")
    if name == "tls":
        details = values["details"]
        for key in (
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "signature_hash",
            "public_key_type",
            "tls_version",
            "chain_collection",
        ):
            if not isinstance(details.get(key), str):
                raise ValueError(f"TLS observation requires {key}")
        for key in ("expired", "hostname_matches", "verified"):
            if not isinstance(details.get(key), bool):
                raise ValueError(f"TLS observation requires boolean {key}")
        if not isinstance(details.get("chain"), list) or not isinstance(details.get("sans"), list):
            raise ValueError("TLS observation requires chain and SAN arrays")
        if details.get("public_key_bits") is not None and not isinstance(details["public_key_bits"], int):
            raise ValueError("TLS public key size must be an integer")
        details.setdefault("verification_error", None)
    if name == "endpoints":
        canonical_url(values["url"])
        if not all(isinstance(p, dict) for p in values["parameters"]):
            raise ValueError("Endpoint parameters must be objects")
    if name == "findings":
        for key in ("analyst_severity", "priority_override"):
            if values[key] is not None and values[key] not in ENUMS["severity"]:
                raise ValueError(f"Invalid finding {key}")
        if (
            values["analyst_confidence"] is not None
            and values["analyst_confidence"] not in ENUMS["confidence"]
        ):
            raise ValueError("Invalid analyst confidence")


def import_snapshot(db, payload, digest, synthetic=False):
    document = payload.document
    if document.get("schema_version") != "1.0" or not isinstance(document.get("assessment"), dict):
        raise ValueError("Upload a complete WebScope JSON assessment export (schema_version 1.0)")
    original = document["assessment"]
    if not isinstance(original.get("id"), str):
        raise ValueError("Snapshot is missing its assessment ID")
    try:
        policy = Configuration(**original.get("config", {}))
        scope = ScopeInput(**original["scope"])
        target = original["target"]
    except (KeyError, TypeError, ValidationError) as exc:
        raise ValueError("Snapshot target, scope or configuration is invalid") from exc
    policy.mode = "PASSIVE"
    policy.allow_private_network = False
    item = assessments.create(
        db,
        AssessmentCreate(
            name=payload.name,
            description="Synthetic example data."
            if synthetic
            else "Uploaded WebScope snapshot. Imported facts and analyst statements are unverified declarations.",
            target=target,
            scope=scope,
            config=policy,
            authorized=False,
        ),
    )
    item.data_origin = "SYNTHETIC" if synthetic else "UPLOADED"
    source_rows = {"evidence": rows(document, "evidence")}
    source_rows.update({name: rows(document, name) for name in DATASETS})
    if sum(len(values) for values in source_rows.values()) > 5000:
        raise ValueError("Snapshot is limited to 5,000 records")
    mapping = {original["id"]: item.id}
    dataset_ids = {}
    for name, values in source_rows.items():
        ids = set()
        for row in values:
            if row.get("assessment_id") != original["id"]:
                raise ValueError("Snapshot contains a cross-assessment record")
            if "id" not in row and name in ("finding_evidence", "case_findings", "case_evidence"):
                continue
            old = row.get("id")
            if not isinstance(old, str) or not old or len(old) > 100 or old in mapping:
                raise ValueError("Snapshot contains a missing or duplicate record ID")
            ids.add(old)
            mapping[old] = m.uid()
        dataset_ids[name] = ids

    pending_links = []
    for row in source_rows["evidence"]:
        values = model_fields(m.Evidence, row)
        data = remap_json(values["data"], mapping)
        original_parent = values["data"].get("source_evidence_id")
        if original_parent:
            if original_parent not in dataset_ids["evidence"]:
                raise ValueError("Snapshot evidence source does not exist in this upload")
            pending_links.append((mapping[original_parent], mapping[row["id"]]))
        if values["type"] == "SCREENSHOT":
            data = safe_png(data)
        data["import_provenance"] = {
            "declared_id": row["id"],
            "declared_collector": values["collector"],
            "declared_sha256": values["sha256"],
            "upload_sha256": digest,
            "trust": "SYNTHETIC_FIXTURE" if synthetic else "UNVERIFIED_UPLOAD",
        }
        safe = redaction.clean(data)
        canonical = json.dumps({"data": safe, "raw": values["raw"]}, sort_keys=True, ensure_ascii=True)
        db.add(
            m.Evidence(
                **{
                    **values,
                    "id": mapping[row["id"]],
                    "assessment_id": item.id,
                    "data": safe,
                    "source": remap_json(values["source"], mapping),
                    "collector": "webscope/synthetic-import" if synthetic else "webscope/unverified-import",
                    "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                }
            )
        )
    db.flush()
    for parent, child in set(pending_links):
        db.add(m.EvidenceLink(parent_id=parent, child_id=child, assessment_id=item.id))
    for link in rows(document, "evidence_links"):
        if link.get("assessment_id") != original["id"]:
            raise ValueError("Cross-assessment evidence lineage is prohibited")
        parent, child = link.get("parent_id"), link.get("child_id")
        if parent not in dataset_ids["evidence"] or child not in dataset_ids["evidence"] or parent == child:
            raise ValueError("Invalid evidence lineage")
        if (mapping[parent], mapping[child]) not in pending_links:
            db.add(
                m.EvidenceLink(
                    parent_id=mapping[parent],
                    child_id=mapping[child],
                    assessment_id=item.id,
                    relation=redaction.text(str(link.get("relation", "derived_from")))[:100],
                )
            )
            pending_links.append((mapping[parent], mapping[child]))
    db.flush()

    imported_rules = {}
    for rule in rows(document, "rules", 200):
        old_id = rule.get("id")
        if not isinstance(old_id, str) or old_id in imported_rules:
            raise ValueError("Invalid or duplicate imported detection rule")
        values = model_fields(m.DetectionRule, rule)
        rid = f"IMPORT-{item.id}-{old_id[:60]}"
        imported_rules[old_id] = rid
        db.add(
            m.DetectionRule(
                id=rid,
                **{
                    **values,
                    "description": "Unverified imported rule declaration. " + values["description"],
                    "request_type": "NONE (uploaded data)",
                    "safety_level": "IMPORTED",
                },
            )
        )
    db.flush()

    order = (
        "hosts",
        "dns",
        "tls",
        "endpoints",
        "technologies",
        "transactions",
        "cookies",
        "security_headers",
        "findings",
        "cases",
        "notes",
        "timeline",
        "finding_evidence",
        "case_findings",
        "case_evidence",
    )
    for name in order:
        model = DATASETS[name]
        for row in source_rows[name]:
            values = model_fields(model, row)
            validate_observation(name, values)
            for key, table in REFERENCE_FIELDS.items():
                old = values.get(key)
                if old is not None:
                    if old not in dataset_ids[table]:
                        raise ValueError(f"Invalid {name} relationship: referenced {table} record is absent")
                    values[key] = mapping[old]
            if name == "findings":
                if values["rule_id"] not in imported_rules:
                    raise ValueError("Finding is missing its imported rule declaration")
                values["rule_id"] = imported_rules[values["rule_id"]]
                values["automated"] = {
                    **remap_json(values["automated"], mapping),
                    "import_trust": "SYNTHETIC_FIXTURE" if synthetic else "UNVERIFIED_UPLOAD",
                }
            for key in ("details", "request", "response", "data"):
                if key in values:
                    values[key] = remap_json(values[key], mapping)
            kwargs = {"assessment_id": item.id, **values}
            if "id" in row:
                kwargs["id"] = mapping[row["id"]]
            db.add(model(**kwargs))
        db.flush()
    item.status = "COMPLETED"
    event(
        db,
        item.id,
        "SYNTHETIC_DATA_LOADED" if synthetic else "DATA_IMPORTED",
        "Synthetic fixture loaded without requests."
        if synthetic
        else "WebScope snapshot imported without requests. Imported claims are not re-verified findings.",
        {
            "format": "webscope",
            "sha256": digest,
            "temporary": True,
            "reports": "Prior report metadata is preserved in the source upload; generate fresh reports from this workspace.",
        },
    )
    return item


def pairs(value, label):
    if not isinstance(value, list) or len(value) > 300:
        raise ValueError(f"HAR {label} must be an array of at most 300 name/value pairs")
    result = []
    for pair in value:
        if (
            not isinstance(pair, dict)
            or not isinstance(pair.get("name"), str)
            or not isinstance(pair.get("value"), str)
        ):
            raise ValueError(f"Invalid HAR {label}")
        result.append((pair["name"], pair["value"]))
    return result


def import_har(db, payload, digest):
    document = payload.document
    log = document.get("log")
    if not isinstance(log, dict) or not str(log.get("version", "")).startswith("1."):
        raise ValueError("Upload a HAR 1.x document containing log.entries")
    entries = rows(log, "entries", 200)
    if not entries:
        raise ValueError("HAR must contain at least one HTTP transaction")
    target = payload.target
    if not target:
        request = entries[0].get("request")
        target = request.get("url") if isinstance(request, dict) else None
    if not isinstance(target, str):
        raise ValueError("HAR requires a valid target URL")
    target = redaction.url(target)
    host = urlsplit(target).hostname
    item = assessments.create(
        db,
        AssessmentCreate(
            name=payload.name,
            target=target,
            description="Uploaded HAR capture; collection claims are unverified. No requests were sent.",
            scope=ScopeInput(allowed_hosts=[host] if host else []),
            config=Configuration(),
            authorized=False,
        ),
    )
    item.data_origin = "UPLOADED"
    scope = assessments.scope_for(db, item)
    for entry in entries:
        req, res = entry.get("request"), entry.get("response")
        if not isinstance(req, dict) or not isinstance(res, dict) or not isinstance(req.get("url"), str):
            raise ValueError("Every HAR entry requires request and response objects")
        method = req.get("method", "GET")
        if method not in ENUMS["method"]:
            raise ValueError("Unsupported HAR HTTP method")
        status = res.get("status")
        duration = entry.get("time", 0)
        if (
            not isinstance(status, int)
            or not 100 <= status <= 599
            or not isinstance(duration, (int, float))
            or duration < 0
        ):
            raise ValueError("Invalid HAR status or timing")
        url = redaction.url(canonical_url(req["url"]))
        request_headers = redaction.headers(pairs(req.get("headers", []), "request headers"))
        response_headers = redaction.headers(pairs(res.get("headers", []), "response headers"))
        content = res.get("content", {})
        if not isinstance(content, dict) or not isinstance(content.get("text", ""), str):
            raise ValueError("Invalid HAR response content")
        content_type = content.get("mimeType") or response_headers.get("content-type", "")
        if not isinstance(content_type, str):
            raise ValueError("Invalid HAR content type")
        body = content.get("text", "")
        if content.get("encoding") == "base64":
            try:
                body = base64.b64decode(body, validate=True).decode("utf-8", errors="replace")
            except binascii.Error as exc:
                raise ValueError("Invalid HAR base64 body") from exc
        elif content.get("encoding") not in (None, ""):
            raise ValueError("Unsupported HAR body encoding")
        encoded = body.encode()
        truncated = len(encoded) > 262144
        textual = any(kind in content_type for kind in ("text", "json", "xml", "javascript", "form"))
        body = (
            redaction.body(encoded[:262144].decode("utf-8", errors="replace"), content_type)
            if textual
            else "[Binary body omitted]"
        )
        request_data = {
            "method": method,
            "url": url,
            "headers": request_headers,
            "query": redaction.clean(dict(pairs(req.get("queryString", []), "query parameters"))),
            "body_metadata": {"uploaded": True, "body_omitted": True},
            "timestamp": str(entry.get("startedDateTime", ""))[:100],
            "source": "UNVERIFIED_HAR",
        }
        req_ev = evidence(
            db,
            item.id,
            "HTTP_REQUEST",
            url,
            "Uploaded HAR request (not executed)",
            request_data,
            f"{method} {url}\n" + "\n".join(f"{k}: {v}" for k, v in request_headers.items()),
        )
        response_data = {
            "status_code": status,
            "headers": response_headers,
            "content_type": content_type,
            "content_length": min(len(encoded), 262144),
            "body_hash": hashlib.sha256(encoded[:262144]).hexdigest(),
            "body": body,
            "elapsed_ms": duration,
            "redirect": None,
            "truncated": truncated,
            "import_provenance": {"source": "UNVERIFIED_HAR", "upload_sha256": digest},
        }
        res_ev = evidence(
            db,
            item.id,
            "HTTP_RESPONSE",
            url,
            f"Uploaded HAR HTTP {status} response",
            response_data,
            f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in response_headers.items()) + "\n\n" + body,
        )
        tx = m.HTTPTransaction(
            assessment_id=item.id,
            evidence_id=res_ev.id,
            request_evidence_id=req_ev.id,
            method=method,
            url=url,
            status_code=status,
            elapsed_ms=duration,
            request=req_ev.data,
            response=res_ev.data,
        )
        db.add(tx)
        db.flush()
        harvest(db, item.id, scope, tx)
        fingerprint(db, item.id, tx)
    seed_rules(db)
    analyze(db, item)
    item.status = "COMPLETED"
    event(
        db,
        item.id,
        "DATA_IMPORTED",
        "HAR analyzed from uploaded evidence without target requests.",
        {"format": "har", "entries": len(entries), "sha256": digest, "temporary": True},
    )
    return item


def import_document(db, payload):
    if not payload.consent:
        raise ValueError(
            "Confirm that you are allowed to upload this data and understand its temporary retention"
        )
    digest = bounded_document(payload.document)
    if payload.format == "webscope":
        return import_snapshot(db, payload, digest)
    if payload.format == "har":
        return import_har(db, payload, digest)
    if not payload.target:
        raise ValueError("An OpenAPI import requires an explicit target URL")
    host = urlsplit(payload.target).hostname
    item = assessments.create(
        db,
        AssessmentCreate(
            name=payload.name,
            target=payload.target,
            scope=ScopeInput(allowed_hosts=[host] if host else []),
            config=Configuration(),
            authorized=False,
        ),
    )
    item.data_origin = "UPLOADED"
    import_openapi(db, item.id, assessments.scope_for(db, item), payload.document)
    item.status = "COMPLETED"
    event(
        db,
        item.id,
        "DATA_IMPORTED",
        "OpenAPI inventory imported; no endpoints executed",
        {"sha256": digest, "format": "openapi", "temporary": True},
    )
    return item


def load_examples(db):
    existing = list(
        db.scalars(
            select(m.Assessment).where(
                m.Assessment.owner_id == db.info.get("owner_id"), m.Assessment.data_origin == "SYNTHETIC"
            )
        )
    )
    if existing:
        return existing
    source = Path(__file__).resolve().parents[3] / "docs" / "example" / "assessment.json"
    document = json.loads(source.read_text())
    payload = DataImport(
        format="webscope", document=document, name="Synthetic web application investigation", consent=True
    )
    sample = import_snapshot(db, payload, bounded_document(document), synthetic=True)
    from app.services.synthetic import infrastructure_example

    return [sample, infrastructure_example(db)]
