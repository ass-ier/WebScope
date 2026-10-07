import hashlib
import json

from sqlalchemy import select

from app import models as m
from app.services.redaction import clean, text


def evidence(db, assessment_id, kind, source, summary, data, raw=""):
    safe_data, safe_raw = clean(data), text(raw)
    canonical = json.dumps({"data": safe_data, "raw": safe_raw}, sort_keys=True, ensure_ascii=True)
    item = m.Evidence(
        assessment_id=assessment_id,
        type=kind,
        source=text(source),
        summary=text(summary),
        data=safe_data,
        raw=safe_raw,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )
    db.add(item)
    db.flush()
    parent_id = safe_data.get("source_evidence_id")
    if parent_id:
        db.add(m.EvidenceLink(parent_id=parent_id, child_id=item.id, assessment_id=assessment_id))
        db.flush()
    return item


def event(db, assessment_id, kind, message, data=None):
    item = m.TimelineEvent(
        assessment_id=assessment_id, event=kind, message=text(message), data=clean(data or {})
    )
    db.add(item)
    db.flush()
    return item


def rows(db, model, assessment_id):
    return list(db.scalars(select(model).where(model.assessment_id == assessment_id)))


def record(item):
    return clean(
        {
            column.name: getattr(item, column.name)
            for column in item.__table__.columns
            if column.name != "content"
        }
        | ({"content": item.content} if isinstance(item, m.AnalystNote) else {})
    )


def add_note(db, assessment_id, payload, finding_id=None, case_id=None):
    data = clean(payload.model_dump())
    source = (
        f"finding:{finding_id}"
        if finding_id
        else f"case:{case_id}"
        if case_id
        else f"assessment:{assessment_id}"
    )
    ev = evidence(db, assessment_id, "ANALYST_NOTE", source, "Analyst note", data, data["content"])
    note = m.AnalystNote(
        assessment_id=assessment_id, finding_id=finding_id, case_id=case_id, evidence_id=ev.id, **data
    )
    db.add(note)
    db.flush()
    event(
        db,
        assessment_id,
        "ANALYST_NOTE_ADDED",
        "Analyst added a note",
        {"note_id": note.id, "case_id": case_id},
    )
    return note
