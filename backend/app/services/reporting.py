import csv
import hashlib
import html
import io
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from sqlalchemy import select

from app import models as m
from app.services.analysis import risk
from app.services.assessments import overview
from app.services.graph import graph
from app.services.store import event, record, rows

DATASETS = {
    "hosts": m.Host,
    "dns": m.DNSRecord,
    "tls": m.TLSCertificate,
    "endpoints": m.Endpoint,
    "technologies": m.Technology,
    "transactions": m.HTTPTransaction,
    "cookies": m.Cookie,
    "security_headers": m.SecurityHeaderObservation,
    "evidence": m.Evidence,
    "findings": m.Finding,
    "notes": m.AnalystNote,
    "timeline": m.TimelineEvent,
    "cases": m.Case,
    "reports": m.Report,
}


def snapshot(db, assessment):
    data = {"schema_version": "1.0", "generated_at": m.now(), "assessment": overview(db, assessment)}
    data.update(
        {name: [record(r) for r in rows(db, model, assessment.id)] for name, model in DATASETS.items()}
    )
    data["finding_evidence"] = [record(r) for r in rows(db, m.FindingEvidence, assessment.id)]
    data["case_findings"] = [record(r) for r in rows(db, m.CaseFinding, assessment.id)]
    data["case_evidence"] = [record(r) for r in rows(db, m.CaseEvidence, assessment.id)]
    data["evidence_links"] = [record(r) for r in rows(db, m.EvidenceLink, assessment.id)]
    data["rules"] = [record(r) for r in db.scalars(select(m.DetectionRule))]
    data["risk"] = {item.id: risk(assessment, item) for item in rows(db, m.Finding, assessment.id)}
    data["graph"] = graph(db, assessment.id)
    return data


def escape(value):
    return (
        html.escape(str(value), quote=True)
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("[", "\\[")
        .replace("]", "\\]")
    )


def sections(data):
    a = data["assessment"]
    result = [
        (
            "Executive Summary",
            [
                f"Assessment: {a['name']}",
                f"Target: {a['target']}",
                f"Status: {a['status']}",
                f"{len(data['findings'])} automated observations; "
                + f"{sum(f['status'] == 'CONFIRMED' for f in data['findings'])} analyst-confirmed findings.",
                "Severity distribution (excluding dismissed/false-positive): "
                + ", ".join(
                    f"{name}: {a['severity_counts'][name]}"
                    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                ),
                "This report distinguishes observed facts from analyst conclusions. It does not claim comprehensive vulnerability coverage.",
            ],
        ),
        (
            "Scope",
            [
                f"Authorization: {a['authorization_note']}",
                json.dumps(a["scope"], indent=2),
                f"Authorized at: {a.get('authorized_at')}",
                json.dumps(a["config"], indent=2),
            ],
        ),
        (
            "Methodology",
            [
                "Explicit, scoped, rate-limited read-only collection; deterministic passive analysis of persisted evidence.",
                "GET/HEAD/OPTIONS only. No credential attacks, authentication bypass, exploitation, or target data modification.",
                "A single execution budget covers collection operations and redirects. Errors and limits are recorded in the timeline.",
                "All stored evidence and exports are redacted. Body hashes describe collected bytes, possibly truncated.",
                "TLS results describe only observed certificates and negotiated protocols, not exhaustive protocol support.",
            ],
        ),
        (
            "Attack Surface",
            [
                *[
                    f"Host: {h['hostname']}; addresses: {', '.join(h['addresses']) or 'not resolved'}; evidence {h['evidence_id']}"
                    for h in data["hosts"]
                ],
                *[
                    f"{e['method']} {e['url']}\nSource: {e['source']}; in scope: {e['in_scope']}; "
                    f"authentication: {e['authentication']}; content type: {e['content_type'] or 'not collected'}\n"
                    f"Parameters: {json.dumps(e['parameters'])}; evidence: {e['evidence_id']}"
                    for e in data["endpoints"]
                ],
                *[
                    f"DNS {d['record_type']} {d['hostname']}: {', '.join(d['records']) or 'no records'}; "
                    f"TTL {d['ttl']}; resolver {d['resolver']}; evidence {d['evidence_id']}"
                    for d in data["dns"]
                ],
                *[
                    f"TLS {t['hostname']}: {t['details']['tls_version']}; verified: {t['details']['verified']}; "
                    f"expires {t['details']['not_after']}; issuer {t['details']['issuer']}; "
                    f"chain {t['details']['chain_collection']}; evidence {t['evidence_id']}"
                    for t in data["tls"]
                ],
            ]
            or ["No attack-surface observations collected."],
        ),
        (
            "Technology Inventory",
            [
                f"{t['name']} / {t['category']} / version {t['version'] or 'not established'} / confidence {t['confidence']}\n"
                f"Basis: {t['rationale']}\nEvidence: {t['evidence_id']}"
                for t in data["technologies"]
            ]
            or ["No technology indicators collected."],
        ),
        (
            "Security Controls",
            [
                *[
                    f"{h['name']}: {'present' if h['present'] else 'absent'}; {h['rationale']} Evidence: {h['evidence_id']}"
                    for h in data["security_headers"]
                ],
                *[
                    f"Cookie {c['name']} attributes (values redacted): {json.dumps(c['attributes'])}; evidence {c['evidence_id']}"
                    for c in data["cookies"]
                ],
            ]
            or ["No security controls collected."],
        ),
    ]
    findings = []
    for f in data["findings"]:
        findings.extend(
            [
                f"{f['rule_id']} / {f['title']}",
                f"Automated severity: {f['severity']}; confidence: {f['confidence']}; analyst status: {f['status']}",
                f"Why WebScope flagged this: {f['rationale']}",
                f"Evidence: {f['evidence_id']}; endpoint: {f['endpoint_id']}; rule version: {f['rule_version']}",
                f"Affected asset: {f['affected_asset']}",
                f"Description: {f['description']}",
                f"Impact: {f['impact']}",
                f"Remediation: {f['remediation']}",
                f"References: {', '.join(f['references'])}",
            ]
        )
    result += [
        (
            "Automated Findings",
            findings or ["No findings generated. This is not a statement that the target is secure."],
        ),
        (
            "Evidence",
            [
                "Evidence excerpts below are capped at 800 characters per item. The complete redacted structured/raw "
                "record and relationships are available in the companion assessment JSON and workstation.",
                *[
                    f"{e['id']} / {e['type']} / {e['created_at']}\nSource: {e['source']}\n{e['summary']}\n"
                    f"Integrity SHA-256: {e['sha256']}\nExcerpt: {(e['raw'] or json.dumps(e['data']))[:800]}"
                    for e in data["evidence"]
                ],
            ],
        ),
        (
            "Risk Assessment",
            [
                *[
                    f"{fid}: priority {r['priority']} (computed {r['automated_priority']}, score {r['score']})\n"
                    f"Factors: {json.dumps(r['factors'])}\nOverride explanation: {r['override_reason'] or 'none'}"
                    for fid, r in data["risk"].items()
                ],
                next(iter(data["risk"].values()))["explanation"]
                if data["risk"]
                else "No finding risk factors to assess.",
            ],
        ),
        (
            "Remediation Recommendations",
            [f"{f['rule_id']}: {f['remediation']}" for f in data["findings"]] or ["No rule recommendations."],
        ),
        (
            "Analyst Conclusions",
            [
                json.dumps(
                    [
                        {
                            "finding_id": f["id"],
                            "status": f["status"],
                            "conclusion": f["analyst_assessment"],
                            "severity": f["analyst_severity"],
                            "confidence": f["analyst_confidence"],
                            "priority_override": f["priority_override"],
                            "override_reason": f["override_reason"],
                        }
                        for f in data["findings"]
                    ],
                    indent=2,
                ),
                json.dumps(data["notes"], indent=2),
            ],
        ),
        (
            "Assessment Timeline",
            [
                f"{e['created_at']} {e['event']}: {e['message']} {json.dumps(e['data'])}"
                for e in data["timeline"]
            ],
        ),
        (
            "Appendix",
            [
                f"Snapshot schema {data['schema_version']}; generated {data['generated_at']}",
                "Evidence integrity hashes cover redacted canonical data/raw content. Original target bodies are not retained.",
                json.dumps(
                    {
                        "cases": data["cases"],
                        "case_findings": data["case_findings"],
                        "case_evidence": data["case_evidence"],
                        "finding_evidence": data["finding_evidence"],
                        "rules": [
                            {
                                "id": r["id"],
                                "version": r["version"],
                                "name": r["name"],
                                "safety_level": r["safety_level"],
                            }
                            for r in data["rules"]
                        ],
                    },
                    indent=2,
                ),
            ],
        ),
    ]
    return result


def markdown(data):
    lines = [
        "# WebScope Security Assessment",
        "",
        "Evidence-Driven Web Application Security Assessment Workstation",
        "",
    ]
    for title, paragraphs in sections(data):
        lines += ["## " + title, ""]
        for paragraph in paragraphs:
            lines += [escape(paragraph).replace("\n", "  \n"), ""]
    return "\n".join(lines).encode()


def csv_bytes(data, dataset):
    records = data[dataset]
    columns = {
        "endpoints": [
            "id",
            "url",
            "method",
            "parameters",
            "content_type",
            "authentication",
            "source",
            "evidence_id",
            "in_scope",
        ],
        "findings": [
            "id",
            "title",
            "category",
            "severity",
            "confidence",
            "status",
            "rationale",
            "remediation",
            "evidence_id",
            "rule_id",
            "rule_version",
            "analyst_assessment",
            "analyst_severity",
            "priority_override",
            "override_reason",
        ],
        "technologies": ["id", "name", "category", "version", "confidence", "rationale", "evidence_id"],
        "evidence": ["id", "type", "source", "summary", "sha256", "collector", "created_at"],
    }[dataset]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for row in records:
        safe = {}
        for key in columns:
            value = row.get(key)
            value = (
                json.dumps(value, ensure_ascii=True)
                if isinstance(value, (dict, list))
                else str(value if value is not None else "")
            )
            if value.lstrip(" \t\r\n\v\f\ufeff").startswith(("=", "+", "-", "@")) or value.startswith(
                ("\t", "\r", "\n")
            ):
                value = "'" + value
            safe[key] = value
        writer.writerow(safe)
    return output.getvalue().encode("utf-8-sig")


def pdf(data):
    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=(8.27 * inch, 11.69 * inch),
        rightMargin=42,
        leftMargin=42,
        topMargin=46,
        bottomMargin=44,
        title="WebScope Security Assessment",
        author="WebScope",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="EvidenceText",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            alignment=TA_LEFT,
            spaceAfter=6,
            wordWrap="CJK",
            textColor=colors.HexColor("#253246"),
        )
    )
    story = [
        Paragraph("WebScope", styles["Title"]),
        Paragraph("Evidence-driven security assessment", styles["Heading2"]),
        Paragraph(html.escape(data["assessment"]["name"]), styles["Normal"]),
        Spacer(1, 18),
    ]
    for title, paragraphs in sections(data):
        story.append(Paragraph(title, styles["Heading1"]))
        for paragraph in paragraphs:
            # Bounded paragraphs avoid a single oversized untrusted JSON block exhausting layout.
            for line in paragraph.splitlines() or [""]:
                for offset in range(0, max(1, len(line)), 2400):
                    story.append(
                        Paragraph(html.escape(line[offset : offset + 2400]) or " ", styles["EvidenceText"])
                    )
        story.append(Spacer(1, 10))

    def footer(canvas, document):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#536174"))
        canvas.drawString(42, 25, "WebScope | Authorized assessment | Redacted evidence")
        canvas.drawRightString(8.27 * inch - 42, 25, str(document.page))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def generate(db, assessment, payload):
    if payload.format == "csv" and payload.dataset == "assessment":
        raise ValueError("CSV requires endpoints, findings, technologies, or evidence dataset")
    data = snapshot(db, assessment)
    formats = {
        "json": ("application/json", "json", lambda: json.dumps(data, indent=2, ensure_ascii=True).encode()),
        "markdown": ("text/markdown; charset=utf-8", "md", lambda: markdown(data)),
        "csv": ("text/csv; charset=utf-8", "csv", lambda: csv_bytes(data, payload.dataset)),
        "pdf": ("application/pdf", "pdf", lambda: pdf(data)),
    }
    mime, extension, render = formats[payload.format]
    content = render()
    item = m.Report(
        assessment_id=assessment.id,
        format=payload.format,
        dataset=payload.dataset,
        filename=f"webscope-{assessment.id[:8]}-{payload.dataset}.{extension}",
        mime_type=mime,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )
    db.add(item)
    db.flush()
    event(
        db,
        assessment.id,
        "REPORT_GENERATED",
        f"{payload.format.upper()} report generated",
        {"report_id": item.id, "sha256": item.sha256, "dataset": item.dataset},
    )
    return item
