import io
import json

import httpx
import pytest
from pypdf import PdfReader

from app import models as m
from app.schemas import ReportCreate
from app.services import redaction, reporting
from app.services.analysis import analyze, parse_cookie
from app.services.assessments import scope_for
from app.services.discovery import harvest, import_openapi
from app.services.network import NetworkRun
from app.services.store import evidence, rows


@pytest.mark.parametrize(
    "value",
    [
        'password="DISTINCT_SECRET"',
        "API_KEY=DISTINCT_SECRET",
        '{"access_token": "DISTINCT_SECRET"}',
        "Authorization: Bearer DISTINCT_SECRET",
        "Cookie: session=DISTINCT_SECRET",
        "https://user:DISTINCT_SECRET@allowed.test/?api_key=DISTINCT_SECRET",
        '<input type="password" value="DISTINCT_SECRET">',
        "<textarea>DISTINCT_SECRET</textarea>",
        "<input name=password value=DISTINCT_SECRET>",
        "<Password>DISTINCT_SECRET</Password>",
        '<meta name="csrf-token" content="DISTINCT_SECRET">',
        "-----BEGIN PRIVATE KEY-----\nDISTINCT_SECRET\n-----END PRIVATE KEY-----",
    ],
)
def test_sensitive_text_redacted(value):
    assert "DISTINCT_SECRET" not in redaction.text(value)


def test_cookie_attributes_survive_duplicate_header_redaction():
    headers = redaction.headers(
        [
            ("Set-Cookie", "session=ONE_SECRET; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=allowed.test"),
            ("Set-Cookie", "prefs=TWO_SECRET; Expires=Wed, 09 Jun 2030 10:18:14 GMT; Path=/prefs"),
        ]
    )
    assert "ONE_SECRET" not in str(headers) and "TWO_SECRET" not in str(headers)
    first, second = headers["set-cookie"].splitlines()
    assert parse_cookie(first)[1]["secure"] is True
    assert parse_cookie(first)[1]["samesite"] == "Lax"
    assert parse_cookie(second)[1]["expires"] == "Wed, 09 Jun 2030 10:18:14 GMT"


@pytest.mark.parametrize(
    "body,content_type",
    [
        ("{ malformed json", "application/json"),
        ("<html><a href='/path'>broken", "text/html"),
        ("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>", "application/xml"),
        ("\ufffd\x00invalid text", "text/plain"),
    ],
)
async def test_malformed_content_retained_safely_without_crash(db, make_assessment, body, content_type):
    item = make_assessment()
    run = NetworkRun(
        db,
        item.id,
        scope_for(db, item),
        httpx.MockTransport(lambda r: httpx.Response(200, text=body, headers={"content-type": content_type})),
    )
    tx = await run.request("http://127.0.0.1:9998/")
    harvest(db, item.id, run.scope, tx)
    analyze(db, item)
    assert rows(db, m.Evidence, item.id)


async def test_hsts_http_context_framing_alternative_and_public_cors(db, make_assessment):
    item = make_assessment()
    run = NetworkRun(
        db,
        item.id,
        scope_for(db, item),
        httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Content-Security-Policy": "frame-ancestors 'none'",
                    "Access-Control-Allow-Origin": "*",
                },
                text="<html></html>",
            )
        ),
    )
    tx = await run.request("http://127.0.0.1:9998/")
    harvest(db, item.id, run.scope, tx)
    analyze(db, item)
    findings = rows(db, m.Finding, item.id)
    assert not any(f.rule_id in ("WS-SEC-001", "WS-HDR-004") for f in findings)
    wildcard = next(f for f in findings if f.rule_id == "WS-CORS-001")
    assert wildcard.severity == "INFO" and wildcard.confidence == "HIGH"


def test_csv_formula_injection_and_markdown_pdf_target_escaping(db, make_assessment):
    item = make_assessment()
    item.name = "<script>alert('target')</script>"
    for prefix in ("=", "+", "-", "@", " \t=", "\r="):
        evidence(
            db,
            item.id,
            "ANALYST_NOTE",
            prefix + "formula()",
            prefix + "formula()",
            {"text": "<b>untrusted</b>"},
        )
    for format in ("csv", "markdown", "pdf"):
        report = reporting.generate(
            db, item, ReportCreate(format=format, dataset="evidence" if format == "csv" else "assessment")
        )
        if format == "csv":
            import csv

            parsed = list(csv.DictReader(io.StringIO(report.content.decode("utf-8-sig"))))
            assert all(r["source"].startswith("'") for r in parsed)
        elif format == "markdown":
            assert b"<script>" not in report.content and b"&lt;script&gt;" in report.content
        else:
            text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(report.content)).pages)
            assert "<script>" in text  # Literal text, not executable markup.


def test_openapi_recursive_refs_kept_and_bad_refs_rejected(db, make_assessment):
    item = make_assessment()
    scope = scope_for(db, item)
    recursive = {
        "openapi": "3.0.0",
        "paths": {},
        "components": {
            "schemas": {
                "Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}
            }
        },
    }
    assert import_openapi(db, item.id, scope, recursive)["imported"] == 0
    for ref in ("file:///etc/passwd", "https://evil.test", "#/missing"):
        with pytest.raises(ValueError):
            import_openapi(db, item.id, scope, {"openapi": "3.0.0", "paths": {}, "x-ref": {"$ref": ref}})
    json.dumps(recursive)
