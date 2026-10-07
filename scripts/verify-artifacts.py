"""Verify the real browser-generated example without contacting any target."""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path

from PIL import Image
from pypdf import PdfReader

root = Path(__file__).resolve().parents[1]
directory = root / "docs" / "example"
proof = json.loads((directory / "workflow-proof.json").read_text())
exports = proof["exports"]
snapshot_file = next(e.get("artifact", e["filename"]) for e in exports if e["format"] == "json")
snapshot = json.loads((directory / snapshot_file).read_text())
assert snapshot["assessment"]["id"] == proof["assessment_id"]
assert snapshot["assessment"]["status"] == "COMPLETED"
assert snapshot["target_record"]["validated_at"]
assert snapshot["scope_rule_records"]
assert len(snapshot["endpoints"]) == proof["counts"]["endpoints"]
assert len(snapshot["findings"]) == proof["counts"]["findings"]
assert len(snapshot["evidence"]) == proof["counts"]["evidence"]
assert len(snapshot["graph"]["nodes"]) == proof["graph_nodes"]
assert len(snapshot["graph"]["edges"]) == proof["graph_edges"]
assert snapshot["cases"][0]["status"] == "CLOSED"
assert snapshot["case_findings"][0]["finding_id"] == proof["finding_id"]
assert snapshot["case_evidence"][0]["evidence_id"] == proof["evidence_id"]
finding = next(f for f in snapshot["findings"] if f["id"] == proof["finding_id"])
assert finding["status"] == "CONFIRMED" and finding["confidence"] == "MEDIUM"
assert finding["automated"]["confidence"] == "MEDIUM"
assert snapshot["risk"][finding["id"]]["priority"] == "HIGH"
assert finding["override_reason"]
capture = next(e for e in snapshot["evidence"] if e["id"] == proof["capture_id"])
assert capture["type"] == "SCREENSHOT"
image = Image.open(io.BytesIO(base64.b64decode(capture["data"]["image_base64"])))
assert image.width == 1100 and image.format == "PNG"
secrets = ["COOKIE_DUMMY_SECRET", "PREFERENCE_DUMMY_SECRET", "FORM_DUMMY_SECRET",
           "API_DUMMY_SECRET", "ENV_DUMMY_SECRET"]
results = []
for export in exports:
    file = directory / export.get("artifact", export["filename"])
    content = file.read_bytes()
    result = {**export, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    if export["format"] == "pdf":
        reader = PdfReader(io.BytesIO(content))
        text = "\n".join(p.extract_text() for p in reader.pages)
        result["pages"] = len(reader.pages)
        for heading in ("Executive Summary", "Scope", "Methodology", "Attack Surface", "Technology Inventory",
                        "Automated Findings", "Evidence", "Risk Assessment", "Remediation Recommendations",
                        "Analyst Conclusions", "Assessment Timeline", "Appendix"):
            assert heading in text, heading
        assert "Why WebScope flagged this" in text
        assert "credentialed origin reflection" in text
    else:
        text = content.decode("utf-8-sig")
    for secret in secrets:
        assert secret not in text, f"Secret leaked into {file.name}: {secret}"
    if export["format"] == "csv":
        parsed = list(csv.DictReader(io.StringIO(text)))
        assert len(parsed) == len(snapshot[export["dataset"]])
        assert "id" in parsed[0]
        result["rows"] = len(parsed)
    if export["format"] == "markdown":
        assert "## Analyst Conclusions" in text and "## Automated Findings" in text
        assert "Why WebScope flagged this" in text
    results.append(result)

spacings = []
previous = None
for event in proof["network_attempts"]:
    data = event["data"]
    if data["request_number"] == 1:
        previous = None
    if previous is not None:
        spacings.append(data["elapsed_seconds"] - previous)
    previous = data["elapsed_seconds"]
assert spacings and min(spacings) >= 0.0999  # Four-decimal audit timestamps may round by 0.0001s.
assert len(proof["network_attempts"]) == 12
assert proof["page_errors"] == []
summary = {
    "result": "PASS",
    "assessment_id": proof["assessment_id"],
    "artifacts_verified": len(results),
    "minimum_recorded_attempt_spacing_seconds": round(min(spacings), 4),
    "rate_configuration_per_second": 10,
    "actual_collector_requests": 12,
    "additional_fixture_audit_reads": proof["actual_fixture_requests"].count("/fixture-requests"),
    "redaction_sentinels_checked": len(secrets),
    "redacted_capture_dimensions": list(image.size),
    "artifacts": results,
}
(directory / "artifact-verification.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
