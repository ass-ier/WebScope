# Evidence and provenance

Uploaded HAR, WebScope JSON and OpenAPI JSON now enter isolated temporary
browser workspaces. See [deployment.md](deployment.md). Imported evidence
receives fresh IDs and recomputed redacted integrity hashes, retaining declared
source ID/hash/collector as **unverified import provenance**. Imported rule
declarations are namespaced to the new assessment and cannot overwrite installed
rules. PNG evidence is decoded, dimension-checked and re-encoded without source
metadata; its pixels still require uploader review.

Synthetic templates are labeled SYNTHETIC, uploads UPLOADED, and locally
collected records COLLECTED. Importing never grants target authorization or
executes an endpoint. Session expiry/deletion removes the whole owned evidence
graph rather than leaving orphaned findings.

`Evidence` stores a UUID, assessment UUID, type, source, summary, timestamp,
collector version, redacted structured data, redacted raw text, and integrity
SHA-256. HTTP response body hashes separately describe the collected decoded
bytes before redaction. Wire hashes are recorded when raw transport bytes are
available; they are not fabricated for already-buffered injected transports.
Truncated bodies are explicitly marked and are not full-response hashes.

## Types and sources

Collection emits HTTP_REQUEST, HTTP_RESPONSE, DNS_RESPONSE, TLS_CERTIFICATE,
HTML, JAVASCRIPT, ENDPOINT, HEADER, COOKIE, TECHNOLOGY_OBSERVATION and
CORS_OBSERVATION. Analyst notes emit ANALYST_NOTE. Failed/blocked operations
use explicit typed event evidence, such as REDIRECT_BLOCKED, HTTP_TIMEOUT,
HTTP_FAILED, PATH_BLOCKED, BUDGET_EXHAUSTED and TLS_VERIFICATION_FAILED.

Derived observations retain `source_evidence_id`. Endpoints link to the HTML,
script, robots/sitemap response, manual endpoint declaration, or imported
OpenAPI document that introduced them. Transactions link request and response
evidence and the discovered endpoint. Technologies link their indicator
evidence and endpoint. DNS/TLS and security-control observations link their
collection evidence.

SCREENSHOT evidence can be created with **Capture redacted evidence**. It is
a PNG rendering of already-redacted persisted text, explicitly labeled as not
a target-browser rendering. It links back to its source evidence; image bytes
are available through the evidence image endpoint and included in complete JSON.
Screenshots in `docs/screenshots/` separately prove the real workstation
workflow. WebScope never executes target JavaScript or claims headless target
screenshot collection.

## Database-enforced relationships

`Finding.evidence_id` is non-null and has a composite foreign key to
`Evidence(id, assessment_id)`. A separate FindingEvidence relation supports
additional links without relaxing the mandatory primary link. CaseFinding,
CaseEvidence, endpoint/transaction/technology and analyst-note links also
use same-assessment composite foreign keys. A SQLite trigger rejects evidence
updates; another rejects edits to automated finding facts.

The automated facts include rule ID/version, severity, confidence, rationale,
evidence ID and observation classification. Analyst status, written conclusion,
severity/confidence reclassification and explained priority override are stored
separately. There is no automatic promotion to CONFIRMED.

## Inspecting and exporting

Evidence Explorer exposes structured and raw-redacted views and related
findings/endpoints/transactions. The transaction viewer shows both halves of
the exchange, timing, headers, truncation and hashes. Every collection,
discovery, analyst disposition, note, case action and report generation records
a timeline event.

Assessment JSON is the complete portable snapshot, including all inventories,
evidence, relationships, rules, notes, cases, timeline, risk factors and graph.
Markdown/PDF include human-oriented inventories and bounded evidence excerpts,
with stable evidence IDs for lookup in the companion JSON. CSV evidence export
is deliberately an index, not an unredacted response dump.
