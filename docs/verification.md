# Verification record

Verification was performed on **2026-10-07**, on an owned local workstation.
The authoritative specification has 1,549 lines and SHA-256
`c2d3b5c14002cc462c4e29329e62affc07c1bc9b09f85fe9ae6e9dfac0cab3fe`.
All 45 sections and individual acceptance criteria are registered in
[implementation-status.md](implementation-status.md).

## Environment

| Component | Observed version |
|---|---|
| OS/architecture | macOS 26.6.2, arm64 |
| Python | 3.12.11 |
| Node / npm | 20.19.2 / 11.4.2 |
| FastAPI / Pydantic | 0.142.2 / 2.13.5 |
| SQLAlchemy / Alembic | 2.1.4 / 1.20.0 |
| httpx / dnspython | 0.28.1 / 2.8.0 |
| cryptography | 48.0.1 |
| pytest | 9.1.1 |
| ReportLab / pypdf | 4.5.1 / 6.19.0 |
| React / React Router | 19.3.0 / 7.18.4 |
| TypeScript / Vite | 5.9.3 / 7.3.7 |
| Tailwind / TanStack Query | 4.3.3 / 5.104.1 |
| React Flow | 12.12.0 |
| Vitest / Playwright | 3.2.7 / 1.63.0 |

Dependency integrity: `python -m pip check` reported no broken requirements;
`npm ls --depth=0` resolved the declared frontend dependencies. Backend versions
are frozen in `backend/requirements.lock`; frontend versions in
`frontend/package-lock.json`. Environments live in the worktree (`.venv`,
`frontend/node_modules`).

## Executed checks

| Check | Exact command | Captured result |
|---|---|---|
| Backend unit/API/policy/parser/infrastructure/integrity/report suite | `cd backend && ../.venv/bin/pytest -q` | 109 passed; 0 failed; 0 skipped |
| Backend lint | `cd backend && ../.venv/bin/ruff check app tests alembic` | All checks passed |
| Fresh migrations/schema drift/rollback/re-upgrade | `alembic upgrade head; alembic check; alembic downgrade base; alembic upgrade head` against dedicated proof SQLite file | Revision 0003; no schema drift; integrity `ok`; no FK violations; 24 tables including version table |
| Frontend component/API-integration/workflow tests | `cd frontend && npm test -- --reporter=dot` | 43 passed; 0 failed; 0 skipped |
| Frontend typecheck/production build | `cd frontend && npm run build` | TypeScript and Vite build passed |
| Browser E2E | `cd frontend && npx playwright test --reporter=list` | 2 passed; 0 failed; 0 skipped; Chromium |
| Actual exported file verification | `.venv/bin/python scripts/verify-artifacts.py` | 7 actual artifacts parsed and verified; result PASS |
| Reopened production deployment | `node scripts/verify-production.mjs` | PASS with Vite and target fixture stopped; 20 same-origin browser requests, no page errors |

Total automated test count: **154 passed, 0 failed, 0 skipped**, plus the
migration, lint/build, artifact parsing and production-deployment checks.

The backend suite emits one dependency deprecation warning: Starlette's
TestClient deprecates its httpx integration in favor of httpx2. The specified
httpx stack remains functional; no tests were skipped or hidden.

Logs:
[backend](verification-logs/backend-tests.txt),
[migrations](verification-logs/migrations.txt),
[frontend](verification-logs/frontend-tests.txt),
[build](verification-logs/frontend-build.txt),
[browser](verification-logs/browser-e2e.txt).

Production persistence proof is recorded separately in
[production-smoke.json](verification-logs/production-smoke.json). After stopping
Vite and the target fixture, the final backend was reopened and served compiled
assets, deep-linked findings/raw evidence/graph, saved notes, the closed case and
the byte-identical persisted PDF. All 20 observed browser requests remained on
the local backend origin.

## What the tests actually prove

**Scope and networking.** Actual fake-transport sends and resolution hooks,
not just validator return values, remain at zero for suffix-host attacks
(`allowed.test.evil.test`), userinfo confusion
(`allowed.test@denied.test`), denied hosts/ports/paths, encoded and double-encoded
aliases, dot segments, backslashes and unsafe methods. Blocked redirects
produce persisted evidence without following their destination. DNS answers
are validated and transport connections use the pinned IP with scoped Host
and SNI. Private/loopback denial and explicit opt-in are exercised.

**Budgets and deadlines.** One execution budget counts actual HTTP sends across
redirects, robots, sitemap and linked resources. A fixture test caps at five
sends. Inter-send timestamps are measured, not inferred from configuration.
Slow response, trickling body, response-byte cap, gzip expansion, malformed
compression, run-duration and transport-header override cases are exercised.
Explicit HEAD HTTP/HTTPS availability and OPTIONS method observations never
execute advertised POST methods.

**Passive boundaries.** Socket, address-resolution, HTTP and DNS hooks fail the
test if passive analysis tries to network. OpenAPI import is similarly tested
with a fail-on-network hook. Actual browser E2E compares the local fixture's
request counter before and after Analyze; only the test's audit-read request
is added.

**DNS/TLS.** All seven DNS record types are exercised using deterministic fake
resolver answers with TTL, resolver and timestamp. DNS errors and budget
exhaustion are explicit. TXT secrets are checked in the observation table,
not only the API. Certificate fixtures cover fields, expiry, SAN mismatch,
key/hash metadata and trust failure. One TLS test performs a real loopback
handshake against a generated trusted fixture certificate. Weak negotiated
protocol rule logic uses a clearly synthetic connector fixture; no claim is
made that this host negotiated deprecated TLS with a real server.

**Detection and provenance.** Header context, cookies, CORS, disclosure
signatures, API indicators and all fingerprint mechanisms have fixtures.
Analysis is deterministic and idempotent for existing source evidence.
Findings retain rule/version, separate confidence/severity and a non-null
primary evidence reference. Direct database operations reject missing or
cross-assessment evidence, orphaning deletion and immutable-fact edits.
Same-assessment case links, derived evidence lineage and PNG capture are tested.
An on-disk migrated database is reopened to verify notes, case relationships
and frozen report downloads survive process/session replacement.

**Redaction.** Distinct dummy values are seeded into duplicate Set-Cookie,
Authorization/API-key headers, URL queries, JSON/form/XML/HTML/textarea/PEM
patterns, notes, named parameter examples and DNS TXT. Sensitive values are
searched for in API/raw evidence, graph/timeline, Markdown/JSON/CSV and extracted
PDF text. Cookie attributes and non-secret CORS credentials policy remain
inspectable. OpenAPI security-schema metadata is not erased just because its
name contains “API key”.

**Local application boundary.** Cross-origin/cross-site mutation, hostile Host,
missing custom header, non-JSON content type, oversized body, invalid/null
inputs, unvalidated/unauthorized collection and invalid lifecycle changes are
negative-tested. Production SPA deep links work without swallowing unknown
API routes. Target HTML remains text. CSV cells with formula prefixes are
quoted defensively; Markdown/PDF metacharacters are escaped.

## Real running API and frontend workflow

The E2E suite starts from an empty assessment form in Chromium. It uses the
real Vite frontend and local FastAPI backend—not mocked API responses—and the
owned `fixtures/demo.py` application bound to `127.0.0.1:9998`.

The complete test creates/authorizes/scopes/validates, confirms discovery,
confirms safe disclosure/CORS checks, opens a source-backed finding, saves a
written analyst conclusion and explained priority override, adds a note,
inspects raw evidence, renders a PNG capture, adds a manual POST inventory
entry, imports OpenAPI, creates a linked case, adds case notes, progresses all
case stages to CLOSED, inspects inventory/control/transaction/timeline pages,
reruns passive analysis, generates all seven exports, and downloads through
the actual browser control.

The second browser test proves passive creation/analysis produces no
transactions and collection/delete actions remain guarded.

The committed example contains **22 endpoints, 3 technology indicators,
12 HTTP transactions, 139 evidence records, 44 findings and one closed case**.
Severity counts are 0 critical, 2 high, 5 medium, 15 low and 22 informational.
The complete relation graph has 72 nodes and 84 edges. Counts are not mocked
dashboard data; they are saved in [workflow-proof.json](example/workflow-proof.json).

The collector sent eight discovery requests and four explicit safe-check
requests. The external redirect, excluded `/admin/private`, form `/session`,
manual mutation inventory and imported `/api/orders` were not requested.
Three `/fixture-requests` reads were performed by the test harness to audit
behavior; they are separated from the twelve collector requests.

Actual rate timing, file sizes/hashes, CSV row counts, PDF page count and
record IDs are in [artifact-verification.json](example/artifact-verification.json).
The PDF is parsed for all report headings and finding rationale; CSV and JSON
are parsed for structure and relationships, rather than checked only for MIME.

## Visual and responsive proof

Actual desktop captures use 1440×1000; mobile captures use 390×844:

- [Finding desktop](screenshots/finding-desktop.png)
- [Raw evidence desktop](screenshots/evidence-desktop.png)
- [Attack-surface graph desktop](screenshots/graph-desktop.png)
- [Finding mobile](screenshots/finding-mobile.png)
- [Raw evidence mobile](screenshots/evidence-mobile.png)

The first batched pass found an unreadable initial graph fit when findings
formed a tall column. This was treated as a functional visual defect, not
decorative polish. The confirmation pass checks the compact inventory layout,
explicit finding visibility, accurate counts, and readable graph controls.
The finding/evidence views passed the initial desktop/mobile review.
Horizontal document overflow is asserted absent at 390px. Target content is
never executed to produce these screenshots.

The one-time mechanical design detector returned `[]`
([raw result](verification-logs/design-detector.json)). A separate, read-only
visual finish review judged persistence, typography/material, evidence
hierarchy and responsive adaptation as passing, and the graph readability
defect as **resolved**, with **no remaining material fixes**. Because the named
skill reviewer was unavailable in this harness, a general-purpose agent
performed that screenshot-bounded role. DESIGN.md and its frontend sidecar were
extracted from the built styles by the UI implementation agent rather than a
separate named documenter.

## Limitations and unrun environments

No external/third-party target, public DNS interoperability, authenticated
session, live exploit, distributed load or exhaustive cipher/protocol test was
run. Browser E2E is Chromium, not a claim of Safari/Firefox coverage. Safe
read-only collection does not guarantee that a poorly designed target's GET
handlers are side-effect-free. Redaction covers documented patterns, not all
opaque or unlabelled proprietary secrets.

There are no required placeholder pages or fake export formats. Optional
external intelligence and the specification's exploit/scanner/AI non-goals
remain intentionally unimplemented. SCREENSHOT is explicitly a rendering of
redacted source text, not headless target-browser capture. OpenAPI accepts JSON
3.x; YAML must be converted locally, and remote/file references are rejected.

## Persistence, commits and services

Implementation is persisted in local commits on
`mk23rd-webscope-full-implementation`; no repository was published or pushed.
The branch's final commit log is the authoritative change record.
The proof assessment remains in the ignored local data directory and the
portable example artifacts are committed. Verification-only API, frontend and
fixture servers are stopped at handoff. Start them using the documented scripts;
no background service is required to inspect the committed artifacts.
