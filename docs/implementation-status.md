# Implementation and acceptance matrix

**Follow-up:** this original 45-section register is supplemented by
[deployment.md](deployment.md) and [hosted verification](hosted-verification.md).
The user subsequently requested Vercel/Render deployment, no sign-in, isolated
temporary uploads and prominent retention notices. Hosted import-only mode and
ephemeral session storage are intentional user-directed behavior changes;
local collection and the original deterministic analysis remain available.

This register covers all **45 sections** of the authoritative 1,549-line
specification, SHA-256
`c2d3b5c14002cc462c4e29329e62affc07c1bc9b09f85fe9ae6e9dfac0cab3fe`.
Every line was read before architecture or source edits. No summary substituted
for the original, and the original attachment was not modified.

**Status vocabulary:** IT = implemented and tested in the stated fixture/local
environment; IU = implemented but not exercised; P = partial; N = not
implemented; O = intentionally optional/non-goal. IT does not imply Internet
interoperability or exploit validation. Exact commands/results and artifacts
are in [verification.md](verification.md).

### Linked implementation and test index

Backend sources: [models](../backend/app/models.py),
[Pydantic schemas](../backend/app/schemas.py), [API](../backend/app/main.py),
[migrations](../backend/alembic/versions),
[scope](../backend/app/services/scope.py),
[network gate](../backend/app/services/network.py),
[discovery/OpenAPI](../backend/app/services/discovery.py),
[DNS/TLS](../backend/app/services/infrastructure.py),
[fingerprints](../backend/app/services/technology.py),
[rules/risk](../backend/app/services/analysis.py),
[evidence store](../backend/app/services/store.py),
[redaction](../backend/app/services/redaction.py),
[capture](../backend/app/services/capture.py),
[graph](../backend/app/services/graph.py),
[reports](../backend/app/services/reporting.py).

Executed tests: [scope/transport](../backend/tests/test_policy.py),
[budgets/deadlines/malformed input](../backend/tests/test_limits.py),
[parsers/reports/OpenAPI](../backend/tests/test_parsers.py),
[DNS/TLS](../backend/tests/test_infrastructure.py),
[fingerprints](../backend/tests/test_technologies.py),
[database integrity/reopen](../backend/tests/test_integrity.py),
[API workflow/redaction](../backend/tests/test_workflow.py),
[frontend workflows](../frontend/tests/workflows.test.tsx),
[graph layout](../frontend/tests/graph-layout.test.ts),
[real browser E2E](../frontend/e2e/workstation.spec.ts),
[export parser](../scripts/verify-artifacts.py),
[production reopen](../scripts/verify-production.mjs).
All page implementations are in [frontend pages](../frontend/src/pages).

## All 45 specification sections

| § | Requirement and implemented surface | Status | Code and executed proof |
|---|---|---|---|
| 1 | Evidence first; authorization; local-first; no fake AI; passive before active; non-destructive; reproducibility; analyst control | IT | `services/scope.py`, `network.py`, `analysis.py`, `models.py`; `test_policy.py`, `test_integrity.py`, `test_workflow.py`, browser E2E |
| 2 | WebScope product name, subtitle, evidence-driven analyst identity | IT | README, PRODUCT, frontend shell and finding screenshots |
| 3 | Python 3.12+, FastAPI/Pydantic v2/SQLAlchemy/SQLite/Alembic/httpx/BeautifulSoup/dnspython/cryptography; React/TS/Vite/Tailwind/Router/Query/real graph | IT | Backend manifest/lock, frontend manifest/lock; independent tests and production build |
| 4 | Modular, independently testable backend/frontend, fixtures, docs, scripts | IT | Repository structure; separate test commands; no monolithic collection route logic |
| 5 | Assessment UUID/name/description/target/timestamps/status/scope/config and all related inventories | IT | `models.py`, `schemas.py`, `assessments.py`; create/update/list, lifecycle and snapshot tests |
| 6 | Explicit targets, exact allowed/excluded hosts/paths, central scope, blocked redirect evidence | IT | `scope.py`, `network.py`; exact no-resolve/no-send vectors, redirected and encoded path tests |
| 7 | Controlled target/IP/HTTP(S)/redirect/TLS/method/server/header/cookie/HTML/resource/script/form/API/robots/sitemap discovery; configurable modes | IT | `assessments.py`, `discovery.py`; discovery fixtures, optional HEAD/OPTIONS tests, browser graph |
| 8 | Request method/URL/headers/query/body metadata/time; response status/headers/type/length/body/hash/timing/redirect; sensitive redaction | IT | `network.py`, `redaction.py`; raw/structured transaction tests, response cap/timeout/gzip tests |
| 9 | Source-bearing fingerprint name/category/version/confidence, headers/HTML/scripts/CSS/cookies/banners/assets; all listed category mechanisms | IT | `technology.py`; parameterized fingerprint fixtures plus real demo React/Express/generator indicators |
| 10 | Endpoint URL/method/parameters/content type/auth observations/source/evidence; HTML/forms/JS/robots/sitemap/manual/OpenAPI | IT | `discovery.py`; parser/API tests and browser manual/import steps; mutation methods never executed |
| 11 | Real domain/host/IP/endpoint/API/form/resource/technology graph with named relationships | IT | `graph.py`, React Flow page; graph nodes/edges checked in E2E and screenshot; external references not fetched |
| 12 | A/AAAA/CNAME/MX/TXT/NS/SOA, resolver/time/TTL/records, contextual oddities | IT | `infrastructure.py`; deterministic all-record resolver tests and explicit DNS failure/budget/passive tests |
| 13 | TLS subject/issuer/SAN/validity/expiry/signature/key/negotiated protocol/chain, evidence-backed conditions | IT | `infrastructure.py`, TLS rules; certificate fixtures, verification fallback and actual local trusted TLS handshake |
| 14 | All eight required headers; severity/confidence/rationale/evidence/recommendation; no automatic critical absence | IT | `analysis.py`; missing HTML headers, HTTP HSTS exclusion and CSP framing alternative tests |
| 15 | Cookie Secure/HttpOnly/SameSite/Domain/Path/expiry; session-name heuristic, separate potential weaknesses | IT | `parse_cookie`, cookie rules; duplicate value redaction and attribute tests, browser controls |
| 16 | ACAO/ACAC/method/header observations, wildcard context, explicit origin reflection probe | IT | CORS rules and CORS evidence; positive/negative tests, real safe-check CORS finding |
| 17 | Explicit configured disclosure paths only; content signatures, directory/error/source-map/banner observations | IT | `analysis.py`, checks endpoint; opt-in tests, real `/.env`, `/.git/`, `/debug`; no brute-force enumeration |
| 18 | REST methods/types/auth/parameters/schema/error/data indicators/CORS; OpenAPI params/security requirements/local refs | IT | `discovery.py`, `analysis.py`; import/ref/shape/depth tests, browser import, no-network assertions |
| 19 | Rule metadata, safety level/required evidence/request type/remediation; explicit safe GET checks with bounds/audit | IT | `DetectionRule`, `NetworkRun`, checks confirmation; policy tests and browser confirmation |
| 20 | Full finding identity/title/category/severity/confidence/status/description/impact/evidence/rule/asset/endpoint/remediation/references/time/analyst assessment | IT | `Finding`, finding response/detail; full workflow and immutability tests |
| 21 | NEW/REVIEWING/CONFIRMED/FALSE_POSITIVE/NEEDS_VERIFICATION/DISMISSED, notes and separate written conclusions | IT | Finding PATCH/notes and detail UI; required-reason tests, component tests and real browser review |
| 22 | Dedicated raw/structured evidence explorer; HTTP/DNS/TLS/HTML/JS/endpoint/cookie/header/technology/screenshot/note types | IT | Evidence model/API/UI; redacted PNG capture from saved text, source links, raw evidence E2E |
| 23 | Finding cannot exist without same-assessment evidence; no orphaning; additional evidence relation | IT | Composite FKs/non-null primary evidence, immutable triggers, EvidenceLink; direct database negative tests |
| 24 | Transparent severity/confidence/exposure/importance/auth/impact factors, explained priority and overrides | IT | `risk()`, detail UI and all reports; exact formula tests and browser HIGH override retaining automated facts |
| 25 | Real dashboard/overview counts, severity chart, graph, technologies, endpoints, recent evidence/activity | IT | Dashboard/overview components; no fake data, effective-severity component tests and fixture screenshots |
| 26 | Creation/validation/discovery/TLS/check/finding/review/report audit timeline | IT | `TimelineEvent`, store event boundary; workflow snapshot events and real recorded request timestamps |
| 27 | Assessment-linked cases, title/description/scope/status/priority/assignee/findings/evidence/notes/timeline and five-stage lifecycle | IT | Case/CaseFinding/CaseEvidence, API/UI; cross-assessment guards and full browser OPEN→CLOSED |
| 28 | Technical Markdown, complete JSON, native PDF; executive/scope/method/inventory/findings/evidence/risk/remediation/conclusions/timeline/appendix | IT | `reporting.py`; PDF text parsing, JSON relationship parsing and actual downloaded artifacts |
| 29 | JSON/Markdown/PDF and four CSV datasets; real bytes, persisted hashes; CSV formula protection | IT | Report BLOB model/API; seven browser exports, artifact parser, adversarial formula-prefix tests |
| 30 | External CVE/technology/DNS/CT/threat intelligence remain optional and independent | O | Explicit future roadmap; no integration dependency or fake functional buttons |
| 31 | All 21 minimum models plus FindingEvidence/EvidenceLink/Settings; FKs/indexes | IT | Frozen Alembic migrations, schema comparison, direct integrity/reopen tests |
| 32 | REST assessment/discover/analyze/inventory/findings/evidence/timeline/review/notes/graph/reports APIs with Pydantic boundaries | IT | `main.py`, `schemas.py`, `/openapi.json`; API tests and real browser client |
| 33 | All sixteen named pages plus usable details/edit flows | IT | Frontend page modules, component tests, E2E route smoke and complete workflow |
| 34 | Overview target/status/scope/hosts/endpoints/APIs/technologies/findings/severities/recent evidence/activity | IT | Backend overview and frontend overview; E2E actual count assertions |
| 35 | Finding detail prominently shows Why WebScope flagged this, evidence/exchange/rule/impact/remediation/references/analyst notes | IT | Finding page; component tests and desktop/mobile screenshots |
| 36 | Raw and structured redacted exchange/evidence, timestamps, linked findings/endpoints | IT | Evidence/transaction pages, same-assessment source lineage; raw view and PNG E2E |
| 37 | Clearly labeled loopback-only intentionally weak demo, deterministic fixtures; TLS practical fixture | IT | `fixtures/demo.py`, OpenAPI sample, loopback TLS test; no malicious payloads or external scans |
| 38 | Backend unit/API/policy/parser/DNS/TLS/header/cookie/CORS/endpoint/finding/evidence/report/security tests; frontend workflows | IT | Full pytest/Vitest/Playwright suites, lint/build and artifact parsing logs |
| 39 | All grouped acceptance criteria | IT | Granular acceptance table below |
| 40 | Restrained dark dense/readable responsive technical workstation, semantic severity and strong evidence | IT | DESIGN/tokens, screenshots, overflow assertions, bounded visual verification |
| 41 | README identity/overview/architecture/features/workflow/security/evidence/rules/screenshots/example/testing/install/usage/limitations/responsible use/roadmap | IT | README and five focused docs; linked real artifacts |
| 42 | No port scanner, unrestricted crawler, brute force, destructive exploit/malware framework, proxy replacement, chatbot, fake AI/vulnerability-only database | O | Intentionally excluded; method/scope/import/passive guards verify relevant boundaries |
| 43 | All eight implementation phases complete, not foundation-only | IT | Local commit history, phase tracker, backend/frontend/E2E and report proof |
| 44 | No fake features, unsupported claims, silent operational failures, source execution, unsafe scope bypass; deterministic modular maintainable code | IT | Explicit error evidence, typed APIs, failure and malformed-input tests, docs limitations |
| 45 | Complete target→discovery→surface→controls→safe checks→evidence→finding→review→conclusion→risk→report investigation | IT | `frontend/e2e/workstation.spec.ts`, committed workflow proof and seven reports |

## Individual §39 acceptance criteria

| Criterion | Status | Exact proof |
|---|---|---|
| Create assessment | IT | Browser Create assessment and `test_full_api_investigation_exports_redaction` |
| Define target | IT | URL validation, credential-bearing target rejection, live loopback target |
| Define scope | IT | Creation/edit schemas, reauthorization component/API tests |
| Validate target | IT | DRAFT→READY API/browser; no network at validation |
| Execute controlled discovery | IT | Browser confirmed discovery; 12 total collector requests across discovery/check runs |
| DNS analysis | IT | `test_all_dns_types_ttl_resolver_and_errors`, passive denial |
| HTTP discovery | IT | Actual local fixture plus mock no-send and redirect tests |
| HTTPS/TLS analysis | IT | `test_real_loopback_tls_handshake`, trust failure and certificate fixture tests |
| Endpoint discovery | IT | HTML/form/script/robots/sitemap plus browser manual/OpenAPI inventory |
| Technology detection | IT | All fingerprint mechanism fixtures, actual three demo indicators |
| Header analysis | IT | Eight header observations, contextual HSTS/frame exceptions |
| Cookie analysis | IT | Duplicate Set-Cookie attribute/redaction and heuristic findings |
| CORS analysis | IT | Wildcard context and confirmed-safe-probe workflow |
| Attack-surface graph | IT | Real React Flow nodes/relationships, graph metadata and screenshots |
| Endpoint inventory | IT | 22 parsed CSV/JSON rows, UI search/detail/import |
| Technology inventory | IT | Three parsed export rows with confidence/source |
| HTTP transaction viewer | IT | Browser exchange detail and raw/structured component tests |
| Evidence explorer | IT | Raw redacted source, lineage and actual PNG capture |
| Timeline | IT | Actual network/review/case/report events in snapshot |
| Deterministic rules | IT | Versioned definitions and repeated-analysis deduplication |
| Severity | IT | Contextual rules, automated facts retained through overrides |
| Confidence | IT | Independent factors and weak-indicator tests |
| Evidence relationship | IT | Non-null/composite FK/direct DB rejection of invalid links/deletion |
| Remediation | IT | Finding detail and parsed Markdown/PDF sections |
| Analyst status | IT | Written disposition guards and actual CONFIRMED finding |
| Analyst notes | IT | Finding/case notes persisted/reopened and exported |
| Markdown report | IT | Generated and content/redaction parsed |
| JSON report | IT | Complete snapshot, references, rules and risk parsed |
| PDF report | IT | Native ReportLab PDF; headings and finding text extracted with pypdf |
| CSV exports | IT | Four parsed datasets, expected row counts and formula-injection tests |
| Scope enforcement | IT | Validator plus transport assertions proving zero DNS/HTTP calls |
| Redirect enforcement | IT | Blocked external redirect; only permitted sends counted |
| Request limits | IT | Shared redirect/resources/robots/sitemap budget test |
| Rate limiting | IT | Timestamp spacing tests plus actual recorded ≥0.1s at 10/s |
| Timeout handling | IT | Slow response/trickle, total run deadline and recorded errors |
| Sensitive-data redaction | IT | Distinct dummy sentinels checked in API/raw/graph/timeline and all report formats |
| Safe active checks | IT | Explicit confirmation/configured paths, safe-method deny tests, no imported calls |
| Backend tests | IT | Full suite and log in verification record |
| Frontend tests | IT | Component/API-integration/workflow suite and log |
| Integration tests | IT | Real API/browser/loopback fixture and local TLS |
| Deterministic fixtures | IT | Synthetic read-only demo, DNS doubles, generated local certificates |
| Documentation complete | IT | README, architecture/security/rules/evidence/usage, this matrix and verification artifacts |

## Deliberate boundaries, not disguised mandatory gaps

No mandatory section is marked partial or not implemented. External intelligence,
destructive/exploit behavior and the other named non-goals are intentionally
absent. Network collection, detection and redaction are **bounded supported
capabilities**, not promises of universal crawling, all-secret recognition or
all-protocol interoperability. TLS protocol enumeration, authenticated browser
sessions, target-side JavaScript rendering, YAML import and arbitrary remote
OpenAPI refs are not advertised as implemented. SCREENSHOT means a labeled
redacted-evidence capture, not a rendered target page.

Tests prove the implemented behavior with deterministic fixtures and owned
loopback services. No public DNS integration or third-party security assessment
was run. See the verification record for exact exercised paths and limitations.
