# Hosted deployment and temporary-upload verification

User-directed follow-up: prepare Vercel/Render deployment, include synthetic
data, allow user uploads, **do not add sign-in**, isolate temporary sessions,
and make retention obvious. Verified locally on 2026-10-08 (UTC+03:00).

## Implemented behavior

| Requirement | Implementation | Executed proof |
|---|---|---|
| No sign-in | Anonymous HttpOnly browser-session cookie; no account/password models or routes | Entry/UI tests and actual HTTPS browser assertion that no password input exists |
| Isolated sessions | Assessment ownership and authorization on every record/collection/report/rule route | Two browser contexts and API clients cannot access each other's IDs or exports |
| Synthetic data available | Full 139-evidence/44-finding web example, plus seven DNS types and illustrative TLS example | New sessions contain two private synthetic assessments; count assertions and source labels |
| New user uploads | HAR 1.x, WebScope snapshot JSON, OpenAPI 3.x JSON | Real HAR browser upload; snapshot and OpenAPI API tests |
| Safe import | Size/depth/count limits, redaction, ID remapping, relationship validation, unverified provenance | Positive/negative upload suite, malformed/cross-assessment/duplicate rollback tests |
| Temporary retention | Fixed 24-hour expiry, background cleanup, immediate End session deletion, hosted startup reset | Expiry denial, cleanup deletion, copied-cookie revocation and restart tests |
| Obvious notice | Entry copy, persistent session banner, upload acknowledgement, expiry timestamp, deletion dialog | Desktop/mobile screenshots and component/browser assertions |
| Hosted network safety | Backend import-only collection gate | Fail-on-network hooks and disabled browser actions |
| Vercel frontend | `frontend/vercel.mjs`, validated API origin, same-origin rewrite, SPA routing/security headers | Six config tests, provider-schema instance validation, production build |
| Render backend | `render.yaml`, native Python, migration/start script, free plan and ephemeral storage | Provider blueprint schema validation and local hosted-mode startup |
| Existing local workflows | Local safe collection, review, notes, cases and all exports remain operational | Two original full browser workflows rerun using session-scoped requests |

## Final executed results

| Command | Result | Log |
|---|---|---|
| `cd backend && ../.venv/bin/pytest -q` | **134 passed**, 0 failed, 0 skipped | [backend-tests.txt](verification-logs/hosted/backend-tests.txt) |
| `cd backend && ../.venv/bin/ruff check app tests alembic` | Passed | [backend-lint.txt](verification-logs/hosted/backend-lint.txt) |
| `cd frontend && npm test -- --reporter=dot` | **54 passed**, 0 failed, 0 skipped | [frontend-tests.txt](verification-logs/hosted/frontend-tests.txt) |
| `cd frontend && npm run build` | TypeScript and Vite passed | [frontend-build.txt](verification-logs/hosted/frontend-build.txt) |
| Fresh `alembic upgrade head`, `check`, `downgrade base`, `upgrade head` | Revision 0004; no drift; integrity `ok`; no FK violations | [migrations.txt](verification-logs/hosted/migrations.txt) |
| `WEBSCOPE_BASE_URL=http://127.0.0.1:8765 npx playwright test --reporter=list` | **2 passed**, local full workflow | [local-browser-regression.txt](verification-logs/hosted/local-browser-regression.txt) |
| `WEBSCOPE_BASE_URL=https://127.0.0.1:8877 WEBSCOPE_TEST_HTTPS=1 WEBSCOPE_TEST_HOSTED=1 npx playwright test --reporter=list` | **1 passed**, hosted HTTPS workflow | [browser-e2e.txt](verification-logs/hosted/browser-e2e.txt) |
| `node scripts/verify-production.mjs` | Compiled UI, private synthetic notes/case, graph, hashed PDF and local-only requests passed | [local-production-smoke.json](verification-logs/hosted/local-production-smoke.json) |
| `.venv/bin/python scripts/validate-deployment.py` | Render blueprint and Vercel configuration instance passed | [deployment-schema-validation.json](verification-logs/hosted/deployment-schema-validation.json) |

**191 automated tests passed** across backend, frontend and the two browser
suite invocations. The existing Starlette/httpx TestClient deprecation warning
remains; no tests are skipped because of it.

Provider validation fetched only public schemas; no repository code, user
uploads or target data was sent to Vercel/Render. Render's schema validated
normally. Vercel's published schema contains mixed JSON Schema drafts in an
unused experimental-trigger definition. The validator therefore validates the
actual configuration against its declared draft without meta-validating that
unused provider definition; this limitation is recorded in the JSON result.

## Actual browser proof

The hosted browser run used the real compiled React app and API over owned
loopback HTTPS, with a generated test-only certificate. It:

1. Opened the no-sign-in notice and started an anonymous temporary workspace.
2. Verified both synthetic examples and disabled hosted discovery.
3. Uploaded `fixtures/http/upload.har` after the retention/permission checkbox.
4. Verified redacted evidence and an actual downloadable JSON report.
5. Opened an independent browser context and proved cross-session 401/404 denial.
6. Verified a Secure/HttpOnly/SameSite session cookie with no persistent expiry.
7. Captured desktop/mobile upload and retention UI with no document overflow.
8. Ended the session, confirmed deletion and proved the copied old cookie no
   longer grants access.

The actual assertions and count summary are in
[browser-proof.json](verification-logs/hosted/browser-proof.json). No browser
page errors occurred and all observed browser requests were same-origin.

Screenshots:
[desktop upload](verification-logs/hosted/uploads-desktop.png),
[mobile upload](verification-logs/hosted/uploads-mobile.png),
[mobile no-sign-in/retention entry](verification-logs/hosted/session-notice-mobile.png).
The bounded first review and confirmation preserved the existing visual
system; no new global palette or redesign was introduced. Hook notices about
pre-existing palette/type variants were treated as documentation mismatches,
not reasons to restyle unrelated controls. The new 16px entry copy is explicitly
documented in DESIGN.md.

## Important corrections discovered during verification

- Large unbroken text exposed quadratic behavior in the old assignment
  redaction regex. Token-boundary matching and bounded nested URL processing
  now retain redaction while the 262 KB regression finishes within one second.
- Import records are validated beyond top-level types so malformed HTTP/TLS
  payloads cannot defer a crash until analysis/reporting.
- Transactions commit before responses, allowing quota and relationship
  failures to return errors while rolling back the entire upload.
- Imported rule registries and report snapshots are filtered by workspace,
  not globally exposed across sessions.
- Separate Playwright output directories prevent concurrent hosted/local
  verification runs from deleting each other's traces.

## What has not been done

**No actual Vercel or Render service has been deployed**, no Git repository
has been published, and no cloud account/resource has been created. Public
DNS/TLS routing, Vercel rewrite behavior in the user's account, free-tier cold
starts and custom domains require the post-deployment smoke check in
[deployment.md](deployment.md).

This is a bounded public demo, not unlimited SaaS: 25 temporary sessions,
10 assessments per session, 2 MB uploads and a 20 MB evidence/report content
budget. Host restarts/redeploys intentionally discard work. No authentication,
recovery, persistent upload backups, remote-reference fetching, uploaded
executable execution or hosted target scanning is implemented.

The local preview can remain available on `http://127.0.0.1:8765`. The owned
HTTPS verification server and intentionally weak target fixture are stopped
after verification; generated test certificate/key and scratch databases are
removed. The original committed example artifacts remain unchanged.
