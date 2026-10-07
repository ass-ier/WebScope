# Deploy WebScope on Vercel + Render

This deployment is a **no-sign-in, temporary evidence workstation**, not a
public scanning service. Vercel serves React; Render serves FastAPI and an
ephemeral SQLite workspace database. No paid resource is created by this
repository change. The supplied Render blueprint selects its free web-service
plan and intentionally does **not** attach a persistent disk.

## User-facing behavior

- **Start temporary workspace** creates a random, isolated browser session.
  There are no usernames, passwords, sign-in pages, or recovery links.
- Every new session includes the complete synthetic web investigation:
  22 endpoints, 3 technology observations, 12 transactions, 139 evidence
  records, 44 findings, notes, screenshots and a closed linked case. A second
  synthetic example includes all seven DNS record types and illustrative TLS
  certificate/chain/protocol observations. Synthetic data is explicitly labeled.
- **Upload data** accepts HAR 1.x, complete WebScope JSON exports, and OpenAPI
  3.x JSON. Every upload becomes a separate assessment in that session.
- Uploaded records are bounded, validated, redacted and assigned fresh IDs.
  WebScope snapshots retain source/analyst declarations as **unverified imports**.
  HAR responses are analyzed offline; OpenAPI builds inventory only.
- Reports can be generated and downloaded normally. Original report BLOBs are
  not trusted/imported from arbitrary files; generate fresh reports after import.

### Temporary means temporary

This notice appears before session creation, across the workstation, on the
upload form, and in the deletion confirmation:

> Export anything you want to keep. This workspace expires 24 hours after
> creation. Access ends immediately at expiry; the deletion worker runs every
> minute while the service is running. End session deletes the workspace
> immediately. A hosted restart or redeploy clears it earlier. Closing a tab
> alone does not guarantee immediate server deletion. There is no account or
> recovery link.

Tabs in the **same browser profile share one session cookie**. Separate browser
profiles/incognito contexts get different workspaces. This is browser-session
isolation, not per-tab storage. The cookie is HttpOnly, SameSite=Lax and Secure
in hosted mode, with no persistent cookie expiry. Browser session restoration
can retain session cookies, so tab/browser close is deliberately not used as
a server-deletion promise.

Only a hash of the random session token is stored. Expired tokens lose access
before cleanup. **End session** removes the session's assessments, evidence,
findings, notes, cases, reports and imported rule declarations. Hosted startup
removes all previous temporary workspaces. SQLite secure-delete is enabled,
but this is not a forensic erasure guarantee for infrastructure snapshots or
operator-created backups. Do not attach a persistent disk or enable upload
backups if you want the supplied disposable-storage policy.

## 1. Prepare the repository

Push the repository to a Git provider you control when you are ready. This
implementation does not create a remote repository or push on your behalf.
Render needs the **whole repository**, including `docs/example/assessment.json`,
which is the versioned, already-redacted synthetic source. Do not exclude it
from the deployment checkout.

Choose your intended Vercel project domain, for example
`https://your-webscope.vercel.app`. This example is a configuration value to
replace, not an existing deployment.

## 2. Deploy the Render API

In Render, create a **Blueprint** from the repository's `render.yaml`.
Review the plan and any provider charges before accepting.

The blueprint uses:

| Setting | Value |
|---|---|
| Runtime | Python 3.12.11 |
| Repository root | Whole repository, not `backend/` |
| Build | `pip install -c backend/requirements.lock -e backend` |
| Start | `bash scripts/run-render.sh` |
| Health check | `/api/health` |
| Data directory | `/tmp/webscope` (ephemeral) |
| Workers | One |
| Persistent disk | **None** |
| Mode | `WEBSCOPE_DEPLOYMENT=hosted` |

Enter **`WEBSCOPE_PUBLIC_ORIGIN`** as your exact HTTPS Vercel origin, without a
path or trailing slash. Render's `RENDER_EXTERNAL_HOSTNAME` is automatically
accepted as the API Host. For a custom API domain, additionally set
`WEBSCOPE_ALLOWED_HOSTS` to a comma-separated list of exact hostnames, without
schemes, ports or wildcards.

The startup command validates hosted configuration, applies migration `0004`,
then listens on Render's `$PORT` and `0.0.0.0`. Missing/invalid public-origin
configuration fails startup rather than permitting arbitrary origins.
Do not change `WEBSCOPE_DEPLOYMENT` to `local` on Render.

Save the Render service's HTTPS URL, for example
`https://your-webscope-api.onrender.com`.

## 3. Deploy the Vercel frontend

Import the same repository into Vercel:

| Setting | Value |
|---|---|
| Root Directory | **`frontend`** |
| Framework | Vite |
| Install | `npm ci` |
| Build | `npm run build` |
| Output | `dist` |
| Environment | `WEBSCOPE_API_ORIGIN=https://your-webscope-api.onrender.com` |

`frontend/vercel.mjs` reads `WEBSCOPE_API_ORIGIN` at build time and creates:

- `/api/*` → the Render API;
- `/openapi.json` → the Render schema;
- the SPA fallback for frontend routes;
- security headers and `no-store` for API responses.

The browser sends requests only to the **Vercel origin**. The rewrite forwards
session cookies and responses; no public cross-origin credentialed CORS policy
or browser-visible API secret is required. The frontend does not store the
workspace token in localStorage.

After Vercel assigns the actual production URL, ensure it exactly matches
Render's `WEBSCOPE_PUBLIC_ORIGIN`. If it differs, update Render and redeploy.
Changing the API upstream requires a Vercel redeploy. Preview deployment
origins are intentionally not wildcard-allowed; use a separate API configured
for a specific preview origin if needed.

## 4. Deployment smoke check

1. Open the Vercel URL. Confirm **No sign-in** and the temporary-data notice.
2. Start a session. Confirm both synthetic assessments appear.
3. Upload `fixtures/http/upload.har`. Confirm a new **Uploaded data** assessment
   appears, with redacted response evidence and generated observations.
4. Generate/download JSON and PDF, then open a separate incognito browser.
   The other session must not see the uploaded assessment.
5. Choose **End session → Delete session data**. The old assessment URL should
   no longer grant access. Start again to get fresh synthetic examples.
6. Restart the Render service. Existing temporary sessions should be invalid.

The code/configuration and local HTTPS equivalent are tested, but **no actual
Vercel or Render deployment has been performed** in this task. Provider build
logs, public routing and custom-domain configuration still require this live
smoke check after you deploy.

## Safety and operational limits

Hosted mode rejects discovery and safe-check execution at the service boundary,
even if a client submits an authorized SAFE_HTTP configuration. It never sends
target HTTP, DNS or TLS requests. Collect authorized target evidence using the
local workstation, or export a browser HAR yourself, then upload it.

Defaults intentionally suit a bounded public demonstration:

| Limit | Value |
|---|---:|
| Concurrent temporary workspaces | 25 |
| Assessments per workspace | 10, including the two examples |
| Upload file/document | 2 MB |
| Request envelope | 2.1 MB |
| HAR entries | 200 |
| WebScope records per upload | 5,000 |
| Upload nesting / value count | 40 levels / 40,000 values |
| Stored evidence/report content budget | 20 MB per workspace |
| Lifetime | 24 hours, not extended by activity |

Database/index and derived-observation overhead are additional to the content
budget. Capacity exhaustion returns an explicit error; it does not silently
discard another session. This is not an unlimited multi-tenant SaaS platform.
Use provider rate/WAF limits for public traffic; no-sign-in access cannot
prevent every resource-exhaustion attack.

HAR request bodies are omitted. Supported headers/query/body patterns are
redacted, but opaque secrets and pixels in uploaded PNG evidence cannot be
reliably sanitized. The UI requires upload permission/retention acknowledgement
and advises users to remove sensitive content first.

Free Render services may sleep/cold-start and lose temporary work on restarts.
Do not promise always-on availability, backups, or recovery. A paid instance
can improve availability without attaching a persistent disk, but is a separate
operator decision.

## Local verification

```sh
cd backend
../.venv/bin/pytest -q
../.venv/bin/ruff check app tests alembic
cd ../frontend
npm test -- --reporter=dot
npm run build
cd ..
.venv/bin/python scripts/serve-hosted-fixture.py
```

The last command runs an owned HTTPS fixture at `https://127.0.0.1:8877`, with a
generated test-only certificate and isolated `data/hosted-verification/`.
In another terminal:

```sh
cd frontend
WEBSCOPE_BASE_URL=https://127.0.0.1:8877 \
WEBSCOPE_TEST_HTTPS=1 WEBSCOPE_TEST_HOSTED=1 \
npx playwright test --reporter=list
```

`WEBSCOPE_TEST_HTTPS=1` relaxes certificate verification **only in Playwright's
local fixture run**. It does not alter production target TLS validation.

## Provider references checked

- [Vercel programmatic configuration](https://vercel.com/docs/project-configuration/vercel-ts)
- [Render Blueprint specification](https://render.com/docs/blueprint-spec)
- [Render ephemeral filesystems and disks](https://render.com/docs/disks)
