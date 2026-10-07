# Deterministic detection rules

Rules are seeded in the database from `services/analysis.py`, available through
`GET /api/rules`, and pinned at `1.0.0` in each generated finding. All rules have
name, category, description, severity, confidence, required evidence,
request type, safety level, remediation and references. No rule calls an LLM.

| Rules | Observed condition | Interpretation |
|---|---|---|
| WS-HDR-001, WS-SEC-001, WS-HDR-003–008 | Missing CSP/HSTS/nosniff/framing/referrer/permissions/opener/resource policies | HTML/HTTPS context gates rules; missing headers are INFO–MEDIUM, not confirmed exploits |
| WS-HDR-009 | Permissive CSP tokens | LOW / MEDIUM confidence; nonce/hash and application context still require review |
| WS-CK-001–004 | Session-like cookie missing Secure/HttpOnly, SameSite review, broad domain | Name heuristics are explicit; values never retained; browser defaults and intended use affect impact |
| WS-CORS-001 | ACAO wildcard | INFO / HIGH confidence; public resources may intentionally allow it |
| WS-CORS-002 | Wildcard plus credentials | LOW / HIGH confidence; browsers reject wildcard credentialed reads |
| WS-CORS-003 | Explicit safe origin reflected with credentials enabled | HIGH / MEDIUM confidence potential weakness; no authenticated data access was demonstrated |
| WS-DISC-001–002 | Configured source-control/environment path plus content signature | HTTP 200 alone is insufficient; no automatic secret-file enumeration |
| WS-DISC-003–006 | Index marker, verbose error, source-map reference, server banner | Contextual information exposure observations, not a vulnerable-version assertion |
| WS-API-001 | Sensitive-looking JSON field names | LOW severity / LOW confidence; analyst must establish authorization and actual impact |
| WS-TLS-001–004 | Expiry, SAN mismatch, trust failure, observed weak protocol/hash/RSA key | Actual certificate/handshake evidence required; no unobserved protocol claims |

Missing HSTS is not reported for HTTP. Framing absence is not flagged when
CSP frame-ancestors is present. Technology fingerprints remain separate
confidence-bearing observations; self-reported banners do not prove versions
are vulnerable. Unusual DNS results remain observations, not vulnerabilities.

Analysis can be rerun on the same persisted transactions without duplicate
findings. Deduplication keys are rule + source evidence + finding title.
New collection creates new source evidence and can legitimately produce new
observations; it does not silently merge historical facts.

## Analyst review and risk

NEW, REVIEWING, NEEDS_VERIFICATION, CONFIRMED, FALSE_POSITIVE and DISMISSED are
analyst statuses. Final dispositions require a written conclusion. Reclassifying
severity/confidence or overriding priority requires a reason. The original
automated severity, confidence and rationale never change.

Risk exposes severity, confidence, internet/internal exposure, asset importance,
authentication context, and described potential impact. Severity weights 0–4
are multiplied by confidence .5/.75/1. Non-informational findings add .5 for
internet exposure, .5 for production importance and .25 when authentication is
not required. Scores cap at 4. Priority thresholds are LOW >0, MEDIUM >=1.75,
HIGH >=2.75 and CRITICAL >=3.75. Impact is explained, not assigned an invented
independent score. The UI/report displays the full formula and any override.
