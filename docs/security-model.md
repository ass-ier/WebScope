# Security model and responsible operation

## Authorization and scope

Only assess systems you own or have explicit written permission to assess.
The application requires an authorization statement and exact target/scope.
Validation is syntactic/policy validation, not a network scan. Passive mode
never sends traffic. SAFE_HTTP collection is a separate, explicit action.
Scope or private-network-policy changes require explicit reauthorization.

Every HTTP request, linked resource, redirect, explicit DNS query and TLS
connection is routed through `NetworkRun`. Its execution budget, inter-attempt
rate spacing, wall-clock duration and per-operation timeout are shared.
Spacing is conservatively measured from completion of the prior operation, so
request preparation or persistence overhead cannot compress actual send gaps.
An OS address lookup counts as one operation; underlying resolver packet
retries are managed by the OS. DNS record resolution has a bounded lifetime.
The budget is per explicit execution, not a lifetime assessment allowance.

Hosts use exact IDNA-normalized matching, never suffix matching. Credentials in
URL authorities are rejected. HTTP(S) only; target port plus 80/443 and explicitly
configured ports are allowed. Excluded hosts take precedence. Excluded paths
match the canonical path and descendants, not similarly named siblings.

For comparison, paths are percent-decoded up to five times, dot segments
collapsed and matrix parameters removed. Backslashes, controls, malformed
escapes and encoded query/fragment delimiters are rejected. The validated
original spelling is sent, never a different inferred path. Thus encoded
aliases cannot bypass an excluded canonical path.

## Network boundary

All resolved IPs must pass the address policy. Mixed safe/unsafe DNS answers
are rejected. Private and loopback addresses require the explicit
`allow_private_network` option in an authorized assessment. Link-local,
unspecified, multicast and reserved addresses remain denied. DNS answers are
pinned for the execution: HTTP connects to the validated IP while preserving
the scoped Host and TLS SNI, preventing a second transport DNS lookup.
Proxy environment variables are ignored. Caller-supplied framing/Host overrides
are prohibited.

Redirects are not automatically followed by httpx. Each hop is independently
validated, rate limited and budgeted. Out-of-scope destinations produce
`REDIRECT_BLOCKED` evidence before a connection. GET, HEAD and OPTIONS are
the only transport methods. Form actions, imported operations, JavaScript API
calls, robots disallows and source maps are inventoried rather than executed.
HTML page links and linked scripts can be followed only within configured depth.
GET is not universally side-effect-free in poorly designed applications:
exclude action URLs before collection and use depth 0 when that is uncertain.

Safe disclosure checks request **only** configured paths after a second
confirmation. No directory dictionary, payload execution, credential attacks,
authentication bypass or target modification is implemented. The optional
CORS probe sends `Origin: https://webscope.invalid`, never target credentials.

Bodies are capped before persistence. Gzip/deflate expansion is bounded too;
unsupported encodings are explicitly omitted. Total HTTP deadlines include
slow/trickling bodies. A truncation marker means the evidence may be incomplete.
TLS verification failures remain failures even when a second, separately
budgeted connection inspects the untrusted certificate. Only the negotiated
protocol is reported; this is not exhaustive cipher/protocol enumeration.

## Local application boundary

Bind to loopback, as the startup scripts do. Host allowlisting prevents DNS
rebinding to an arbitrary attacker domain. Non-local origins and cross-site
fetches are rejected. Mutations require a non-simple `X-WebScope-Request:
workstation` header and JSON content type; there is no permissive CORS policy.
The backend returns a restrictive CSP, no-sniff, no-referrer and no-store.
Request-validation errors do not echo submitted values.

This is **not** a multi-user network service. There is no account login or
protection against a malicious local process running as the same OS user.
Do not expose port 8765 publicly, run as root, or deploy behind a permissive
proxy. Local machine access and backups are part of the trust boundary.

## Redaction and untrusted data

Authorization, cookies, API keys, token/password/credential-bearing structured
fields, URL userinfo/query fields, common assignments, HTML form values,
textarea contents, common XML secret elements and PEM private keys are
redacted at collection/persistence and again on serialization. Duplicate
Set-Cookie values are removed while attributes survive. Binary bodies are
omitted, not displayed as raw downloads. Raw evidence means **redacted raw
text**, never an unredacted alternate view.

Arbitrary unlabelled or proprietary secret formats cannot be reliably identified
by deterministic redaction. Do not supply real credentials or collect private
data expecting this tool to act as a universal data-loss-prevention system.
Review redacted evidence before sharing reports. No credential storage or
authenticated browser-session import is implemented.

Target HTML is displayed as escaped text, never rendered. OpenAPI imports are
size/depth/operation/expansion bounded, accept local refs only, and do not fetch
remote/file refs. XML DTD/entity declarations are rejected. Markdown/HTML
metacharacters are escaped in reports; PDF text uses escaped ReportLab
paragraphs. CSV formula-leading cells receive an apostrophe prefix.

## Evidence integrity

Foreign keys enforce same-assessment relationships. A finding has a mandatory
primary evidence reference; deleting supporting evidence is rejected rather
than orphaning a finding. Database triggers prohibit changes to original
evidence and automated finding facts. Analyst classifications and notes are
separate. See [evidence-model.md](evidence-model.md) and the integrity tests.
