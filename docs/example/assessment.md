# WebScope Security Assessment

Evidence-Driven Web Application Security Assessment Workstation

## Executive Summary

Assessment: WebScope local fixture assessment

Target: http://127.0.0.1:9998/

Status: COMPLETED

44 automated observations; 1 analyst-confirmed findings.

Severity distribution (excluding dismissed/false-positive): CRITICAL: 0, HIGH: 2, MEDIUM: 5, LOW: 15, INFO: 22

This report distinguishes observed facts from analyst conclusions. It does not claim comprehensive vulnerability coverage.

## Scope

Authorization: I own the loopback WebScope fixture and authorize bounded read-only collection.

{  
  &quot;allowed\_hosts&quot;: \[  
    &quot;127.0.0.1&quot;  
  \],  
  &quot;excluded\_hosts&quot;: \[\],  
  &quot;excluded\_paths&quot;: \[  
    &quot;/admin&quot;,  
    &quot;/payments&quot;  
  \]  
}

Authorized at: 2026-10-07T19:41:47.137164+00:00

{  
  &quot;mode&quot;: &quot;SAFE\_HTTP&quot;,  
  &quot;max\_requests&quot;: 30,  
  &quot;rate\_per\_second&quot;: 10.0,  
  &quot;timeout\_seconds&quot;: 5.0,  
  &quot;max\_body\_bytes&quot;: 262144,  
  &quot;max\_redirects&quot;: 5,  
  &quot;max\_depth&quot;: 1,  
  &quot;max\_duration\_seconds&quot;: 120.0,  
  &quot;links&quot;: true,  
  &quot;javascript&quot;: true,  
  &quot;robots&quot;: true,  
  &quot;sitemap&quot;: true,  
  &quot;availability&quot;: false,  
  &quot;methods&quot;: false,  
  &quot;dns&quot;: false,  
  &quot;tls&quot;: true,  
  &quot;allow\_private\_network&quot;: true,  
  &quot;allowed\_ports&quot;: \[\],  
  &quot;safe\_paths&quot;: \[  
    &quot;/.env&quot;,  
    &quot;/.git/&quot;,  
    &quot;/debug&quot;,  
    &quot;/cors&quot;  
  \],  
  &quot;exposure&quot;: &quot;INTERNAL&quot;,  
  &quot;asset\_importance&quot;: &quot;STANDARD&quot;,  
  &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;  
}

## Methodology

Explicit, scoped, rate-limited read-only collection; deterministic passive analysis of persisted evidence.

GET/HEAD/OPTIONS only. No credential attacks, authentication bypass, exploitation, or target data modification.

A single execution budget covers collection operations and redirects. Errors and limits are recorded in the timeline.

All stored evidence and exports are redacted. Body hashes describe collected bytes, possibly truncated.

TLS results describe only observed certificates and negotiated protocols, not exhaustive protocol support.

## Attack Surface

Host: 127.0.0.1; addresses: 127.0.0.1; evidence cbf205c2-a435-4aa2-a5bb-55c5b628ac04

GET http://127.0.0.1:9998/  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: text/html; charset=utf-8  
Parameters: \[\]; evidence: fec969bb-c018-44a4-9ea2-811b93f94712

GET http://127.0.0.1:9998/login  
Source: HTML; in scope: True; authentication: NOT\_CHALLENGED; content type: text/html; charset=utf-8  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/api/users  
Source: HTML; in scope: True; authentication: NOT\_CHALLENGED; content type: application/json  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/verbose  
Source: HTML; in scope: True; authentication: NOT\_CHALLENGED; content type: text/plain; charset=utf-8  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/redirect-blocked  
Source: HTML; in scope: True; authentication: NOT\_CHALLENGED; content type: not collected  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/admin/private  
Source: HTML; in scope: False; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET https://outside.invalid/resource  
Source: HTML; in scope: False; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

POST http://127.0.0.1:9998/session  
Source: FORM; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[{&quot;name&quot;: &quot;username&quot;, &quot;in&quot;: &quot;body&quot;, &quot;type&quot;: &quot;text&quot;}, {&quot;name&quot;: &quot;password&quot;, &quot;in&quot;: &quot;body&quot;, &quot;type&quot;: &quot;text&quot;}\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/assets/react.production.js  
Source: HTML; in scope: True; authentication: NOT\_CHALLENGED; content type: application/javascript  
Parameters: \[\]; evidence: 5c0279ed-81fe-4f6b-b498-18c0af431558

GET http://127.0.0.1:9998/robots.txt  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: text/plain; charset=utf-8  
Parameters: \[\]; evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

GET http://127.0.0.1:9998/api/docs  
Source: ROBOTS; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

GET http://127.0.0.1:9998/sitemap.xml  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: application/xml  
Parameters: \[\]; evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

GET http://127.0.0.1:9998/catalog  
Source: SITEMAP; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

GET http://127.0.0.1:9998/api/profile  
Source: JAVASCRIPT; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: 03466307-9ad2-433b-a487-abb782f9bb6a

GET http://127.0.0.1:9998/assets/app.js.map  
Source: JAVASCRIPT; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[\]; evidence: 03466307-9ad2-433b-a487-abb782f9bb6a

GET http://127.0.0.1:9998/.env  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: text/plain; charset=utf-8  
Parameters: \[\]; evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

GET http://127.0.0.1:9998/.git/  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: text/plain; charset=utf-8  
Parameters: \[\]; evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

GET http://127.0.0.1:9998/debug  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: text/html; charset=utf-8  
Parameters: \[\]; evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

GET http://127.0.0.1:9998/cors  
Source: HTTP; in scope: True; authentication: NOT\_CHALLENGED; content type: application/json  
Parameters: \[\]; evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

POST http://127.0.0.1:9998/manual-inventory  
Source: MANUAL; in scope: True; authentication: UNKNOWN; content type: not collected  
Parameters: \[{&quot;name&quot;: &quot;filter&quot;, &quot;in&quot;: &quot;body&quot;, &quot;type&quot;: &quot;string&quot;}\]; evidence: deb84e15-fc39-4ea1-82d7-b319ef378328

GET http://127.0.0.1:9998/api/orders  
Source: OPENAPI; in scope: True; authentication: DECLARED\_REQUIRED; content type: not collected  
Parameters: \[{&quot;name&quot;: &quot;limit&quot;, &quot;in&quot;: &quot;query&quot;, &quot;schema&quot;: {&quot;type&quot;: &quot;integer&quot;}}\]; evidence: d76959f6-69b6-4e65-bc28-d1e0831ea81a

POST http://127.0.0.1:9998/api/orders  
Source: OPENAPI; in scope: True; authentication: DECLARED\_REQUIRED; content type: not collected  
Parameters: \[\]; evidence: d76959f6-69b6-4e65-bc28-d1e0831ea81a

## Technology Inventory

Express / Backend / version not established / confidence MEDIUM  
Basis: Self-reported HTTP banner contains Express; banners can be spoofed  
Evidence: c1f2f991-a0a5-41b7-adaf-d403358ae72f

React / Frontend / version not established / confidence MEDIUM  
Basis: Observed markup/asset marker: react.production.js  
Evidence: 4bf6e234-946c-4f6b-94f5-deb031698e9d

WebScope Fixture / CMS / version not established / confidence LOW  
Basis: Self-reported generator metadata  
Evidence: e42a992f-70a6-4413-9197-f3ffcf6d6eb4

## Security Controls

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: fec969bb-c018-44a4-9ea2-811b93f94712

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57

content-security-policy: absent; content-security-policy absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

strict-transport-security: absent; strict-transport-security absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

x-content-type-options: absent; x-content-type-options absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

x-frame-options: absent; x-frame-options absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

referrer-policy: absent; referrer-policy absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

permissions-policy: absent; permissions-policy absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 500 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab

content-security-policy: absent; content-security-policy absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

strict-transport-security: absent; strict-transport-security absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

x-content-type-options: absent; x-content-type-options absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

x-frame-options: absent; x-frame-options absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

referrer-policy: absent; referrer-policy absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

permissions-policy: absent; permissions-policy absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 307 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: f7dcf338-7344-496d-8829-4e55485a47cf

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability. Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e

content-security-policy: absent; content-security-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

strict-transport-security: absent; strict-transport-security absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

x-content-type-options: absent; x-content-type-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

x-frame-options: absent; x-frame-options absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

referrer-policy: absent; referrer-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

permissions-policy: absent; permissions-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

cross-origin-opener-policy: absent; cross-origin-opener-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

cross-origin-resource-policy: absent; cross-origin-resource-policy absent on 200 HTTP response. Not flagged: resource/transport context or an alternative control makes the missing-header rule inapplicable. Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b

Cookie session attributes (values redacted): {&quot;secure&quot;: false, &quot;httponly&quot;: false, &quot;samesite&quot;: &quot;None&quot;, &quot;domain&quot;: null, &quot;path&quot;: &quot;/&quot;, &quot;expires&quot;: null, &quot;max-age&quot;: null, &quot;value&quot;: &quot;\[REDACTED\]&quot;}; evidence fec969bb-c018-44a4-9ea2-811b93f94712

Cookie preferences attributes (values redacted): {&quot;secure&quot;: true, &quot;httponly&quot;: true, &quot;samesite&quot;: &quot;Lax&quot;, &quot;domain&quot;: null, &quot;path&quot;: &quot;/&quot;, &quot;expires&quot;: null, &quot;max-age&quot;: null, &quot;value&quot;: &quot;\[REDACTED\]&quot;}; evidence fec969bb-c018-44a4-9ea2-811b93f94712

## Automated Findings

WS-HDR-001 / Missing content-security-policy

Automated severity: MEDIUM; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing content-security-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Constrain script/resource origins with a tested Content-Security-Policy.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-003 / Missing x-content-type-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing x-content-type-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set X-Content-Type-Options: nosniff.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-004 / Missing x-frame-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing x-frame-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-005 / Missing referrer-policy

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing referrer-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-006 / Missing permissions-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing permissions-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Restrict browser features that this application does not require.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-007 / Missing cross-origin-opener-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing cross-origin-opener-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Consider same-origin opener isolation where compatible.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-008 / Missing cross-origin-resource-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Missing cross-origin-resource-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Choose a resource policy appropriate to intended cross-origin use.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-CK-001 / Cookie session: Secure absent

Automated severity: MEDIUM; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Cookie session has a session-like name and no Secure attribute. The name is a heuristic, not proof of authentication use.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Session-like cookie without Secure

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set Secure on session cookies and serve the application over HTTPS.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-CK-002 / Cookie session: HttpOnly absent

Automated severity: LOW; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Cookie session has no HttpOnly attribute; actual use requires analyst verification.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Session-like cookie without HttpOnly

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set HttpOnly unless client-side access is explicitly required.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-CK-003 / Cookie session: SameSite review

Automated severity: LOW; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Cookie session: SameSite=None, Secure=False. Browser defaults and cross-site requirements affect risk.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Cookie SameSite requires review

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Choose Lax or Strict where possible; SameSite=None requires Secure.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: fec969bb-c018-44a4-9ea2-811b93f94712; endpoint: eefd4da9-d67e-4ceb-b50b-106f62a47655; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 03a211a7-c7c2-4076-80ba-8261360f302a; endpoint: 683bfd36-96ee-45f9-b951-ec37ad8cec26; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/robots.txt

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: aa18999f-3222-43c4-a2af-b1bb1485cd6d; endpoint: b6f303a7-1beb-4f12-bc5f-9a187de0fb17; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/sitemap.xml

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-001 / Missing content-security-policy

Automated severity: MEDIUM; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing content-security-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Constrain script/resource origins with a tested Content-Security-Policy.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-003 / Missing x-content-type-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing x-content-type-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set X-Content-Type-Options: nosniff.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-004 / Missing x-frame-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing x-frame-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-005 / Missing referrer-policy

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing referrer-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-006 / Missing permissions-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing permissions-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Restrict browser features that this application does not require.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-007 / Missing cross-origin-opener-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing cross-origin-opener-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Consider same-origin opener isolation where compatible.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-008 / Missing cross-origin-resource-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Missing cross-origin-resource-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Choose a resource policy appropriate to intended cross-origin use.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: a67c26b6-a2cc-465d-b9ca-274fa09faf0a; endpoint: 63d3ad51-0d84-4006-9510-1298f0e797a8; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/login

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-CORS-002 / Wildcard origin with credentials

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: ACAO=\*, ACAC=true. Wildcard public resources may be intentional; browsers reject wildcard credentialed reads.

Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57; endpoint: 2f868bd9-1c9a-450a-96cc-a2c99fd7072e; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/api/users

Description: Wildcard origin with credentials

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Use an explicit trusted origin allowlist. Browsers reject wildcard credentialed responses.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57; endpoint: 2f868bd9-1c9a-450a-96cc-a2c99fd7072e; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/api/users

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-API-001 / Sensitive-looking response fields

Automated severity: LOW; confidence: LOW; analyst status: NEW

Why WebScope flagged this: Response includes sensitive-looking field names: api\_token. Values are redacted; field names alone do not prove unauthorized disclosure.

Evidence: 6a411f04-8e9f-403a-af84-153fa3b41f57; endpoint: 2f868bd9-1c9a-450a-96cc-a2c99fd7072e; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/api/users

Description: Sensitive-looking response fields

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Review authorization and data minimization for the observed response fields.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-004 / Verbose server error observed

Automated severity: LOW; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Diagnostic stack/error marker in collected response.

Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab; endpoint: 28982931-3fb3-45b5-bcb0-fe4fa79792c9; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/verbose

Description: Verbose server error observed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Return generic errors externally and retain diagnostics only in restricted logs.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 047f2de6-faf1-49d1-916a-d75ebc72caab; endpoint: 28982931-3fb3-45b5-bcb0-fe4fa79792c9; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/verbose

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: d1f132e2-b82e-4a38-a697-d3e4dca0c289; endpoint: 5c66af4b-9b14-4c97-816d-629e0e3a0d33; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/redirect-blocked

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-005 / Source map reference exposed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Source map reference in collected JavaScript; referenced map is not automatically fetched.

Evidence: f7dcf338-7344-496d-8829-4e55485a47cf; endpoint: 30339f4d-98f9-4e5e-bed2-f29668634cab; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/assets/react.production.js

Description: Source map reference exposed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Review production source maps for unintended source or metadata disclosure.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: f7dcf338-7344-496d-8829-4e55485a47cf; endpoint: 30339f4d-98f9-4e5e-bed2-f29668634cab; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/assets/react.production.js

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4; endpoint: 86ead582-eeed-4965-87db-98e4e20181a6; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/.env

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-002 / Potential environment-file exposure

Automated severity: HIGH; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Explicitly configured environment-file path returned configuration-shaped text; values were redacted.

Evidence: 9ce79b33-4360-4309-9db0-f569e489a2d4; endpoint: 86ead582-eeed-4965-87db-98e4e20181a6; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/.env

Description: Potential environment-file exposure

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Deny public access to environment files; investigate exposure and rotate affected secrets if confirmed.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8; endpoint: 2c7a732a-1c35-4ab1-b2b5-ed5aa52000b4; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/.git/

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-001 / Potential source-control metadata exposure

Automated severity: MEDIUM; confidence: MEDIUM; analyst status: NEW

Why WebScope flagged this: Configured source-control path returned a source-control signature, not merely HTTP 200.

Evidence: ca70165b-385e-4cb3-bcf5-46dbc61d1be8; endpoint: 2c7a732a-1c35-4ab1-b2b5-ed5aa52000b4; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/.git/

Description: Potential source-control metadata exposure

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Remove source-control metadata from the public web root.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-001 / Missing content-security-policy

Automated severity: MEDIUM; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: content-security-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing content-security-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Constrain script/resource origins with a tested Content-Security-Policy.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-003 / Missing x-content-type-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-content-type-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing x-content-type-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set X-Content-Type-Options: nosniff.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-004 / Missing x-frame-options

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: x-frame-options absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing x-frame-options

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-005 / Missing referrer-policy

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: referrer-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing referrer-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-006 / Missing permissions-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: permissions-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing permissions-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Restrict browser features that this application does not require.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-007 / Missing cross-origin-opener-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-opener-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing cross-origin-opener-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Consider same-origin opener isolation where compatible.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-HDR-008 / Missing cross-origin-resource-policy

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: cross-origin-resource-policy absent on 200 HTTP response. Review in application context; absence does not demonstrate exploitability.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Missing cross-origin-resource-policy

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Choose a resource policy appropriate to intended cross-origin use.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-003 / Directory listing observed

Automated severity: LOW; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Directory index marker in collected response.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Directory listing observed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Disable unintended directory indexes.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 555011e6-5d6d-43b6-8030-06317d643d3e; endpoint: fe4450ed-14ee-4ce9-ac0e-2fcde6eea809; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/debug

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-CORS-003 / Potential unsafe credentialed origin reflection

Automated severity: HIGH; confidence: MEDIUM; analyst status: CONFIRMED

Why WebScope flagged this: The explicit safe Origin probe was reflected with credentials enabled. No credentials were sent and no authenticated data access was demonstrated.

Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b; endpoint: 0ad4759e-2047-4a9b-a33f-5821f6f65d24; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/cors

Description: Potential unsafe credentialed origin reflection

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Validate Origin against an exact trusted allowlist; manually verify sensitive authenticated impact.

References: https://owasp.org/www-project-web-security-testing-guide/

WS-DISC-006 / Server technology banner disclosed

Automated severity: INFO; confidence: HIGH; analyst status: NEW

Why WebScope flagged this: Self-reported server/runtime banner observed; no vulnerable-version claim.

Evidence: 06ccc625-4223-4d47-9d73-3314144dd19b; endpoint: 0ad4759e-2047-4a9b-a33f-5821f6f65d24; rule version: 1.0.0

Affected asset: http://127.0.0.1:9998/cors

Description: Server technology banner disclosed

Impact: Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.

Remediation: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

References: https://owasp.org/www-project-web-security-testing-guide/

## Evidence

Evidence excerpts below are capped at 800 characters per item. The complete redacted structured/raw record and relationships are available in the companion assessment JSON and workstation.

ee6bfeff-043f-4ec1-985e-2d29540d4667 / TLS\_NOT\_APPLICABLE / 2026-10-07T19:41:47.399605+00:00  
Source: http://127.0.0.1:9998/  
TLS collection requires an explicitly configured HTTPS target  
Integrity SHA-256: 83a7b1fe0dd74ad231ceaf2157b366b3bfd69469d40f944e9e50f04b6a5d80e2  
Excerpt: {&quot;destination&quot;: &quot;http://127.0.0.1:9998/&quot;, &quot;code&quot;: &quot;TLS\_NOT\_APPLICABLE&quot;}

4cf04a06-4ab0-4c65-bdd7-1ff7251f6ea5 / HTTP\_REQUEST / 2026-10-07T19:41:47.401147+00:00  
Source: http://127.0.0.1:9998/  
GET request  
Integrity SHA-256: f4735de6d9d2749cf0607156f9220c8470b398b9f5dd02850b19abd0b1292158  
Excerpt: GET http://127.0.0.1:9998/ HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

fec969bb-c018-44a4-9ea2-811b93f94712 / HTTP\_RESPONSE / 2026-10-07T19:41:47.421600+00:00  
Source: http://127.0.0.1:9998/  
HTTP 200 response  
Integrity SHA-256: 9f459f9d20cda30fd372517f365798a311c2a879d877bbbf059eba612bca1040  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:46 GMT  
server: uvicorn  
content-length: 657  
content-type: text/html; charset=utf-8  
set-cookie: session=\[REDACTED\]; Path=/; SameSite=None  
preferences=\[REDACTED\]; Path=/; Secure; HttpOnly; SameSite=Lax  
x-powered-by: Express  
  
&lt;!doctype html&gt;&lt;html&gt;&lt;head&gt;  
    &lt;title&gt;WebScope Test Application&lt;/title&gt;&lt;meta name=&quot;generator&quot; content=&quot;WebScope Fixture&quot;&gt;  
    &lt;/head&gt;&lt;body&gt;&lt;h1&gt;FOR LOCAL SECURITY TESTING ONLY&lt;/h1&gt;  
    &lt;a href=&quot;/login&quot;&gt;Login fixture&lt;/a&gt;&lt;a href=&quot;/api/users&quot;&gt;Synthetic API&lt;/a&gt;  
    &lt;a href=&quot;/verbose&quot;&gt;Verbose error&lt;/a&gt;&lt;a href=&quot;/redirect-blocked&quot;&gt;Blocked redirect&lt;/a&gt;  
    &lt;a href=&quot;/admin/private&quot;&gt;Excluded fixture&lt;/a&gt;&lt;a href=&quot;https://outside.invalid/resource&quot;&gt;External (never fetch)&lt;/a&gt;  
    &lt;form action=&quot;/session&quot; method=&quot;POST&quot;&gt;&lt;input name=&quot;username&quot;&gt;&lt;inpu

5c0279ed-81fe-4f6b-b498-18c0af431558 / HTML / 2026-10-07T19:41:47.426134+00:00  
Source: http://127.0.0.1:9998/  
Collected HTML (redacted)  
Integrity SHA-256: d9e13d889b6c6bb96bd7fce30c8bc1298278e1184fe307b319f49e6560d07eb9  
Excerpt: &lt;!doctype html&gt;&lt;html&gt;&lt;head&gt;  
    &lt;title&gt;WebScope Test Application&lt;/title&gt;&lt;meta name=&quot;generator&quot; content=&quot;WebScope Fixture&quot;&gt;  
    &lt;/head&gt;&lt;body&gt;&lt;h1&gt;FOR LOCAL SECURITY TESTING ONLY&lt;/h1&gt;  
    &lt;a href=&quot;/login&quot;&gt;Login fixture&lt;/a&gt;&lt;a href=&quot;/api/users&quot;&gt;Synthetic API&lt;/a&gt;  
    &lt;a href=&quot;/verbose&quot;&gt;Verbose error&lt;/a&gt;&lt;a href=&quot;/redirect-blocked&quot;&gt;Blocked redirect&lt;/a&gt;  
    &lt;a href=&quot;/admin/private&quot;&gt;Excluded fixture&lt;/a&gt;&lt;a href=&quot;https://outside.invalid/resource&quot;&gt;External (never fetch)&lt;/a&gt;  
    &lt;form action=&quot;/session&quot; method=&quot;POST&quot;&gt;&lt;input name=&quot;username&quot;&gt;&lt;input name=&quot;password&quot; value=&quot;\[REDACTED\]&quot;&gt;&lt;/form&gt;  
    &lt;script src=&quot;/assets/react.production.js&quot;&gt;&lt;/script&gt;&lt;/body&gt;&lt;/html&gt;

c1f2f991-a0a5-41b7-adaf-d403358ae72f / TECHNOLOGY\_OBSERVATION / 2026-10-07T19:41:47.435126+00:00  
Source: http://127.0.0.1:9998/  
Technology indicator: Express  
Integrity SHA-256: 9a06dc58eebb76cff3a1aae208a0b473a71b2c863c73428d5d97b4a4471a39e5  
Excerpt: {&quot;name&quot;: &quot;Express&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;rationale&quot;: &quot;Self-reported HTTP banner contains Express; banners can be spoofed&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

4bf6e234-946c-4f6b-94f5-deb031698e9d / TECHNOLOGY\_OBSERVATION / 2026-10-07T19:41:47.436493+00:00  
Source: http://127.0.0.1:9998/  
Technology indicator: React  
Integrity SHA-256: d0c7eea376f765ea732997adbc69cb95f2257535aed111e3f081ef1216bce7fd  
Excerpt: {&quot;name&quot;: &quot;React&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;rationale&quot;: &quot;Observed markup/asset marker: react.production.js&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

e42a992f-70a6-4413-9197-f3ffcf6d6eb4 / TECHNOLOGY\_OBSERVATION / 2026-10-07T19:41:47.437163+00:00  
Source: http://127.0.0.1:9998/  
Technology indicator: WebScope Fixture  
Integrity SHA-256: 1b907509590a6bf85a911b69058cd1e1d0bcd75d5d6a475b0e5ba97af4f88dcc  
Excerpt: {&quot;name&quot;: &quot;WebScope Fixture&quot;, &quot;confidence&quot;: &quot;LOW&quot;, &quot;rationale&quot;: &quot;Self-reported generator metadata&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

16cdd24c-e443-4e4a-adb1-c5fba49d5cc5 / HTTP\_REQUEST / 2026-10-07T19:41:47.502846+00:00  
Source: http://127.0.0.1:9998/robots.txt  
GET request  
Integrity SHA-256: 52e804a82907870964f64d37beb4e60a4e1c013f07f5d76fbe765d481f5eb97d  
Excerpt: GET http://127.0.0.1:9998/robots.txt HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

03a211a7-c7c2-4076-80ba-8261360f302a / HTTP\_RESPONSE / 2026-10-07T19:41:47.513132+00:00  
Source: http://127.0.0.1:9998/robots.txt  
HTTP 200 response  
Integrity SHA-256: c4f48a17686f8445c637ca1ebe13cdf8e31b7a95013663aadc9e5f79b762354e  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:46 GMT  
server: uvicorn  
content-length: 56  
content-type: text/plain; charset=utf-8  
  
User-agent: \*  
Disallow: /admin/private  
Allow: /api/docs  


f7b88c9d-a076-4564-bdc6-7a9fef57b19c / HTTP\_REQUEST / 2026-10-07T19:41:47.602796+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
GET request  
Integrity SHA-256: f0b630cda5e56c295388618da0d6a1775b28c82c33f1869bd86da610a7256a72  
Excerpt: GET http://127.0.0.1:9998/sitemap.xml HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

aa18999f-3222-43c4-a2af-b1bb1485cd6d / HTTP\_RESPONSE / 2026-10-07T19:41:47.616047+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
HTTP 200 response  
Integrity SHA-256: 333d6dc20fdb8e36cc830707074a943a9af2e9c173660e3d37a644faf2fe7304  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:46 GMT  
server: uvicorn  
content-length: 99  
content-type: application/xml  
  
&lt;urlset xmlns=&quot;http://www.sitemaps.org/schemas/sitemap/0.9&quot;&gt;&lt;url&gt;&lt;loc&gt;/catalog&lt;/loc&gt;&lt;/url&gt;&lt;/urlset&gt;

9e4aa029-9dfd-4bac-9301-072e86b7d90b / HTTP\_REQUEST / 2026-10-07T19:41:47.705291+00:00  
Source: http://127.0.0.1:9998/login  
GET request  
Integrity SHA-256: a1be11ac99ae5ad3deb6e6aab5dbaa2de1ca4a34d25b70f9ec8b6862d94e1848  
Excerpt: GET http://127.0.0.1:9998/login HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

a67c26b6-a2cc-465d-b9ca-274fa09faf0a / HTTP\_RESPONSE / 2026-10-07T19:41:47.722195+00:00  
Source: http://127.0.0.1:9998/login  
HTTP 200 response  
Integrity SHA-256: 95f7a720d6fe1239ea00de717d0fe3d0d31a8a5cd5cf91a93705f7136f9b1c0f  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:46 GMT  
server: uvicorn  
content-length: 97  
content-type: text/html; charset=utf-8  
  
&lt;html&gt;&lt;title&gt;Login fixture&lt;/title&gt;&lt;body&gt;No authentication is implemented or tested.&lt;/body&gt;&lt;/html&gt;

be852eae-1d55-49d8-ae3d-9ed3666f084a / HTML / 2026-10-07T19:41:47.726400+00:00  
Source: http://127.0.0.1:9998/login  
Collected HTML (redacted)  
Integrity SHA-256: e5e0e9931f195b160e45691d49b13b6422954f01312bdb8554aeb1ff20f54127  
Excerpt: &lt;html&gt;&lt;title&gt;Login fixture&lt;/title&gt;&lt;body&gt;No authentication is implemented or tested.&lt;/body&gt;&lt;/html&gt;

666fcffd-840a-46db-8876-bf90fa0860a5 / HTTP\_REQUEST / 2026-10-07T19:41:47.808945+00:00  
Source: http://127.0.0.1:9998/api/users  
GET request  
Integrity SHA-256: 163c892f639f8e5891df6a8016c3e8caa49381d4aed7cc34ae1a34374956b5ad  
Excerpt: GET http://127.0.0.1:9998/api/users HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

6a411f04-8e9f-403a-af84-153fa3b41f57 / HTTP\_RESPONSE / 2026-10-07T19:41:47.828637+00:00  
Source: http://127.0.0.1:9998/api/users  
HTTP 200 response  
Integrity SHA-256: b85ea55a217643b993ea61f94f4581b75000c3bf03c3883c072821155801bf62  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
access-control-allow-origin: \*  
access-control-allow-credentials: true  
content-length: 78  
content-type: application/json  
  
{  
  &quot;users&quot;: \[  
    {  
      &quot;id&quot;: 1,  
      &quot;name&quot;: &quot;Synthetic Analyst&quot;  
    }  
  \],  
  &quot;api\_token&quot;: &quot;\[REDACTED\]&quot;  
}

64ad3b80-1ab3-4e8e-9535-462c0783937d / HTTP\_REQUEST / 2026-10-07T19:41:47.911452+00:00  
Source: http://127.0.0.1:9998/verbose  
GET request  
Integrity SHA-256: 38aceeaad5d651d18301a4168d86ad83a1abb72501b45deb3d0aa6bf3cf8b8ac  
Excerpt: GET http://127.0.0.1:9998/verbose HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

047f2de6-faf1-49d1-916a-d75ebc72caab / HTTP\_RESPONSE / 2026-10-07T19:41:47.930555+00:00  
Source: http://127.0.0.1:9998/verbose  
HTTP 500 response  
Integrity SHA-256: af9348b24f37a71cf2e0eb4ff43d37b3106b429a89fb1808d6b49f836c084ea6  
Excerpt: HTTP/1.1 500  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
content-length: 74  
content-type: text/plain; charset=utf-8  
  
Traceback (most recent call last):  
FixtureError: synthetic diagnostic only

84a20d6b-846f-459a-a782-e7bf1b410c5e / HTTP\_REQUEST / 2026-10-07T19:41:48.013793+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
GET request  
Integrity SHA-256: 00887607b6546a9bf81a58295e5b385ac9a2474bb5ed40f9b9be4a4a4e00f4b5  
Excerpt: GET http://127.0.0.1:9998/redirect-blocked HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

d1f132e2-b82e-4a38-a697-d3e4dca0c289 / HTTP\_RESPONSE / 2026-10-07T19:41:48.032837+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
HTTP 307 response  
Integrity SHA-256: d94c7385f20e43efe17c99c98db2da49765ccc228deab1b6b01835cc6460cdc9  
Excerpt: HTTP/1.1 307  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
content-length: 0  
location: http://localhost:9989/never-requested  
  
\[Binary body omitted\]

2a9013d2-b7b1-4e8b-8aed-6c79919b07f2 / REDIRECT\_BLOCKED / 2026-10-07T19:41:48.038939+00:00  
Source: http://localhost:9989/never-requested  
Redirect destination blocked by scope policy  
Integrity SHA-256: d7ffe7b09b3e067d1f9c93dbb5c986012bc01f7820c7880c3a274c5c8df6d787  
Excerpt: {&quot;destination&quot;: &quot;http://localhost:9989/never-requested&quot;, &quot;code&quot;: &quot;REDIRECT\_BLOCKED&quot;}

d450e83b-b79f-4d5a-8f82-b953fff08b36 / HTTP\_REQUEST / 2026-10-07T19:41:48.117298+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
GET request  
Integrity SHA-256: 15aa553fa2bdd3252c30df64ab23990a9160ca8c9521652a74b0cbe07cf4ce3e  
Excerpt: GET http://127.0.0.1:9998/assets/react.production.js HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity

f7dcf338-7344-496d-8829-4e55485a47cf / HTTP\_RESPONSE / 2026-10-07T19:41:48.135213+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
HTTP 200 response  
Integrity SHA-256: d54ff85eb8211c27d1d9b8c117e3a8e166a6639a0b6a9a34fe89444316d2b141  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
content-length: 105  
content-type: application/javascript  
  
/\* Synthetic technology marker, not React code. \*/  
fetch(&quot;/api/profile&quot;);  
//# sourceMappingURL=app.js.map

03466307-9ad2-433b-a487-abb782f9bb6a / JAVASCRIPT / 2026-10-07T19:41:48.139358+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Collected JavaScript (never executed)  
Integrity SHA-256: 684fcea3c4fb4f7259787ba6510490735ebdc6610c70fe55a8e5998c24f3104d  
Excerpt: /\* Synthetic technology marker, not React code. \*/  
fetch(&quot;/api/profile&quot;);  
//# sourceMappingURL=app.js.map

cbf205c2-a435-4aa2-a5bb-55c5b628ac04 / ENDPOINT / 2026-10-07T19:41:48.144512+00:00  
Source: http://127.0.0.1:9998/  
Scoped discovered host  
Integrity SHA-256: a358053f9d6afbc0daf6a6b2f1b178ee4d13d21b3b1d4f487f38080852b0f61a  
Excerpt: {&quot;hostname&quot;: &quot;127.0.0.1&quot;, &quot;addresses&quot;: \[&quot;127.0.0.1&quot;\]}

f7acd137-5e0d-4c2f-b013-65f9dd597df7 / HEADER / 2026-10-07T19:41:48.152639+00:00  
Source: http://127.0.0.1:9998/  
Header observation: content-security-policy  
Integrity SHA-256: 99ec26abc8a5de676febde14a28ab26c23556358982a4ce9acd0dd1b5b043c15  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

01e9d366-3250-4838-ad41-3b450c182873 / HEADER / 2026-10-07T19:41:48.157461+00:00  
Source: http://127.0.0.1:9998/  
Header observation: strict-transport-security  
Integrity SHA-256: 26c309f3ab507f4e87a56ca5310dad6571a27fbfa1395c26a102c8535ffe1ec3  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

ccd3b44a-01c6-40cf-9e5b-27218bf82a46 / HEADER / 2026-10-07T19:41:48.158325+00:00  
Source: http://127.0.0.1:9998/  
Header observation: x-content-type-options  
Integrity SHA-256: ffe095e5272ebdbd9c338c467692176aa41d12bc162d7ac9a8530c883d82a268  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

c69e1819-40a7-4ca3-a4bb-462f7f913c71 / HEADER / 2026-10-07T19:41:48.160408+00:00  
Source: http://127.0.0.1:9998/  
Header observation: x-frame-options  
Integrity SHA-256: b08790ec86f13a446d76544901fd802454a6209d170e8e743608a8c82a606cc4  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

54b07af6-2be3-4c8b-b600-8438c7c6cf24 / HEADER / 2026-10-07T19:41:48.162435+00:00  
Source: http://127.0.0.1:9998/  
Header observation: referrer-policy  
Integrity SHA-256: 6a1fdce440774acfc9ef9a87ce56cdebdeee06546e78d51464aac54970c706ab  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

b1fe6f4c-6646-4422-83f9-07ae56e2e820 / HEADER / 2026-10-07T19:41:48.164525+00:00  
Source: http://127.0.0.1:9998/  
Header observation: permissions-policy  
Integrity SHA-256: abb7580665749ff69ad33a4b8a7596429dcbd8fe23bc397d20e5aae21473c161  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

e27a232d-171c-448b-a0f9-244c94d9667c / HEADER / 2026-10-07T19:41:48.166334+00:00  
Source: http://127.0.0.1:9998/  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 52c6724aaea38ba736006e38d7e516a85a5bd7a154e663dbcbda8f397100d581  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

4df19de2-621b-4cd2-8f85-76ba4ca979fe / HEADER / 2026-10-07T19:41:48.168184+00:00  
Source: http://127.0.0.1:9998/  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: f0c128d93f614eaa6ecb1efd49a1116b0fafcf965d29a1a82559a3294fb9dfbd  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

1df10c27-3e04-4885-8de4-01f46ef37a93 / COOKIE / 2026-10-07T19:41:48.172615+00:00  
Source: http://127.0.0.1:9998/  
Cookie attributes: session  
Integrity SHA-256: 4dad86824e4230b04902ee58cc402e87ce71d336fa9ddd2908cd8e6e10221e3d  
Excerpt: {&quot;name&quot;: &quot;session&quot;, &quot;attributes&quot;: {&quot;secure&quot;: false, &quot;httponly&quot;: false, &quot;samesite&quot;: &quot;None&quot;, &quot;domain&quot;: null, &quot;path&quot;: &quot;/&quot;, &quot;expires&quot;: null, &quot;max-age&quot;: null, &quot;value&quot;: &quot;\[REDACTED\]&quot;}, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2ed82bf5-a1e6-406c-881b-9d29442cf00b / COOKIE / 2026-10-07T19:41:48.176509+00:00  
Source: http://127.0.0.1:9998/  
Cookie attributes: preferences  
Integrity SHA-256: 8a4ca79b1901fbfa895709fd03525d6730c79623d38a0a37675e42ec59378e06  
Excerpt: {&quot;name&quot;: &quot;preferences&quot;, &quot;attributes&quot;: {&quot;secure&quot;: true, &quot;httponly&quot;: true, &quot;samesite&quot;: &quot;Lax&quot;, &quot;domain&quot;: null, &quot;path&quot;: &quot;/&quot;, &quot;expires&quot;: null, &quot;max-age&quot;: null, &quot;value&quot;: &quot;\[REDACTED\]&quot;}, &quot;source\_evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

c21b82bd-31fb-4581-a900-d100c25fc291 / HEADER / 2026-10-07T19:41:48.178569+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: content-security-policy  
Integrity SHA-256: fa1b882cf0b40c6125bdca5ddd8ad8fb6f76bd5a0774c407cdb8d613b1769613  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

1fda88bc-d2ec-4fc3-8978-4db03fe34a19 / HEADER / 2026-10-07T19:41:48.179198+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: strict-transport-security  
Integrity SHA-256: 97c3e73ce4e0386094b0655616ac7654f3236ecd8abedcea8306e7923ccb610b  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

aac6b64a-1ff3-46e2-95b1-4cfd02409355 / HEADER / 2026-10-07T19:41:48.179759+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: x-content-type-options  
Integrity SHA-256: 07a1e4dec275a760aa287ffc96b8cbba1c593dfe93c55e6c3b106fe81f8361e3  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

74c16fd1-3f0d-42da-96a2-600f56f12d56 / HEADER / 2026-10-07T19:41:48.180289+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: x-frame-options  
Integrity SHA-256: b07140f3cfc7600a8c83cc3b55e5e74702845f740447e0f9d1e01cba8e08a050  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

30814609-b69d-439b-8d0d-bd0ff701e469 / HEADER / 2026-10-07T19:41:48.180797+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: referrer-policy  
Integrity SHA-256: f434a551908518c5c37be945b7bb00cd105eb069b33d33722d53159272c8faab  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

f08affd4-ec5d-4010-96c3-ea51452e8011 / HEADER / 2026-10-07T19:41:48.181307+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: permissions-policy  
Integrity SHA-256: 119a985801e872ebb5b01b988e9d5c0a8c2bda7e33d29dc2e5d0ec962fedfdff  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

872d5024-ef0d-4306-95bf-0bed5074d5e1 / HEADER / 2026-10-07T19:41:48.181858+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 877dd41492269f04fa52a37e03af9627791b405de6e688a9073398d93cfa6643  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

f5bf98ec-5bca-4fa4-8ee7-71aee1fca6d1 / HEADER / 2026-10-07T19:41:48.182427+00:00  
Source: http://127.0.0.1:9998/robots.txt  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 6f348d68fe8daffcac815a222219fbce1680d8bdd1987ebb9ca87fb57b133a8a  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

aab63247-8cac-43fc-99dc-9cad00733c9e / HEADER / 2026-10-07T19:41:48.184297+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: content-security-policy  
Integrity SHA-256: b288c88323f818e913d27b8a83b7279396a00f5c4e560b01e81718d55d4c066f  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

ce22ec74-7138-4b23-9269-0afbea0a92dc / HEADER / 2026-10-07T19:41:48.184869+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: strict-transport-security  
Integrity SHA-256: e552917110e5e96a68b4040539c460c0d6d58580ea1d88e8d3dce7d67cb50fbd  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

559c0210-1202-4a6d-848b-df28693efae5 / HEADER / 2026-10-07T19:41:48.185414+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: x-content-type-options  
Integrity SHA-256: c1dbc4edce6c8d68fcdb20be3427c1a886484310b0cfa35b7f6f5d3e8f3795e7  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

6009a04b-c687-467c-8b1e-bf83396fd04b / HEADER / 2026-10-07T19:41:48.185936+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: x-frame-options  
Integrity SHA-256: e6e6d0efe7fb640671138cb68b5b6eb237b28033fcbde6292c5351a93263d0d6  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

fa05e63c-a017-472c-8f52-2065f7f3ada3 / HEADER / 2026-10-07T19:41:48.186530+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: referrer-policy  
Integrity SHA-256: e2eee126d054757c04a22b1462970731a637cc8d475b41a1130b3f2655942e55  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

612a7b99-0e2e-4bf7-a000-85a952447230 / HEADER / 2026-10-07T19:41:48.187033+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: permissions-policy  
Integrity SHA-256: 08e7c40f22d7ab57ecafdae822eaddab51bdf6176977a13343a6d911d7fbe503  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

31fd1a69-78c5-44d6-a4ca-c64b17245af1 / HEADER / 2026-10-07T19:41:48.187551+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: ec314abd6e867950b50cb1e56b6c290471d5b7697aa549949eca0af4a9982a14  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

ac037f24-b756-4f72-bf2e-137c206febe3 / HEADER / 2026-10-07T19:41:48.188069+00:00  
Source: http://127.0.0.1:9998/sitemap.xml  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 1b2aa88689c4f9901ecfd3754325625cac942dd494f5f4e4fda08ae272680823  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

728a8362-3a05-4a94-96a9-1e283ad52642 / HEADER / 2026-10-07T19:41:48.189851+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: content-security-policy  
Integrity SHA-256: 62ba7cda9dd540f5ea6edd534f77c4b7ae315b16f490a95f25db529188dd2282  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

a8834c2d-fe39-4f48-8589-4eafe6531c52 / HEADER / 2026-10-07T19:41:48.191285+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: strict-transport-security  
Integrity SHA-256: 36c911012e86622dbb29ac1b6e7ac3388d6169b35e21a73e29a3c674f8ba4c8e  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

905df729-b68b-4f06-a766-5b3e6920df27 / HEADER / 2026-10-07T19:41:48.191807+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: x-content-type-options  
Integrity SHA-256: 33bc79d4e4ffad7425b87c36f141ac968513d41ae2d7962dce0377c3e27cd335  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

b00ca5a1-b57a-4856-b64e-6425a7e548db / HEADER / 2026-10-07T19:41:48.193127+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: x-frame-options  
Integrity SHA-256: edf24a2509597d712f8b557bb98dcd6554bf59e24708046d54065c27ebc1c056  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

d1f265ed-77ee-4374-b592-c6ecd58dcd48 / HEADER / 2026-10-07T19:41:48.194375+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: referrer-policy  
Integrity SHA-256: d861dfb288ca48b9ca5a10cc92fae40033437f22e135e0aacf5a899b93edea6f  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

a43b7690-7c59-4574-9411-c776e7f1b05a / HEADER / 2026-10-07T19:41:48.195642+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: permissions-policy  
Integrity SHA-256: 96376ba7462f48ca0269c21b038abfbf6fcf6bec07162f59c21100f278446bee  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

aa4ff315-86c9-4c2a-8e92-4669abff0ebc / HEADER / 2026-10-07T19:41:48.196945+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 7ae87ce358400cadbb375eb71c92110933bb5ac35bd2993b2dd6483cfee18fb4  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

7c70dde7-de79-4002-acbe-e3d58a927565 / HEADER / 2026-10-07T19:41:48.198283+00:00  
Source: http://127.0.0.1:9998/login  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 032f39f769ea7ecbe718678356e3d976150fe294310cf52ed670c1642adb7174  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

0b5cd167-13eb-42fa-b898-fde86613fa0f / HEADER / 2026-10-07T19:41:48.200668+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: content-security-policy  
Integrity SHA-256: ebda3bf47622e5fd46bc835cbb2fd15c6e299cfefc00cb365db039f1cef8e3cc  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

ab4ad421-1bc5-4323-830b-84b01db51faf / HEADER / 2026-10-07T19:41:48.201163+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: strict-transport-security  
Integrity SHA-256: 13cb712097bd569f78d9e96cabd1952c29c4ef7cba5e1be142d3a89d76086f24  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

aea7de07-9948-4b57-95f2-d1a7e17c660c / HEADER / 2026-10-07T19:41:48.201630+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: x-content-type-options  
Integrity SHA-256: 492a30fb76629161369c5f3f0b66d248785340e8adb0688eaf939a0da2a0b5fc  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

f20e677a-120f-4a3d-a09e-0ec8708b786a / HEADER / 2026-10-07T19:41:48.202066+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: x-frame-options  
Integrity SHA-256: 5157ac36a6dac5d588da1d54cbff271f3a43881b79c0b71dc3801843e0f06326  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

c207cbfe-4662-45bb-9885-764ac656b1d0 / HEADER / 2026-10-07T19:41:48.202496+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: referrer-policy  
Integrity SHA-256: beb87a4afe3a1d6289b19adbcaa1c8a2d4eea21d5abb8aa214ce2ed95cd66f47  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

b6a930a4-fad8-4efe-9ef8-8c5f5f99ab66 / HEADER / 2026-10-07T19:41:48.202934+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: permissions-policy  
Integrity SHA-256: 6e05fa7592cbc86fabc0ae4e4828aaba44008f7f1f4d2593ad25bc5eb3b3ad18  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

7dbb01c2-8701-4809-ab48-279518316c35 / HEADER / 2026-10-07T19:41:48.203409+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: d2b6b968d23ae5b6ed455d367c3920cc029a7577525ab6ffaefcd559d5b42b4c  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

298d07b7-773f-42da-83c8-b1fe30a75374 / HEADER / 2026-10-07T19:41:48.203861+00:00  
Source: http://127.0.0.1:9998/api/users  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 9d457fc1c1e974df36bbca8dbe9a846cbc0fb247aac725a8aefbe1e00c95db29  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

58b70906-9d88-4bc8-856f-d6cda5f7d8ce / CORS\_OBSERVATION / 2026-10-07T19:41:48.204888+00:00  
Source: http://127.0.0.1:9998/api/users  
Contextual CORS observation  
Integrity SHA-256: c42e4712718514f7eac097615f80f1643194b732dedc6172b16aca4c687c8e35  
Excerpt: {&quot;origin&quot;: &quot;\*&quot;, &quot;allow\_credentials&quot;: &quot;true&quot;, &quot;methods&quot;: null, &quot;headers&quot;: null, &quot;source\_evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;, &quot;request\_origin&quot;: null, &quot;vary&quot;: null}

fcb57910-9466-4f7d-8827-1d2b47af946d / HEADER / 2026-10-07T19:41:48.208422+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: content-security-policy  
Integrity SHA-256: d73b1410fc2272c6e7455a955c2768c3f045fff452a9e5380918c885caf42e8a  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

8228874d-a1d7-474b-8c2c-3ba4b655aeb2 / HEADER / 2026-10-07T19:41:48.208882+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: strict-transport-security  
Integrity SHA-256: 94e64796f4d65fcd4257574cfb79e24be050c9db83f58dd7cb5ebb7bd0a47c28  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

d01944fa-e460-4ac4-8993-d73925a4849d / HEADER / 2026-10-07T19:41:48.209313+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: x-content-type-options  
Integrity SHA-256: ecae349c1c9fb4caa368c4755085f00da4fbbd4205e1aca4482d80c9ae566c5a  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

0a8781a9-220a-4aa0-bb14-1a97ef063631 / HEADER / 2026-10-07T19:41:48.209716+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: x-frame-options  
Integrity SHA-256: 906d6cbf5918cf4300840c23b151343d4cf2e8e078a88440aa7d3e4e1e072fee  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

58754231-d9b7-4def-a351-e8b9ed0edbf0 / HEADER / 2026-10-07T19:41:48.210122+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: referrer-policy  
Integrity SHA-256: 081578a7a1646dac1cbb1374011e2ed27b0c34479ac0ca21e2a9fa1998351628  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

d2fea630-197d-4024-b620-64a79039ad49 / HEADER / 2026-10-07T19:41:48.210539+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: permissions-policy  
Integrity SHA-256: 80cdab596de36f45e13985fc582b3d39f43cc36c391b7fea576749981fc2fb61  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

eaf3208d-d8c8-4e2f-80be-ff657e0f1969 / HEADER / 2026-10-07T19:41:48.210969+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: b10b46bf5be7c9be58e662b7e65446bbb4bee93ce173e350e50c02a49e040b61  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

f4f3ac96-5182-4606-9d99-382c39a24150 / HEADER / 2026-10-07T19:41:48.211415+00:00  
Source: http://127.0.0.1:9998/verbose  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 40b0c94169be6d02c7d4eefa6291486d8f5beb6ddb618be9f122f240b675605c  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

bb9a1cab-e0cd-4bf3-b712-6da195b698d8 / HEADER / 2026-10-07T19:41:48.213570+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: content-security-policy  
Integrity SHA-256: b03d4ac582b39bc5b49bb3fda95d4aba8b679ee58dc5d710ea56ef6de089be26  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

6c4c9563-6b5f-4bf6-a795-a602a306840e / HEADER / 2026-10-07T19:41:48.214037+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: strict-transport-security  
Integrity SHA-256: e0a6be40fa3428ef2b225a662d2e89999a2c22d9ffc47d1df8094428f973333c  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

e7ddd6e2-4c16-4dbb-b4c2-b400518273dd / HEADER / 2026-10-07T19:41:48.214472+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: x-content-type-options  
Integrity SHA-256: 24986f5c9df4910cfc70927cbd05da45becacff45db23e2bb2b503d5e4ff6774  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

790262be-9f26-4c00-9f2b-51d81239dfe2 / HEADER / 2026-10-07T19:41:48.214878+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: x-frame-options  
Integrity SHA-256: 0675615097c913a9229c939e1e4a3a2e061cd6bb0add5bf8d0482f1bfbb3f5c2  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

aa2c7463-9e5b-4cbf-a6c2-c612629f8369 / HEADER / 2026-10-07T19:41:48.215279+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: referrer-policy  
Integrity SHA-256: 0562379f09784ce3d660daf0d6b60f06f60626c1192e7aaf4bd34ff3f20d13c4  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

555812e3-c6d8-40cd-90b4-a2ae168c47fa / HEADER / 2026-10-07T19:41:48.215684+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: permissions-policy  
Integrity SHA-256: 4cbf7c0aa55c9616a7aabd21d1fdf18bbdd85a839defb218e1052478ca465f13  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

1a96f1ca-06cd-40d7-9c59-aad2181b6c3c / HEADER / 2026-10-07T19:41:48.216128+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 67bcdb1769242f4967e7940afb9f120941e963612cc4d95ecfa2b459e68a5b1a  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

1454e177-e718-42f5-b1ef-72cf1e094a04 / HEADER / 2026-10-07T19:41:48.216585+00:00  
Source: http://127.0.0.1:9998/redirect-blocked  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: f16d30efb558fd0a2c030b96f3979396c37029489a61d0b24933ad40e693a8a3  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

4c9e9dc1-8df9-4203-bb4a-3df108f54722 / HEADER / 2026-10-07T19:41:48.218004+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: content-security-policy  
Integrity SHA-256: 7de342153380e6cfe27339f5a8f8b20715aeea777a6de100ab5f75b292979665  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

7ff7e8b2-6133-4fc7-82ba-0724cb9419bb / HEADER / 2026-10-07T19:41:48.218461+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: strict-transport-security  
Integrity SHA-256: 10f0386ea8250b7f5ffab0ad69b13257ec4299dfe3743341e5b40642bb98f04e  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

2f024527-7a34-4adc-aada-e82695407e0e / HEADER / 2026-10-07T19:41:48.218892+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: x-content-type-options  
Integrity SHA-256: f68886707c2dee0d77486b919800d42d3d404d03f8964c6b1396d84fde7f22d1  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

eab693ca-1553-4f20-8390-1cd55da6854c / HEADER / 2026-10-07T19:41:48.219294+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: x-frame-options  
Integrity SHA-256: 74c50fd310f2849a30ae1036add75b9984178a7f9f8d1c998ecdfd90439f8ff8  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

1a2ad6ae-d0bb-4831-baa6-85f386a662e2 / HEADER / 2026-10-07T19:41:48.219698+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: referrer-policy  
Integrity SHA-256: e001b213b4ce12b4a8fa906a20f7a7e6f19ca3e3cbdea8c644e78eccda79bc9b  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

77045ef1-ddad-4d18-8ec1-d2fd189ec2f3 / HEADER / 2026-10-07T19:41:48.220102+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: permissions-policy  
Integrity SHA-256: 18e052335a539e35783e26e241ede6a653576592728893baca2e0d511b58c732  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

e87bb1a1-01c1-44d2-a875-5a6bb990d588 / HEADER / 2026-10-07T19:41:48.220533+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 46dc1da98e6b7118b3377e3e0ee734eb7229328e6603c1cbf1ff9f122951b4ce  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

b433795c-5a53-4605-acd1-06644d6461b4 / HEADER / 2026-10-07T19:41:48.220973+00:00  
Source: http://127.0.0.1:9998/assets/react.production.js  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 176ef555e30218799905b5782161328d248e663213a5e5b1ec8b394da7fc20ae  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

e0ea4b98-3497-481b-a9ab-7e1b21d4282f / HTTP\_REQUEST / 2026-10-07T19:41:48.551967+00:00  
Source: http://127.0.0.1:9998/.env  
GET request  
Integrity SHA-256: 27010ad9f34466fcbe5f5805f9862335596e14a15e97306b96d0e402f8feb38d  
Excerpt: GET http://127.0.0.1:9998/.env HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity  
origin: https://webscope.invalid

9ce79b33-4360-4309-9db0-f569e489a2d4 / HTTP\_RESPONSE / 2026-10-07T19:41:48.559759+00:00  
Source: http://127.0.0.1:9998/.env  
HTTP 200 response  
Integrity SHA-256: b6c0f5280d924fcb247f937426846f8323733f2b3e6dac6e13c29d224698b331  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
content-length: 50  
content-type: text/plain; charset=utf-8  
  
APP\_NAME=WebScopeFixture  
API\_KEY=&quot;\[REDACTED\]&quot;  


cedc76a5-8b64-48ac-83f0-997e2fe0855e / HTTP\_REQUEST / 2026-10-07T19:41:48.654899+00:00  
Source: http://127.0.0.1:9998/.git/  
GET request  
Integrity SHA-256: c7573fb379c792218ff3267410c149707ff0eb174450fd2acab9bd5c53a6dfab  
Excerpt: GET http://127.0.0.1:9998/.git/ HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity  
origin: https://webscope.invalid

ca70165b-385e-4cb3-bcf5-46dbc61d1be8 / HTTP\_RESPONSE / 2026-10-07T19:41:48.665489+00:00  
Source: http://127.0.0.1:9998/.git/  
HTTP 200 response  
Integrity SHA-256: cf235a3ba4a9afc610bbebffe762bc1a6b50eebd5704ac9c519b8f8a1b758c03  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:47 GMT  
server: uvicorn  
content-length: 28  
content-type: text/plain; charset=utf-8  
  
ref: refs/heads/fixture-only

47e59069-0fa2-432b-92dc-158d861800bd / HTTP\_REQUEST / 2026-10-07T19:41:48.757182+00:00  
Source: http://127.0.0.1:9998/debug  
GET request  
Integrity SHA-256: f336616d4253834adfd8ae1e08c714ba54efe58b1907e77412310d3097510bd5  
Excerpt: GET http://127.0.0.1:9998/debug HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity  
origin: https://webscope.invalid

555011e6-5d6d-43b6-8030-06317d643d3e / HTTP\_RESPONSE / 2026-10-07T19:41:48.771600+00:00  
Source: http://127.0.0.1:9998/debug  
HTTP 200 response  
Integrity SHA-256: c8a4342fd5838211c44af1ef108e7c4f1e24c86ea82bb1f38baaccd8a3987f3d  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:48 GMT  
server: uvicorn  
content-length: 64  
content-type: text/html; charset=utf-8  
  
&lt;title&gt;Index of /debug&lt;/title&gt;&lt;p&gt;Synthetic directory listing&lt;/p&gt;

c45ebf58-5d16-4877-959a-7d181d5670cd / HTML / 2026-10-07T19:41:48.775923+00:00  
Source: http://127.0.0.1:9998/debug  
Collected HTML (redacted)  
Integrity SHA-256: d51f20f43940abb34eb5250d1dc8ea25c7dc76cb9ae9bd2115676fdc66855bc7  
Excerpt: &lt;title&gt;Index of /debug&lt;/title&gt;&lt;p&gt;Synthetic directory listing&lt;/p&gt;

4aff0ed4-31cf-4f34-9d35-9b46a072aa67 / HTTP\_REQUEST / 2026-10-07T19:41:48.860032+00:00  
Source: http://127.0.0.1:9998/cors  
GET request  
Integrity SHA-256: 694d83ab827ff3030e1a355bb274e4bcdb7697625fe3ef38ac745b42bd578c24  
Excerpt: GET http://127.0.0.1:9998/cors HTTP/1.1  
host: 127.0.0.1:9998  
user-agent: WebScope/1.0 (authorized assessment)  
accept-encoding: identity  
origin: https://webscope.invalid

06ccc625-4223-4d47-9d73-3314144dd19b / HTTP\_RESPONSE / 2026-10-07T19:41:48.878075+00:00  
Source: http://127.0.0.1:9998/cors  
HTTP 200 response  
Integrity SHA-256: 15fd851029fd38a0e652afb494f4fd38312ff5b9ce0829e78a6c5329378c0587  
Excerpt: HTTP/1.1 200  
date: Wed, 07 Oct 2026 19:41:48 GMT  
server: uvicorn  
access-control-allow-origin: https://webscope.invalid  
access-control-allow-credentials: true  
vary: Origin  
content-length: 35  
content-type: application/json  
  
{  
  &quot;public&quot;: &quot;synthetic fixture only&quot;  
}

a74eaa44-8a92-40e5-9cf0-ab5f0c00f79d / HEADER / 2026-10-07T19:41:48.904639+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: content-security-policy  
Integrity SHA-256: 91179ffdd48610c836c94a105d50b6b2ff43aa80a76ceec9c2882793b5a1763b  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

804a3068-834e-48e7-b2d7-4f2ca2ec4a17 / HEADER / 2026-10-07T19:41:48.905488+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: strict-transport-security  
Integrity SHA-256: 8121ae92894c992948589b93df407d49f904bf74463c9b526e3c2cb0811b8be8  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

24ffe7a5-5ac5-4a67-88f5-fcc441bdc29f / HEADER / 2026-10-07T19:41:48.906177+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: x-content-type-options  
Integrity SHA-256: 0d00a5f225bd531c220bcb22bdb0e9f1a6f21fb979e04e0a49eb3f95148fcd89  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

71ed8278-826a-4c31-9678-4d23f61f761f / HEADER / 2026-10-07T19:41:48.906803+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: x-frame-options  
Integrity SHA-256: 965dd75275eeba71b750c16df6ef22fb679dd44b0ca6bb65bdee47abb051dce6  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

49d2356e-4abd-4acc-a48d-5e5faa7c732b / HEADER / 2026-10-07T19:41:48.907438+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: referrer-policy  
Integrity SHA-256: 8da146cf648b90b66bf7f2a39dd0e163aae9fcd19406e891f0ba0dab6827e1e7  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

fdf03da4-6721-4f99-b9cc-a48047bdd21c / HEADER / 2026-10-07T19:41:48.908068+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: permissions-policy  
Integrity SHA-256: 82332a7112623d66849659108b783a64040c6e2e65f21c581d69410482470954  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

a5337fd2-9267-4f53-95a4-68656e0d2a53 / HEADER / 2026-10-07T19:41:48.908730+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: f62dbeb33c2f08a3ee9707a73e701d8234c21dd4f9f6eb6125b5419ce781f429  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

2236d83f-e085-4f9b-8ca3-2abc26e7b759 / HEADER / 2026-10-07T19:41:48.909400+00:00  
Source: http://127.0.0.1:9998/.env  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 174c7885fbb34e1d5ffcb98316303e878750d906f385e949625b37c3b7c8cacd  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

7ef1b834-4868-4253-a3f3-f4818b38c60e / HEADER / 2026-10-07T19:41:48.912997+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: content-security-policy  
Integrity SHA-256: bbd26c2102e37618ef86e915729c2e119fa9b18dd47ba0ad2c79c2c125591ef8  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

530db512-4a44-4e3a-a507-50c16ac85778 / HEADER / 2026-10-07T19:41:48.913636+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: strict-transport-security  
Integrity SHA-256: 5a272e4630aab5f6160013ac1a9f9653342f0924111505cd82586f0e037347de  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

fbe51ca0-6f46-430b-9593-df8882b1105e / HEADER / 2026-10-07T19:41:48.914231+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: x-content-type-options  
Integrity SHA-256: 4d8a5e7842d3318986ca8b5ace2bd39dfedbbe1b665c116b85ed5e9d97ccdd15  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

28d22570-455c-438c-a63f-8a6b4fbc2ccb / HEADER / 2026-10-07T19:41:48.914776+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: x-frame-options  
Integrity SHA-256: b7084bbc2a0f4c3ca1a5cf4f2be0d85ba620c7315c4410c43e449d10b6a4c2f5  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

9c52b975-e67b-499a-8f04-b223dbfac3a5 / HEADER / 2026-10-07T19:41:48.915316+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: referrer-policy  
Integrity SHA-256: 8af9f35230251d9b6214068bf122c08f4cd81f83ba996e23eab53575c01e5b91  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

13ea1dc5-7e91-46db-9f3a-44a456c6fc2a / HEADER / 2026-10-07T19:41:48.915863+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: permissions-policy  
Integrity SHA-256: ebd95e9e5f9021b841e60f9442424c453f23c1b4ed2ffba487253daca5220af4  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

b467dd30-80da-43a5-833b-b3ee3f8219bc / HEADER / 2026-10-07T19:41:48.916471+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 279dfe4cbb3ab4d0dac07e65e2278d348f6900d5d08a9851ee012222111da8ff  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

f8e21329-c527-43ef-b517-3911415de59e / HEADER / 2026-10-07T19:41:48.917068+00:00  
Source: http://127.0.0.1:9998/.git/  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: a13086346b997a5f266479f81a0854e7772fe9cdcf7924676792d72b2779091d  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

8db03525-10cb-4c33-a40d-96c74514b1cb / HEADER / 2026-10-07T19:41:48.920257+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: content-security-policy  
Integrity SHA-256: 29db117a96c2ab0ab9f027cb5d92a44c9c768652d55f6dcf2c83a772bf4b2d79  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

b0705e82-d031-4855-899d-9355583af22c / HEADER / 2026-10-07T19:41:48.921778+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: strict-transport-security  
Integrity SHA-256: 34b191c1e601ee9336994c2770fae9a15c0f98ac17e28b4e2b96d67b76db41a4  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

a369d6c0-ddfb-4938-b571-fcba7c53afab / HEADER / 2026-10-07T19:41:48.922328+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: x-content-type-options  
Integrity SHA-256: 9c40be08889a9e9e7889f72b4b74bb89d46988fd9aab7028cb6dafd6222bbf3f  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

e327d533-dc33-4125-809b-1ca0db546775 / HEADER / 2026-10-07T19:41:48.923771+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: x-frame-options  
Integrity SHA-256: a94fc12a6f6cd9e42e4ee2b3e86167e0a539f8f03a61c87a6336919bae596364  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

a4df21cc-a35c-409c-a7a4-87b8cacbd9b5 / HEADER / 2026-10-07T19:41:48.925187+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: referrer-policy  
Integrity SHA-256: d5e4061ad95b81e3c0bb0e0fca5b07a88b9818fc2629a043b4392283b4a1b464  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

eaec93a1-f994-4ee8-a1aa-eb163cfbee47 / HEADER / 2026-10-07T19:41:48.926606+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: permissions-policy  
Integrity SHA-256: 18e980285cc154582d2c94ec80bdbfa2e825820bdb90e9d551561cb0a3548712  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

c24df15a-9bf7-48b2-bf12-02f35b5442f0 / HEADER / 2026-10-07T19:41:48.928073+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 27634c54052247e64a9a0ac3c84c27aaa0b909fef986410502dc17843c847843  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

b201c318-3712-4831-9355-f783a3b035b2 / HEADER / 2026-10-07T19:41:48.929518+00:00  
Source: http://127.0.0.1:9998/debug  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: eb10fc34d22182d7414e27c8b71a21173645c7d98c01b6ed36c95479241dcfad  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

84589006-5e2a-4e72-bf64-d3cad5e1715b / HEADER / 2026-10-07T19:41:48.932830+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: content-security-policy  
Integrity SHA-256: dec6eef344583735e50371e447e41e42cf25043c02bb17a3f192a5d6a915e496  
Excerpt: {&quot;name&quot;: &quot;content-security-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

af52257f-f203-44c4-858e-8613afa4d93f / HEADER / 2026-10-07T19:41:48.933353+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: strict-transport-security  
Integrity SHA-256: 4532c8a04fb3649ad6b1075ede7f213b03660e559b444497652f530974fdbcbd  
Excerpt: {&quot;name&quot;: &quot;strict-transport-security&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

7f54384a-bef9-41a3-82a3-26748256c34c / HEADER / 2026-10-07T19:41:48.933847+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: x-content-type-options  
Integrity SHA-256: 611cb0e338368e4e806ac55adc64c0117ba5ced474923f7143643cfdf77085fc  
Excerpt: {&quot;name&quot;: &quot;x-content-type-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

1b2d4e78-3047-4d96-bc8d-a8e5228a8ca2 / HEADER / 2026-10-07T19:41:48.934312+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: x-frame-options  
Integrity SHA-256: 9dc48bdba1802532fe51d5457db393d91711135fda5956944cf98fce0e4b54ad  
Excerpt: {&quot;name&quot;: &quot;x-frame-options&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

adaf9897-26c3-4aae-a619-59e95b8dc1ca / HEADER / 2026-10-07T19:41:48.934770+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: referrer-policy  
Integrity SHA-256: 9dfd1a4b332b59e1c67c11527b4a3cf736e5c5ff6fa2cd0cb18387ca765e172e  
Excerpt: {&quot;name&quot;: &quot;referrer-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

8634bd45-fb6f-4918-86fd-9a2849210733 / HEADER / 2026-10-07T19:41:48.935234+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: permissions-policy  
Integrity SHA-256: 1c3955797a6be2721c50c17c6cb65d8f74cd65c08ec8187b611d164ab46208bc  
Excerpt: {&quot;name&quot;: &quot;permissions-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

851aa632-f639-446b-ab58-1da137ac61ff / HEADER / 2026-10-07T19:41:48.935707+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: cross-origin-opener-policy  
Integrity SHA-256: 8f2e99b994c0e3ef7f897f5d9828a4b7b2ecd096bf0815e001089ba3ffd96e48  
Excerpt: {&quot;name&quot;: &quot;cross-origin-opener-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

4fb422f4-287f-44fc-a921-e32b3e6afd97 / HEADER / 2026-10-07T19:41:48.936178+00:00  
Source: http://127.0.0.1:9998/cors  
Header observation: cross-origin-resource-policy  
Integrity SHA-256: 857f466318481f2232151ed77b37a6fccbdf16a0d538807edd78aaad16e6159c  
Excerpt: {&quot;name&quot;: &quot;cross-origin-resource-policy&quot;, &quot;present&quot;: false, &quot;value&quot;: &quot;&quot;, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

11553b1d-50b8-45a0-b4a4-af5cf357b55d / CORS\_OBSERVATION / 2026-10-07T19:41:48.936914+00:00  
Source: http://127.0.0.1:9998/cors  
Contextual CORS observation  
Integrity SHA-256: b8acf60ed7d9066bc695f9fc255efd5ffe122f48ee98278fdbf8387e676daebe  
Excerpt: {&quot;origin&quot;: &quot;https://webscope.invalid&quot;, &quot;allow\_credentials&quot;: &quot;true&quot;, &quot;methods&quot;: null, &quot;headers&quot;: null, &quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;, &quot;request\_origin&quot;: &quot;https://webscope.invalid&quot;, &quot;vary&quot;: &quot;Origin&quot;}

a550f8a3-8247-4d7c-9f33-5d80aca4a729 / ANALYST\_NOTE / 2026-10-07T19:41:49.631068+00:00  
Source: finding:e919d8fd-0851-400d-86da-dc922ad108b8  
Analyst note  
Integrity SHA-256: 41380037c030d418e8cae0bc0e4f1e2f787d281f54f7a51e08a1c3f334da70fa  
Excerpt: Verified with the configured synthetic Origin probe. Source evidence retained.

2d374e7a-f993-46bb-ba5f-259f95ab3885 / SCREENSHOT / 2026-10-07T19:41:50.038793+00:00  
Source: webscope:evidence:06ccc625-4223-4d47-9d73-3314144dd19b  
Rendered capture of redacted evidence (not target-browser rendering)  
Integrity SHA-256: 7eed214daadbd1ae36b658cc81eef6ee504a3affb1ca0a5304c51677ce9b9dfa  
Excerpt: {&quot;source\_evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;, &quot;media\_type&quot;: &quot;image/png&quot;, &quot;width&quot;: 1100, &quot;height&quot;: 470, &quot;image\_base64&quot;: &quot;iVBORw0KGgoAAAANSUhEUgAABEwAAAHWCAIAAADipotvAACim0lEQVR4nOzdB1hTV/8H8JuQALJRC44yHAwXFvfCgspwI7YqQ2XIUIbaKu462goo7sEUEAVxvK0MEbSVJUNsraiI2goEHEUrogwlgeT/4O3/Ng3JJVBaNX4/T5/3Sc4983dufHO4594wNHv2IwAAAAAAAGQF8213AAAAAAAAoDNhkQMAAAAAADIFixwAAAAAAJApWOQAAAAAAIBMwSIHAAAAAABkChY5AAAAAAAgU7DIAQAAAAAAmYJFDgAAAAAAyBQscgAAAAAAQKZgkQMAAAAAADIFixwAAAAAAJApWOQAAAAAAIBMwSIHAAAAAABkChY5AAAAAAAgU7DIAQAAAAAAmYJFDgAAAAAAyBQscgAAAAAAQKZgkQMAAAAAADIFixwAAAAAAJApWOQAAAAAAIBMwSIHAAAAAABkChY5AAAAAAAgU7DIAQAAAAAAmYJFDgAAAAAAyBQscjpCV0/Xw9NDWVm50+cDAAAAAABkZ5FjZmZ29dpPWtpaxDtPT1fP3dNDWUVZNuLwz1vU0tY6cOggk8l8r6cVAAAAAGRDpy1yXNxcc/Ius1gsKmX3vj1Xr/1kNnEilWIxaVJ+YYGSklLHmujRo8emzV+dO5+

deb84e15-fc39-4ea1-82d7-b319ef378328 / ENDPOINT / 2026-10-07T19:41:50.705051+00:00  
Source: http://127.0.0.1:9998/manual-inventory  
Analyst-supplied endpoint (not executed)  
Integrity SHA-256: 36fe3bd82004fc0d265377757b9ecbc3645423c61deb52d36e804c3605477c4a  
Excerpt: {&quot;url&quot;: &quot;http://127.0.0.1:9998/manual-inventory&quot;, &quot;method&quot;: &quot;POST&quot;, &quot;parameters&quot;: \[{&quot;name&quot;: &quot;filter&quot;, &quot;in&quot;: &quot;body&quot;, &quot;type&quot;: &quot;string&quot;}\]}

d76959f6-69b6-4e65-bc28-d1e0831ea81a / ENDPOINT / 2026-10-07T19:41:50.820806+00:00  
Source: http://127.0.0.1:9998/  
Imported OpenAPI specification (inventory only)  
Integrity SHA-256: 907464da8e2e95dbf244219976c33a69a8ae1671287da2fd883960fcc8fa3013  
Excerpt: {&quot;document&quot;: {&quot;openapi&quot;: &quot;3.0.3&quot;, &quot;info&quot;: {&quot;title&quot;: &quot;WebScope synthetic API&quot;, &quot;version&quot;: &quot;1.0&quot;}, &quot;servers&quot;: \[{&quot;url&quot;: &quot;/&quot;}\], &quot;security&quot;: \[{&quot;sessionAuth&quot;: \[\]}\], &quot;paths&quot;: {&quot;/api/orders&quot;: {&quot;get&quot;: {&quot;operationId&quot;: &quot;listOrders&quot;, &quot;parameters&quot;: \[{&quot;name&quot;: &quot;limit&quot;, &quot;in&quot;: &quot;query&quot;, &quot;schema&quot;: {&quot;type&quot;: &quot;integer&quot;}}\], &quot;responses&quot;: {&quot;200&quot;: {&quot;description&quot;: &quot;Synthetic list&quot;, &quot;content&quot;: {&quot;application/json&quot;: {&quot;schema&quot;: {&quot;type&quot;: &quot;array&quot;, &quot;items&quot;: {&quot;type&quot;: &quot;object&quot;}}}}}}}, &quot;post&quot;: {&quot;operationId&quot;: &quot;createOrderInventoryOnly&quot;, &quot;responses&quot;: {&quot;201&quot;: {&quot;description&quot;: &quot;Never executed&quot;}}}}}, &quot;components&quot;: {&quot;parameters&quot;: {&quot;Limit&quot;: {&quot;name&quot;: &quot;limit&quot;, &quot;in&quot;: &quot;query&quot;, &quot;schema&quot;: {&quot;type&quot;: &quot;integer&quot;}}}, &quot;securitySchemes&quot;: {&quot;sessionAuth&quot;: {&quot;type&quot;: &quot;apiKey&quot;, &quot;in&quot;: &quot;cookie&quot;, &quot;name&quot;: &quot;session&quot;}}}}, &quot;local\_references&quot;: \[&quot;#/components/p

e2511a52-edaf-4aac-81e2-4e7e94d25b14 / ANALYST\_NOTE / 2026-10-07T19:41:51.564053+00:00  
Source: case:faa5870c-73a0-4c96-bd30-c09d8d6588ce  
Analyst note  
Integrity SHA-256: 17508f6fa9f24a4fbaaecc5db57d81b4b6a05140e5512b67adb1084924f0c3f0  
Excerpt: Test case lifecycle completed; no target data was changed.

## Risk Assessment

d433aed7-9597-4e4d-b078-32d949de1a53: priority MEDIUM (computed MEDIUM, score 2)  
Factors: {&quot;severity&quot;: &quot;MEDIUM&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

5b381559-b452-433f-a8fe-03d72dfd3df6: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

eab15af1-4017-4967-a8ae-0a30dacf3727: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

33fdef47-5741-473f-82ad-e0d26251dc1b: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

ed0ec6f6-9351-45af-9777-3fd8338c65d9: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

de36cd08-eb40-449a-b863-2cb65937647f: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

36cde7e2-0d22-486d-a7ef-c269a83ea232: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

0f9754ee-9316-4d84-aebc-c04c409265d4: priority LOW (computed LOW, score 1.5)  
Factors: {&quot;severity&quot;: &quot;MEDIUM&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

8a4ee996-3996-40d2-a524-8a7369c49782: priority LOW (computed LOW, score 0.75)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

cb0d7616-4e11-4ff1-8f42-1e5f0c828292: priority LOW (computed LOW, score 0.75)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

22930c34-a612-401a-b5fe-cdbc0bb383a3: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

76621c17-6016-46a8-92c8-34089ae8a908: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

505d592b-b0f7-43b6-b66e-be178c73430f: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

9dff689d-4849-48a5-ab67-0b91ce04b1b5: priority MEDIUM (computed MEDIUM, score 2)  
Factors: {&quot;severity&quot;: &quot;MEDIUM&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

f8b1c27b-7935-4f81-9325-3172076d9293: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

d13fdebc-21ac-489b-aba0-412ff264bf32: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

a2651e1a-6a5d-489b-a3b9-688447119723: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

7aa052b0-4543-44d9-8e5c-c2be6051cf96: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

54576baf-440a-4282-a80c-0f8cf242ba34: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

cbd820eb-fe99-4f2f-ad15-bb53126eddfb: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

1d50154e-e7cf-4159-a425-bdf381fe8682: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

9c46fc22-c53d-4893-89fd-36f48a97f869: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

31ace72f-ad18-4fad-a7d8-7d2457732523: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

6598e0d1-1892-45bd-899c-56314bd958bc: priority LOW (computed LOW, score 0.5)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;LOW&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

8340818d-5a59-4904-afc8-1f22c35020e3: priority LOW (computed LOW, score 0.75)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

6014e66d-fbb0-49f1-bcc1-b5ac12e916ab: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

d7f56ee1-7e9c-47be-a85b-1aadc1f5b7d4: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

872dd044-4711-42a9-820b-161276199807: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

611ff291-ad29-4b00-9571-47f9784e2c61: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

ea75df85-a484-4bb6-b089-cca4eb62eac0: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

80240cc2-13e5-4795-b5bc-496ee1d32556: priority MEDIUM (computed MEDIUM, score 2.25)  
Factors: {&quot;severity&quot;: &quot;HIGH&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

2650eb1e-893e-4e5f-bb39-4375afbe54a6: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

35fc5bf6-ef6b-45bc-8aa0-7b49d1d5f503: priority LOW (computed LOW, score 1.5)  
Factors: {&quot;severity&quot;: &quot;MEDIUM&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

10968e0f-c78d-4eed-9e6d-b4e167f444f5: priority MEDIUM (computed MEDIUM, score 2)  
Factors: {&quot;severity&quot;: &quot;MEDIUM&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

b109b16e-b65b-4d46-89e9-33d89dd9a155: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

6af2d43a-028a-4028-8cb3-1ffd7b382120: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

62e992e8-d0d2-47fc-9cd2-3ca326fa232f: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

39d5a868-2a16-45e0-a697-6ce1ff2fae0f: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

d1136c4d-081d-4536-8646-8b0313bb69cb: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

c58f96e1-1849-4232-a0b7-991a2d1d5bce: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

7631b342-f442-40de-9e14-b6fd659e5b05: priority LOW (computed LOW, score 1)  
Factors: {&quot;severity&quot;: &quot;LOW&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

b8e256be-96be-497e-843f-16d6cbd63e04: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

e919d8fd-0851-400d-86da-dc922ad108b8: priority HIGH (computed MEDIUM, score 2.25)  
Factors: {&quot;severity&quot;: &quot;HIGH&quot;, &quot;confidence&quot;: &quot;MEDIUM&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: Prioritize configuration correction before production deployment.

ec6870f4-b5fe-4b18-bb25-cc485e9964a1: priority INFO (computed INFO, score 0)  
Factors: {&quot;severity&quot;: &quot;INFO&quot;, &quot;confidence&quot;: &quot;HIGH&quot;, &quot;exposure&quot;: &quot;INTERNAL&quot;, &quot;asset\_importance&quot;: &quot;STANDARD&quot;, &quot;authentication\_context&quot;: &quot;UNKNOWN&quot;, &quot;potential\_impact&quot;: &quot;Context-dependent security exposure; automated evidence is not an analyst-confirmed exploit.&quot;}  
Override explanation: none

Severity weight 0-4 x confidence (LOW .5, MEDIUM .75, HIGH 1), plus internet .5, production .5 and no authentication .25 for non-informational findings; capped at 4. Thresholds: LOW &gt;0, MEDIUM &gt;=1.75, HIGH &gt;=2.75, CRITICAL &gt;=3.75. Impact is described, not given an invented independent score. Overrides never alter original facts.

## Remediation Recommendations

WS-HDR-001: Constrain script/resource origins with a tested Content-Security-Policy.

WS-HDR-003: Set X-Content-Type-Options: nosniff.

WS-HDR-004: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

WS-HDR-005: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

WS-HDR-006: Restrict browser features that this application does not require.

WS-HDR-007: Consider same-origin opener isolation where compatible.

WS-HDR-008: Choose a resource policy appropriate to intended cross-origin use.

WS-CK-001: Set Secure on session cookies and serve the application over HTTPS.

WS-CK-002: Set HttpOnly unless client-side access is explicitly required.

WS-CK-003: Choose Lax or Strict where possible; SameSite=None requires Secure.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-HDR-001: Constrain script/resource origins with a tested Content-Security-Policy.

WS-HDR-003: Set X-Content-Type-Options: nosniff.

WS-HDR-004: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

WS-HDR-005: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

WS-HDR-006: Restrict browser features that this application does not require.

WS-HDR-007: Consider same-origin opener isolation where compatible.

WS-HDR-008: Choose a resource policy appropriate to intended cross-origin use.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-CORS-002: Use an explicit trusted origin allowlist. Browsers reject wildcard credentialed responses.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-API-001: Review authorization and data minimization for the observed response fields.

WS-DISC-004: Return generic errors externally and retain diagnostics only in restricted logs.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-005: Review production source maps for unintended source or metadata disclosure.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-002: Deny public access to environment files; investigate exposure and rotate affected secrets if confirmed.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-DISC-001: Remove source-control metadata from the public web root.

WS-HDR-001: Constrain script/resource origins with a tested Content-Security-Policy.

WS-HDR-003: Set X-Content-Type-Options: nosniff.

WS-HDR-004: Use CSP frame-ancestors or X-Frame-Options to restrict framing.

WS-HDR-005: Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.

WS-HDR-006: Restrict browser features that this application does not require.

WS-HDR-007: Consider same-origin opener isolation where compatible.

WS-HDR-008: Choose a resource policy appropriate to intended cross-origin use.

WS-DISC-003: Disable unintended directory indexes.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

WS-CORS-003: Validate Origin against an exact trusted allowlist; manually verify sensitive authenticated impact.

WS-DISC-006: Minimize unnecessary version banners; a banner does not prove a vulnerable version.

## Analyst Conclusions

\[  
  {  
    &quot;finding\_id&quot;: &quot;d433aed7-9597-4e4d-b078-32d949de1a53&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;5b381559-b452-433f-a8fe-03d72dfd3df6&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;eab15af1-4017-4967-a8ae-0a30dacf3727&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;33fdef47-5741-473f-82ad-e0d26251dc1b&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;ed0ec6f6-9351-45af-9777-3fd8338c65d9&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;de36cd08-eb40-449a-b863-2cb65937647f&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;36cde7e2-0d22-486d-a7ef-c269a83ea232&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;0f9754ee-9316-4d84-aebc-c04c409265d4&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;8a4ee996-3996-40d2-a524-8a7369c49782&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;cb0d7616-4e11-4ff1-8f42-1e5f0c828292&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;22930c34-a612-401a-b5fe-cdbc0bb383a3&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;76621c17-6016-46a8-92c8-34089ae8a908&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;505d592b-b0f7-43b6-b66e-be178c73430f&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;9dff689d-4849-48a5-ab67-0b91ce04b1b5&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;f8b1c27b-7935-4f81-9325-3172076d9293&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;d13fdebc-21ac-489b-aba0-412ff264bf32&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;a2651e1a-6a5d-489b-a3b9-688447119723&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;7aa052b0-4543-44d9-8e5c-c2be6051cf96&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;54576baf-440a-4282-a80c-0f8cf242ba34&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;cbd820eb-fe99-4f2f-ad15-bb53126eddfb&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;1d50154e-e7cf-4159-a425-bdf381fe8682&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;9c46fc22-c53d-4893-89fd-36f48a97f869&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;31ace72f-ad18-4fad-a7d8-7d2457732523&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;6598e0d1-1892-45bd-899c-56314bd958bc&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;8340818d-5a59-4904-afc8-1f22c35020e3&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;6014e66d-fbb0-49f1-bcc1-b5ac12e916ab&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;d7f56ee1-7e9c-47be-a85b-1aadc1f5b7d4&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;872dd044-4711-42a9-820b-161276199807&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;611ff291-ad29-4b00-9571-47f9784e2c61&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;ea75df85-a484-4bb6-b089-cca4eb62eac0&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;80240cc2-13e5-4795-b5bc-496ee1d32556&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;2650eb1e-893e-4e5f-bb39-4375afbe54a6&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;35fc5bf6-ef6b-45bc-8aa0-7b49d1d5f503&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;10968e0f-c78d-4eed-9e6d-b4e167f444f5&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;b109b16e-b65b-4d46-89e9-33d89dd9a155&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;6af2d43a-028a-4028-8cb3-1ffd7b382120&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;62e992e8-d0d2-47fc-9cd2-3ca326fa232f&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;39d5a868-2a16-45e0-a697-6ce1ff2fae0f&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;d1136c4d-081d-4536-8646-8b0313bb69cb&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;c58f96e1-1849-4232-a0b7-991a2d1d5bce&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;7631b342-f442-40de-9e14-b6fd659e5b05&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;b8e256be-96be-497e-843f-16d6cbd63e04&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;,  
    &quot;status&quot;: &quot;CONFIRMED&quot;,  
    &quot;conclusion&quot;: &quot;Confirmed the unsafe origin configuration in the owned fixture; authenticated data impact was not tested.&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: &quot;HIGH&quot;,  
    &quot;override\_reason&quot;: &quot;Prioritize configuration correction before production deployment.&quot;  
  },  
  {  
    &quot;finding\_id&quot;: &quot;ec6870f4-b5fe-4b18-bb25-cc485e9964a1&quot;,  
    &quot;status&quot;: &quot;NEW&quot;,  
    &quot;conclusion&quot;: &quot;&quot;,  
    &quot;severity&quot;: null,  
    &quot;confidence&quot;: null,  
    &quot;priority\_override&quot;: null,  
    &quot;override\_reason&quot;: &quot;&quot;  
  }  
\]

\[  
  {  
    &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;,  
    &quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;,  
    &quot;case\_id&quot;: null,  
    &quot;author&quot;: &quot;Local analyst&quot;,  
    &quot;evidence\_id&quot;: &quot;a550f8a3-8247-4d7c-9f33-5d80aca4a729&quot;,  
    &quot;id&quot;: &quot;27d93f5f-44a2-4011-b29c-3ffa4e81da02&quot;,  
    &quot;created\_at&quot;: &quot;2026-10-07T19:41:49.631615+00:00&quot;,  
    &quot;content&quot;: &quot;Verified with the configured synthetic Origin probe. Source evidence retained.&quot;  
  },  
  {  
    &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;,  
    &quot;finding\_id&quot;: null,  
    &quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;,  
    &quot;author&quot;: &quot;Local analyst&quot;,  
    &quot;evidence\_id&quot;: &quot;e2511a52-edaf-4aac-81e2-4e7e94d25b14&quot;,  
    &quot;id&quot;: &quot;31135728-9d84-48b9-883a-d60d8f0193fd&quot;,  
    &quot;created\_at&quot;: &quot;2026-10-07T19:41:51.564289+00:00&quot;,  
    &quot;content&quot;: &quot;Test case lifecycle completed; no target data was changed.&quot;  
  }  
\]

## Assessment Timeline

2026-10-07T19:41:47.139992+00:00 ASSESSMENT\_CREATED: Assessment created in DRAFT {}

2026-10-07T19:41:47.140262+00:00 AUTHORIZATION\_RECORDED: Analyst explicitly authorized the defined target and scope {&quot;statement&quot;: &quot;I own the loopback WebScope fixture and authorize bounded read-only collection.&quot;}

2026-10-07T19:41:47.284524+00:00 TARGET\_VALIDATED: Target syntax, scope and authorization validated without network traffic {}

2026-10-07T19:41:47.398539+00:00 EXECUTION\_STARTED: Controlled discovery started {}

2026-10-07T19:41:47.400131+00:00 TLS\_NOT\_APPLICABLE: TLS collection requires an explicitly configured HTTPS target {&quot;evidence\_id&quot;: &quot;ee6bfeff-043f-4ec1-985e-2d29540d4667&quot;, &quot;destination&quot;: &quot;http://127.0.0.1:9998/&quot;}

2026-10-07T19:41:47.400583+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 1, &quot;elapsed\_seconds&quot;: 0.0016}

2026-10-07T19:41:47.423228+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;, &quot;transaction\_id&quot;: &quot;ac99b5b3-34da-43c3-8159-9d5082dda9bf&quot;}

2026-10-07T19:41:47.425015+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;eefd4da9-d67e-4ceb-b50b-106f62a47655&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.428610+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;63d3ad51-0d84-4006-9510-1298f0e797a8&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.429238+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;2f868bd9-1c9a-450a-96cc-a2c99fd7072e&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.429815+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;28982931-3fb3-45b5-bcb0-fe4fa79792c9&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.430366+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;5c66af4b-9b14-4c97-816d-629e0e3a0d33&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.430916+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;9a246530-b66b-4044-a706-8a240a1f882f&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: false}

2026-10-07T19:41:47.431621+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;e6a746b7-da7e-4f68-83cd-b84643a6724f&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: false}

2026-10-07T19:41:47.432221+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from FORM {&quot;endpoint\_id&quot;: &quot;54ddf0d7-3139-4396-a197-73ec8867b3fa&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.432752+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTML {&quot;endpoint\_id&quot;: &quot;30339f4d-98f9-4e5e-bed2-f29668634cab&quot;, &quot;evidence\_id&quot;: &quot;5c0279ed-81fe-4f6b-b498-18c0af431558&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.501254+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/robots.txt&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 2, &quot;elapsed\_seconds&quot;: 0.1021}

2026-10-07T19:41:47.514454+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;, &quot;transaction\_id&quot;: &quot;e2eaba9d-0a91-4277-8de3-11012201fcb2&quot;}

2026-10-07T19:41:47.515791+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;683bfd36-96ee-45f9-b951-ec37ad8cec26&quot;, &quot;evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.517663+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from ROBOTS {&quot;endpoint\_id&quot;: &quot;581e9ee9-0cd6-4b32-9c18-2fea8e33cd33&quot;, &quot;evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.601280+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/sitemap.xml&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 3, &quot;elapsed\_seconds&quot;: 0.2021}

2026-10-07T19:41:47.617750+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;, &quot;transaction\_id&quot;: &quot;13de5b3a-40e8-4917-82e4-78a46ecb7435&quot;}

2026-10-07T19:41:47.619464+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;b6f303a7-1beb-4f12-bc5f-9a187de0fb17&quot;, &quot;evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.620945+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from SITEMAP {&quot;endpoint\_id&quot;: &quot;3e4dbe6c-203b-4199-a5b6-1e0c895c169f&quot;, &quot;evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:47.703347+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/login&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 4, &quot;elapsed\_seconds&quot;: 0.3041}

2026-10-07T19:41:47.724354+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;, &quot;transaction\_id&quot;: &quot;186c7266-585e-4f6f-a083-a83b59f4bfd4&quot;}

2026-10-07T19:41:47.805898+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/api/users&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 5, &quot;elapsed\_seconds&quot;: 0.4063}

2026-10-07T19:41:47.831011+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;, &quot;transaction\_id&quot;: &quot;e6333999-1bf8-46c2-b3c9-7fadc046bc1f&quot;}

2026-10-07T19:41:47.908943+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/verbose&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 6, &quot;elapsed\_seconds&quot;: 0.5085}

2026-10-07T19:41:47.932798+00:00 HTTP\_COLLECTED: HTTP 500 collected {&quot;evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;, &quot;transaction\_id&quot;: &quot;1711ba46-649e-4641-8433-5b4a954d2b9f&quot;}

2026-10-07T19:41:48.011019+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/redirect-blocked&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 7, &quot;elapsed\_seconds&quot;: 0.6107}

2026-10-07T19:41:48.037725+00:00 HTTP\_COLLECTED: HTTP 307 collected {&quot;evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;, &quot;transaction\_id&quot;: &quot;df9e6295-058b-4e77-8b4e-9ac445e2632c&quot;}

2026-10-07T19:41:48.039513+00:00 REDIRECT\_BLOCKED: Redirect destination blocked by scope policy {&quot;evidence\_id&quot;: &quot;2a9013d2-b7b1-4e8b-8aed-6c79919b07f2&quot;, &quot;destination&quot;: &quot;http://localhost:9989/never-requested&quot;}

2026-10-07T19:41:48.114474+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/assets/react.production.js&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 8, &quot;elapsed\_seconds&quot;: 0.7129}

2026-10-07T19:41:48.137351+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;, &quot;transaction\_id&quot;: &quot;c9e1a174-8d74-4d77-85ec-be8d53575ae0&quot;}

2026-10-07T19:41:48.141905+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from JAVASCRIPT {&quot;endpoint\_id&quot;: &quot;2c157415-baad-4211-a8cd-c64794423efd&quot;, &quot;evidence\_id&quot;: &quot;03466307-9ad2-433b-a487-abb782f9bb6a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.143173+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from JAVASCRIPT {&quot;endpoint\_id&quot;: &quot;6359e4eb-b71b-4c09-a80b-3a26333e892e&quot;, &quot;evidence\_id&quot;: &quot;03466307-9ad2-433b-a487-abb782f9bb6a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.156817+00:00 FINDING\_GENERATED: WS-HDR-001: Missing content-security-policy {&quot;finding\_id&quot;: &quot;d433aed7-9597-4e4d-b078-32d949de1a53&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.159991+00:00 FINDING\_GENERATED: WS-HDR-003: Missing x-content-type-options {&quot;finding\_id&quot;: &quot;5b381559-b452-433f-a8fe-03d72dfd3df6&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.162012+00:00 FINDING\_GENERATED: WS-HDR-004: Missing x-frame-options {&quot;finding\_id&quot;: &quot;eab15af1-4017-4967-a8ae-0a30dacf3727&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.164081+00:00 FINDING\_GENERATED: WS-HDR-005: Missing referrer-policy {&quot;finding\_id&quot;: &quot;33fdef47-5741-473f-82ad-e0d26251dc1b&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.165863+00:00 FINDING\_GENERATED: WS-HDR-006: Missing permissions-policy {&quot;finding\_id&quot;: &quot;ed0ec6f6-9351-45af-9777-3fd8338c65d9&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.167701+00:00 FINDING\_GENERATED: WS-HDR-007: Missing cross-origin-opener-policy {&quot;finding\_id&quot;: &quot;de36cd08-eb40-449a-b863-2cb65937647f&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.169618+00:00 FINDING\_GENERATED: WS-HDR-008: Missing cross-origin-resource-policy {&quot;finding\_id&quot;: &quot;36cde7e2-0d22-486d-a7ef-c269a83ea232&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.173977+00:00 FINDING\_GENERATED: WS-CK-001: Cookie session: Secure absent {&quot;finding\_id&quot;: &quot;0f9754ee-9316-4d84-aebc-c04c409265d4&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.174969+00:00 FINDING\_GENERATED: WS-CK-002: Cookie session: HttpOnly absent {&quot;finding\_id&quot;: &quot;8a4ee996-3996-40d2-a524-8a7369c49782&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.175942+00:00 FINDING\_GENERATED: WS-CK-003: Cookie session: SameSite review {&quot;finding\_id&quot;: &quot;cb0d7616-4e11-4ff1-8f42-1e5f0c828292&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.177856+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;22930c34-a612-401a-b5fe-cdbc0bb383a3&quot;, &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;}

2026-10-07T19:41:48.183653+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;76621c17-6016-46a8-92c8-34089ae8a908&quot;, &quot;evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;}

2026-10-07T19:41:48.189244+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;505d592b-b0f7-43b6-b66e-be178c73430f&quot;, &quot;evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;}

2026-10-07T19:41:48.190920+00:00 FINDING\_GENERATED: WS-HDR-001: Missing content-security-policy {&quot;finding\_id&quot;: &quot;9dff689d-4849-48a5-ab67-0b91ce04b1b5&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.192831+00:00 FINDING\_GENERATED: WS-HDR-003: Missing x-content-type-options {&quot;finding\_id&quot;: &quot;f8b1c27b-7935-4f81-9325-3172076d9293&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.194080+00:00 FINDING\_GENERATED: WS-HDR-004: Missing x-frame-options {&quot;finding\_id&quot;: &quot;d13fdebc-21ac-489b-aba0-412ff264bf32&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.195329+00:00 FINDING\_GENERATED: WS-HDR-005: Missing referrer-policy {&quot;finding\_id&quot;: &quot;a2651e1a-6a5d-489b-a3b9-688447119723&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.196599+00:00 FINDING\_GENERATED: WS-HDR-006: Missing permissions-policy {&quot;finding\_id&quot;: &quot;7aa052b0-4543-44d9-8e5c-c2be6051cf96&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.197932+00:00 FINDING\_GENERATED: WS-HDR-007: Missing cross-origin-opener-policy {&quot;finding\_id&quot;: &quot;54576baf-440a-4282-a80c-0f8cf242ba34&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.199261+00:00 FINDING\_GENERATED: WS-HDR-008: Missing cross-origin-resource-policy {&quot;finding\_id&quot;: &quot;cbd820eb-fe99-4f2f-ad15-bb53126eddfb&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.200121+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;1d50154e-e7cf-4159-a425-bdf381fe8682&quot;, &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;}

2026-10-07T19:41:48.205742+00:00 FINDING\_GENERATED: WS-CORS-002: Wildcard origin with credentials {&quot;finding\_id&quot;: &quot;9c46fc22-c53d-4893-89fd-36f48a97f869&quot;, &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

2026-10-07T19:41:48.206467+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;31ace72f-ad18-4fad-a7d8-7d2457732523&quot;, &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

2026-10-07T19:41:48.207882+00:00 FINDING\_GENERATED: WS-API-001: Sensitive-looking response fields {&quot;finding\_id&quot;: &quot;6598e0d1-1892-45bd-899c-56314bd958bc&quot;, &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;}

2026-10-07T19:41:48.212356+00:00 FINDING\_GENERATED: WS-DISC-004: Verbose server error observed {&quot;finding\_id&quot;: &quot;8340818d-5a59-4904-afc8-1f22c35020e3&quot;, &quot;evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

2026-10-07T19:41:48.213057+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;6014e66d-fbb0-49f1-bcc1-b5ac12e916ab&quot;, &quot;evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;}

2026-10-07T19:41:48.217499+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;d7f56ee1-7e9c-47be-a85b-1aadc1f5b7d4&quot;, &quot;evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;}

2026-10-07T19:41:48.221880+00:00 FINDING\_GENERATED: WS-DISC-005: Source map reference exposed {&quot;finding\_id&quot;: &quot;872dd044-4711-42a9-820b-161276199807&quot;, &quot;evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

2026-10-07T19:41:48.222551+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;611ff291-ad29-4b00-9571-47f9784e2c61&quot;, &quot;evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;}

2026-10-07T19:41:48.223132+00:00 PASSIVE\_ANALYSIS\_COMPLETED: Deterministic analysis of persisted evidence; no requests issued {}

2026-10-07T19:41:48.224031+00:00 EXECUTION\_COMPLETED: Collection finished; inspect recorded errors and limit events for coverage gaps {&quot;network\_operations&quot;: 8, &quot;remaining\_queue&quot;: 0, &quot;successful\_collection&quot;: true}

2026-10-07T19:41:48.549593+00:00 EXECUTION\_STARTED: Explicit safe checks started {}

2026-10-07T19:41:48.550977+00:00 SECURITY\_CHECK\_EXECUTED: Only explicit configured paths will be requested {&quot;safe\_paths&quot;: \[&quot;/.env&quot;, &quot;/.git/&quot;, &quot;/debug&quot;, &quot;/cors&quot;\], &quot;cors\_probe&quot;: true}

2026-10-07T19:41:48.551312+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/.env&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 1, &quot;elapsed\_seconds&quot;: 0.0013}

2026-10-07T19:41:48.560839+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;, &quot;transaction\_id&quot;: &quot;efdcea9c-5656-4c1f-b70f-ae587b144282&quot;}

2026-10-07T19:41:48.562018+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;86ead582-eeed-4965-87db-98e4e20181a6&quot;, &quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.653164+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/.git/&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 2, &quot;elapsed\_seconds&quot;: 0.1027}

2026-10-07T19:41:48.666768+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;, &quot;transaction\_id&quot;: &quot;19cdf9a7-9cd5-4bf0-9ada-d69486c5a6f2&quot;}

2026-10-07T19:41:48.668057+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;2c7a732a-1c35-4ab1-b2b5-ed5aa52000b4&quot;, &quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.755258+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/debug&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 3, &quot;elapsed\_seconds&quot;: 0.2047}

2026-10-07T19:41:48.773387+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;, &quot;transaction\_id&quot;: &quot;6d13f0f3-98d9-4233-b92f-5d3a6478da58&quot;}

2026-10-07T19:41:48.775258+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;fe4450ed-14ee-4ce9-ac0e-2fcde6eea809&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.857383+00:00 NETWORK\_ATTEMPT: HTTP\_GET authorized by central policy {&quot;url&quot;: &quot;http://127.0.0.1:9998/cors&quot;, &quot;operation&quot;: &quot;HTTP\_GET&quot;, &quot;request\_number&quot;: 4, &quot;elapsed\_seconds&quot;: 0.3069}

2026-10-07T19:41:48.880231+00:00 HTTP\_COLLECTED: HTTP 200 collected {&quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;, &quot;transaction\_id&quot;: &quot;470df2cd-547f-4838-a7c1-77cd4b16915e&quot;}

2026-10-07T19:41:48.882562+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from HTTP {&quot;endpoint\_id&quot;: &quot;0ad4759e-2047-4a9b-a33f-5821f6f65d24&quot;, &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:48.911216+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;ea75df85-a484-4bb6-b089-cca4eb62eac0&quot;, &quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

2026-10-07T19:41:48.912293+00:00 FINDING\_GENERATED: WS-DISC-002: Potential environment-file exposure {&quot;finding\_id&quot;: &quot;80240cc2-13e5-4795-b5bc-496ee1d32556&quot;, &quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;}

2026-10-07T19:41:48.918543+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;2650eb1e-893e-4e5f-bb39-4375afbe54a6&quot;, &quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

2026-10-07T19:41:48.919549+00:00 FINDING\_GENERATED: WS-DISC-001: Potential source-control metadata exposure {&quot;finding\_id&quot;: &quot;35fc5bf6-ef6b-45bc-8aa0-7b49d1d5f503&quot;, &quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;}

2026-10-07T19:41:48.921389+00:00 FINDING\_GENERATED: WS-HDR-001: Missing content-security-policy {&quot;finding\_id&quot;: &quot;10968e0f-c78d-4eed-9e6d-b4e167f444f5&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.923433+00:00 FINDING\_GENERATED: WS-HDR-003: Missing x-content-type-options {&quot;finding\_id&quot;: &quot;b109b16e-b65b-4d46-89e9-33d89dd9a155&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.924846+00:00 FINDING\_GENERATED: WS-HDR-004: Missing x-frame-options {&quot;finding\_id&quot;: &quot;6af2d43a-028a-4028-8cb3-1ffd7b382120&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.926252+00:00 FINDING\_GENERATED: WS-HDR-005: Missing referrer-policy {&quot;finding\_id&quot;: &quot;62e992e8-d0d2-47fc-9cd2-3ca326fa232f&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.927685+00:00 FINDING\_GENERATED: WS-HDR-006: Missing permissions-policy {&quot;finding\_id&quot;: &quot;39d5a868-2a16-45e0-a697-6ce1ff2fae0f&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.929149+00:00 FINDING\_GENERATED: WS-HDR-007: Missing cross-origin-opener-policy {&quot;finding\_id&quot;: &quot;d1136c4d-081d-4536-8646-8b0313bb69cb&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.930562+00:00 FINDING\_GENERATED: WS-HDR-008: Missing cross-origin-resource-policy {&quot;finding\_id&quot;: &quot;c58f96e1-1849-4232-a0b7-991a2d1d5bce&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.931437+00:00 FINDING\_GENERATED: WS-DISC-003: Directory listing observed {&quot;finding\_id&quot;: &quot;7631b342-f442-40de-9e14-b6fd659e5b05&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.932242+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;b8e256be-96be-497e-843f-16d6cbd63e04&quot;, &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;}

2026-10-07T19:41:48.937819+00:00 FINDING\_GENERATED: WS-CORS-003: Potential unsafe credentialed origin reflection {&quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;, &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

2026-10-07T19:41:48.938586+00:00 FINDING\_GENERATED: WS-DISC-006: Server technology banner disclosed {&quot;finding\_id&quot;: &quot;ec6870f4-b5fe-4b18-bb25-cc485e9964a1&quot;, &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;}

2026-10-07T19:41:48.939100+00:00 PASSIVE\_ANALYSIS\_COMPLETED: Deterministic analysis of persisted evidence; no requests issued {}

2026-10-07T19:41:48.940676+00:00 EXECUTION\_COMPLETED: Collection finished; inspect recorded errors and limit events for coverage gaps {&quot;network\_operations&quot;: 4, &quot;remaining\_queue&quot;: 0, &quot;successful\_collection&quot;: true}

2026-10-07T19:41:49.532007+00:00 FINDING\_CONFIRMED: Analyst updated finding assessment; original automated facts retained {&quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;, &quot;changes&quot;: {&quot;status&quot;: &quot;CONFIRMED&quot;, &quot;analyst\_assessment&quot;: &quot;Confirmed the unsafe origin configuration in the owned fixture; authenticated data impact was not tested.&quot;, &quot;analyst\_severity&quot;: null, &quot;analyst\_confidence&quot;: null, &quot;priority\_override&quot;: &quot;HIGH&quot;, &quot;override\_reason&quot;: &quot;Prioritize configuration correction before production deployment.&quot;}}

2026-10-07T19:41:49.631948+00:00 ANALYST\_NOTE\_ADDED: Analyst added a note {&quot;note\_id&quot;: &quot;27d93f5f-44a2-4011-b29c-3ffa4e81da02&quot;, &quot;case\_id&quot;: null}

2026-10-07T19:41:50.039352+00:00 EVIDENCE\_CAPTURED: Redacted evidence image captured {&quot;evidence\_id&quot;: &quot;2d374e7a-f993-46bb-ba5f-259f95ab3885&quot;}

2026-10-07T19:41:50.705838+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from MANUAL {&quot;endpoint\_id&quot;: &quot;4cb96feb-864d-4582-ad1b-824f39d63716&quot;, &quot;evidence\_id&quot;: &quot;deb84e15-fc39-4ea1-82d7-b319ef378328&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:50.821774+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from OPENAPI {&quot;endpoint\_id&quot;: &quot;72e221fc-80fd-45b3-bd8c-ef6c5fa833da&quot;, &quot;evidence\_id&quot;: &quot;d76959f6-69b6-4e65-bc28-d1e0831ea81a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:50.822638+00:00 ENDPOINT\_DISCOVERED: Endpoint inventoried from OPENAPI {&quot;endpoint\_id&quot;: &quot;2af5d264-46c3-44b5-acc5-069e7f6e7f28&quot;, &quot;evidence\_id&quot;: &quot;d76959f6-69b6-4e65-bc28-d1e0831ea81a&quot;, &quot;in\_scope&quot;: true}

2026-10-07T19:41:50.822906+00:00 OPENAPI\_IMPORTED: Imported 2 operations without requests {&quot;evidence\_id&quot;: &quot;d76959f6-69b6-4e65-bc28-d1e0831ea81a&quot;}

2026-10-07T19:41:51.208393+00:00 CASE\_CREATED: Assessment investigation case opened {&quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;}

2026-10-07T19:41:51.564570+00:00 ANALYST\_NOTE\_ADDED: Analyst added a note {&quot;note\_id&quot;: &quot;31135728-9d84-48b9-883a-d60d8f0193fd&quot;, &quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;}

2026-10-07T19:41:51.907428+00:00 CASE\_UPDATED: Case status: INVESTIGATING {&quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;, &quot;changes&quot;: {&quot;status&quot;: &quot;INVESTIGATING&quot;, &quot;title&quot;: &quot;Fixture CORS remediation case&quot;, &quot;description&quot;: &quot;Evidence-led configuration remediation and verification.&quot;, &quot;priority&quot;: &quot;HIGH&quot;, &quot;assigned\_analyst&quot;: &quot;Local fixture analyst&quot;}}

2026-10-07T19:41:52.315645+00:00 CASE\_UPDATED: Case status: REMEDIATION {&quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;, &quot;changes&quot;: {&quot;status&quot;: &quot;REMEDIATION&quot;, &quot;title&quot;: &quot;Fixture CORS remediation case&quot;, &quot;description&quot;: &quot;Evidence-led configuration remediation and verification.&quot;, &quot;priority&quot;: &quot;HIGH&quot;, &quot;assigned\_analyst&quot;: &quot;Local fixture analyst&quot;}}

2026-10-07T19:41:52.749574+00:00 CASE\_UPDATED: Case status: VERIFICATION {&quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;, &quot;changes&quot;: {&quot;status&quot;: &quot;VERIFICATION&quot;, &quot;title&quot;: &quot;Fixture CORS remediation case&quot;, &quot;description&quot;: &quot;Evidence-led configuration remediation and verification.&quot;, &quot;priority&quot;: &quot;HIGH&quot;, &quot;assigned\_analyst&quot;: &quot;Local fixture analyst&quot;}}

2026-10-07T19:41:53.182359+00:00 CASE\_UPDATED: Case status: CLOSED {&quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;, &quot;changes&quot;: {&quot;status&quot;: &quot;CLOSED&quot;, &quot;title&quot;: &quot;Fixture CORS remediation case&quot;, &quot;description&quot;: &quot;Evidence-led configuration remediation and verification.&quot;, &quot;priority&quot;: &quot;HIGH&quot;, &quot;assigned\_analyst&quot;: &quot;Local fixture analyst&quot;}}

2026-10-07T19:41:56.863451+00:00 PASSIVE\_ANALYSIS\_COMPLETED: Deterministic analysis of persisted evidence; no requests issued {}

## Appendix

Snapshot schema 1.0; generated 2026-10-07T19:41:57.177099+00:00

Evidence integrity hashes cover redacted canonical data/raw content. Original target bodies are not retained.

{  
  &quot;cases&quot;: \[  
    {  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;,  
      &quot;title&quot;: &quot;Fixture CORS remediation case&quot;,  
      &quot;description&quot;: &quot;Evidence-led configuration remediation and verification.&quot;,  
      &quot;scope&quot;: {  
        &quot;allowed\_hosts&quot;: \[  
          &quot;127.0.0.1&quot;  
        \],  
        &quot;excluded\_hosts&quot;: \[\],  
        &quot;excluded\_paths&quot;: \[  
          &quot;/admin&quot;,  
          &quot;/payments&quot;  
        \]  
      },  
      &quot;status&quot;: &quot;CLOSED&quot;,  
      &quot;priority&quot;: &quot;HIGH&quot;,  
      &quot;assigned\_analyst&quot;: &quot;Local fixture analyst&quot;,  
      &quot;id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;,  
      &quot;created\_at&quot;: &quot;2026-10-07T19:41:51.207137+00:00&quot;  
    }  
  \],  
  &quot;case\_findings&quot;: \[  
    {  
      &quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;,  
      &quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    }  
  \],  
  &quot;case\_evidence&quot;: \[  
    {  
      &quot;case\_id&quot;: &quot;faa5870c-73a0-4c96-bd30-c09d8d6588ce&quot;,  
      &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    }  
  \],  
  &quot;finding\_evidence&quot;: \[  
    {  
      &quot;finding\_id&quot;: &quot;d433aed7-9597-4e4d-b078-32d949de1a53&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;5b381559-b452-433f-a8fe-03d72dfd3df6&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;eab15af1-4017-4967-a8ae-0a30dacf3727&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;33fdef47-5741-473f-82ad-e0d26251dc1b&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;ed0ec6f6-9351-45af-9777-3fd8338c65d9&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;de36cd08-eb40-449a-b863-2cb65937647f&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;36cde7e2-0d22-486d-a7ef-c269a83ea232&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;0f9754ee-9316-4d84-aebc-c04c409265d4&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;8a4ee996-3996-40d2-a524-8a7369c49782&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;cb0d7616-4e11-4ff1-8f42-1e5f0c828292&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;22930c34-a612-401a-b5fe-cdbc0bb383a3&quot;,  
      &quot;evidence\_id&quot;: &quot;fec969bb-c018-44a4-9ea2-811b93f94712&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;76621c17-6016-46a8-92c8-34089ae8a908&quot;,  
      &quot;evidence\_id&quot;: &quot;03a211a7-c7c2-4076-80ba-8261360f302a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;505d592b-b0f7-43b6-b66e-be178c73430f&quot;,  
      &quot;evidence\_id&quot;: &quot;aa18999f-3222-43c4-a2af-b1bb1485cd6d&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;9dff689d-4849-48a5-ab67-0b91ce04b1b5&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;f8b1c27b-7935-4f81-9325-3172076d9293&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;d13fdebc-21ac-489b-aba0-412ff264bf32&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;a2651e1a-6a5d-489b-a3b9-688447119723&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;7aa052b0-4543-44d9-8e5c-c2be6051cf96&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;54576baf-440a-4282-a80c-0f8cf242ba34&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;cbd820eb-fe99-4f2f-ad15-bb53126eddfb&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;1d50154e-e7cf-4159-a425-bdf381fe8682&quot;,  
      &quot;evidence\_id&quot;: &quot;a67c26b6-a2cc-465d-b9ca-274fa09faf0a&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;9c46fc22-c53d-4893-89fd-36f48a97f869&quot;,  
      &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;31ace72f-ad18-4fad-a7d8-7d2457732523&quot;,  
      &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;6598e0d1-1892-45bd-899c-56314bd958bc&quot;,  
      &quot;evidence\_id&quot;: &quot;6a411f04-8e9f-403a-af84-153fa3b41f57&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;8340818d-5a59-4904-afc8-1f22c35020e3&quot;,  
      &quot;evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;6014e66d-fbb0-49f1-bcc1-b5ac12e916ab&quot;,  
      &quot;evidence\_id&quot;: &quot;047f2de6-faf1-49d1-916a-d75ebc72caab&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;d7f56ee1-7e9c-47be-a85b-1aadc1f5b7d4&quot;,  
      &quot;evidence\_id&quot;: &quot;d1f132e2-b82e-4a38-a697-d3e4dca0c289&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;872dd044-4711-42a9-820b-161276199807&quot;,  
      &quot;evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;611ff291-ad29-4b00-9571-47f9784e2c61&quot;,  
      &quot;evidence\_id&quot;: &quot;f7dcf338-7344-496d-8829-4e55485a47cf&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;ea75df85-a484-4bb6-b089-cca4eb62eac0&quot;,  
      &quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;80240cc2-13e5-4795-b5bc-496ee1d32556&quot;,  
      &quot;evidence\_id&quot;: &quot;9ce79b33-4360-4309-9db0-f569e489a2d4&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;2650eb1e-893e-4e5f-bb39-4375afbe54a6&quot;,  
      &quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;35fc5bf6-ef6b-45bc-8aa0-7b49d1d5f503&quot;,  
      &quot;evidence\_id&quot;: &quot;ca70165b-385e-4cb3-bcf5-46dbc61d1be8&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;10968e0f-c78d-4eed-9e6d-b4e167f444f5&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;b109b16e-b65b-4d46-89e9-33d89dd9a155&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;6af2d43a-028a-4028-8cb3-1ffd7b382120&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;62e992e8-d0d2-47fc-9cd2-3ca326fa232f&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;39d5a868-2a16-45e0-a697-6ce1ff2fae0f&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;d1136c4d-081d-4536-8646-8b0313bb69cb&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;c58f96e1-1849-4232-a0b7-991a2d1d5bce&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;7631b342-f442-40de-9e14-b6fd659e5b05&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;b8e256be-96be-497e-843f-16d6cbd63e04&quot;,  
      &quot;evidence\_id&quot;: &quot;555011e6-5d6d-43b6-8030-06317d643d3e&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;e919d8fd-0851-400d-86da-dc922ad108b8&quot;,  
      &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    },  
    {  
      &quot;finding\_id&quot;: &quot;ec6870f4-b5fe-4b18-bb25-cc485e9964a1&quot;,  
      &quot;evidence\_id&quot;: &quot;06ccc625-4223-4d47-9d73-3314144dd19b&quot;,  
      &quot;assessment\_id&quot;: &quot;e470520c-03be-4dd7-97d6-28a5f2e8a9f3&quot;  
    }  
  \],  
  &quot;rules&quot;: \[  
    {  
      &quot;id&quot;: &quot;WS-HDR-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing content-security-policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-SEC-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing strict-transport-security&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-003&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing x-content-type-options&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-004&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing x-frame-options&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-005&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing referrer-policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-006&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing permissions-policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-007&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing cross-origin-opener-policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-008&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Missing cross-origin-resource-policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-HDR-009&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Permissive Content-Security-Policy&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CK-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Session-like cookie without Secure&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CK-002&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Session-like cookie without HttpOnly&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CK-003&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Cookie SameSite requires review&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CK-004&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Broad cookie domain or path&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CORS-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Wildcard CORS origin observed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CORS-002&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Wildcard origin with credentials&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-CORS-003&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Potential unsafe credentialed origin reflection&quot;,  
      &quot;safety\_level&quot;: &quot;SAFE\_READ\_ONLY&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Potential source-control metadata exposure&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-002&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Potential environment-file exposure&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-003&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Directory listing observed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-004&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Verbose server error observed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-005&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Source map reference exposed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-DISC-006&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Server technology banner disclosed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-API-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Sensitive-looking response fields&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-TLS-001&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Expired TLS certificate&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-TLS-002&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;TLS certificate hostname mismatch&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-TLS-003&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;TLS certificate validation failed&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    },  
    {  
      &quot;id&quot;: &quot;WS-TLS-004&quot;,  
      &quot;version&quot;: &quot;1.0.0&quot;,  
      &quot;name&quot;: &quot;Weak negotiated TLS or certificate algorithm&quot;,  
      &quot;safety\_level&quot;: &quot;PASSIVE&quot;  
    }  
  \]  
}
