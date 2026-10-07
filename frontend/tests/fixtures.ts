import type { Assessment, CaseDetail, Configuration, DetectionRule, EvidenceDetail, FindingDetail, TransactionDetail } from '../src/types'

// Synthetic records for isolated frontend tests only; never imported by application code.
export function fixtures() {
  const config: Configuration = {
    mode: 'PASSIVE', max_requests: 30, rate_per_second: 2, timeout_seconds: 5,
    max_body_bytes: 262144, max_redirects: 5, max_depth: 1, max_duration_seconds: 120,
    links: true, javascript: true, robots: true, sitemap: true, dns: false, tls: true,
    availability: false, methods: false,
    allow_private_network: false, allowed_ports: [], safe_paths: [],
    exposure: 'INTERNAL', asset_importance: 'STANDARD', authentication_context: 'UNKNOWN',
  }
  const created_at = '2026-10-07T12:00:00Z'
  const assessment: Assessment = {
    id: 'a-1', created_at, updated_at: created_at, name: 'Fixture assessment',
    description: 'Synthetic frontend integration fixture.', target: 'https://fixture.test',
    authorized: true, authorization_note: 'Test-only permission', authorized_at: created_at,
    status: 'READY', scope: { allowed_hosts: ['fixture.test'], excluded_hosts: [], excluded_paths: ['/private'] },
    config, counts: { hosts: 0, endpoints: 0, apis: 0, technologies: 0, transactions: 1, evidence: 1, findings: 1, cases: 0 },
    severity_counts: { INFO: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0 },
  }
  const rule: DetectionRule = {
    id: 'WS-TEST-001', version: '1.0', name: 'Fixture response header rule', category: 'HEADERS',
    description: 'A synthetic deterministic rule for test coverage.', severity: 'MEDIUM', confidence: 'HIGH',
    required_evidence: ['HTTP_RESPONSE'], request_type: 'NONE', safety_level: 'PASSIVE',
    remediation: 'Set the appropriate policy.', references: ['https://developer.mozilla.org/'],
  }
  const evidence: EvidenceDetail = {
    id: 'e-1', assessment_id: 'a-1', created_at, type: 'HTTP_RESPONSE', source: 'https://fixture.test/',
    summary: 'Captured fixture response', data: { headers: { authorization: '[REDACTED]' }, status_code: 200 },
    raw: '<script>window.untrustedTarget = true</script>\nAuthorization: [REDACTED]',
    sha256: 'a'.repeat(64), collector: 'webscope/test', findings: [], endpoints: [], transactions: [], lineage: [],
  }
  const transaction: TransactionDetail = {
    id: 't-1', assessment_id: 'a-1', evidence_id: 'e-1', request_evidence_id: 'e-request', endpoint_id: null,
    created_at, method: 'GET', url: 'https://fixture.test/', status_code: 200, elapsed_ms: 14.2,
    request: { method: 'GET', url: 'https://fixture.test/', headers: { Authorization: '[REDACTED]' }, query: {}, body_metadata: {}, timestamp: created_at },
    response: { status_code: 200, headers: { 'Content-Type': 'text/html' }, content_type: 'text/html', content_length: 60, body_hash: 'b'.repeat(64), body: evidence.raw, elapsed_ms: 14.2, redirect: null, truncated: true },
    evidence: [evidence],
  }
  const finding: FindingDetail = {
    id: 'f-1', assessment_id: 'a-1', created_at, evidence_id: 'e-1', endpoint_id: null,
    rule_id: rule.id, rule_version: '1.0', title: 'Missing fixture policy', category: 'HEADERS',
    severity: 'MEDIUM', confidence: 'HIGH', status: 'NEW',
    description: 'The recorded response did not include the expected policy.',
    rationale: 'The policy header was absent from response evidence e-1.',
    impact: 'Potentially weaker browser isolation.', remediation: 'Review and apply the required policy.',
    references: rule.references, affected_asset: 'https://fixture.test/', automated: { header: 'fixture-policy', present: false },
    analyst_assessment: '', analyst_severity: null, analyst_confidence: null, priority_override: null, override_reason: '',
    evidence: [evidence], transactions: [transaction], notes: [], rule,
    risk: { factors: { severity: 'MEDIUM', confidence: 'HIGH', exposure: 'INTERNAL', asset_importance: 'STANDARD', authentication_context: 'UNKNOWN', potential_impact: 'Browser isolation' }, score: 4.2, automated_priority: 'MEDIUM', priority: 'MEDIUM', explanation: 'Medium severity, high confidence, and internal exposure determine this priority.', override_reason: '' },
  }
  const caseDetail: CaseDetail = {
    id: 'c-1', assessment_id: 'a-1', created_at, title: 'Fixture policy investigation', description: 'Review browser controls.',
    scope: assessment.scope, status: 'OPEN', priority: 'MEDIUM', assigned_analyst: 'Test analyst', findings: [finding], evidence: [evidence], notes: [], timeline: [],
  }
  return { config, assessment, rule, evidence, transaction, finding, caseDetail }
}
