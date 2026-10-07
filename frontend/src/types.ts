export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
export type JsonObject = { [key: string]: Json }
export const severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const
export type Severity = typeof severities[number]
export const confidences = ['LOW', 'MEDIUM', 'HIGH'] as const
export type Confidence = typeof confidences[number]
export const findingStatuses = ['NEW', 'REVIEWING', 'CONFIRMED', 'FALSE_POSITIVE', 'NEEDS_VERIFICATION', 'DISMISSED'] as const
export type FindingStatus = typeof findingStatuses[number]
export const caseStatuses = ['OPEN', 'INVESTIGATING', 'REMEDIATION', 'VERIFICATION', 'CLOSED'] as const
export type CaseStatus = typeof caseStatuses[number]
export const caseTransitions: Record<CaseStatus, readonly CaseStatus[]> = {
  OPEN: ['INVESTIGATING'],
  INVESTIGATING: ['OPEN', 'REMEDIATION'],
  REMEDIATION: ['INVESTIGATING', 'VERIFICATION'],
  VERIFICATION: ['REMEDIATION', 'CLOSED'],
  CLOSED: ['INVESTIGATING'],
}
export interface Identity { id: string; created_at: string }
export interface Configuration {
  mode: 'PASSIVE' | 'SAFE_HTTP'
  max_requests: number
  rate_per_second: number
  timeout_seconds: number
  max_body_bytes: number
  max_redirects: number
  max_depth: number
  max_duration_seconds: number
  links: boolean
  javascript: boolean
  robots: boolean
  sitemap: boolean
  dns: boolean
  tls: boolean
  availability: boolean
  methods: boolean
  allow_private_network: boolean
  allowed_ports: number[]
  safe_paths: string[]
  exposure: 'INTERNAL' | 'INTERNET'
  asset_importance: 'LOW' | 'STANDARD' | 'PRODUCTION'
  authentication_context: 'UNKNOWN' | 'REQUIRED' | 'NOT_REQUIRED'
}
export interface Scope {
  allowed_hosts: string[]
  excluded_hosts: string[]
  excluded_paths: string[]
}
export interface AssessmentCreate {
  name: string
  description: string
  target: string
  scope: Scope
  config: Configuration
  authorized: boolean
  authorization_note: string
}
export interface Assessment extends Identity, AssessmentCreate {
  status: 'DRAFT' | 'READY' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'ARCHIVED'
  updated_at: string
  authorized_at: string | null
  counts: Record<'hosts' | 'endpoints' | 'apis' | 'technologies' | 'transactions' | 'evidence' | 'findings' | 'cases', number>
  severity_counts: Record<Severity, number>
}
export function assessmentIsReadOnly(assessment?: Assessment) {
  return !assessment || assessment.status === 'ARCHIVED' || assessment.status === 'RUNNING'
}
export interface Evidence extends Identity {
  assessment_id: string
  type: string
  source: string
  summary: string
  data: JsonObject
  raw: string
  sha256: string
  collector: string
}
export interface ScreenshotEvidence extends Evidence {
  type: 'SCREENSHOT'
  data: JsonObject & {
    source_evidence_id: string
    media_type: 'image/png'
    width: number
    height: number
    image_base64: string
    rendering: string
  }
}
export interface EvidenceLineage {
  parent_id: string
  child_id: string
  assessment_id: string
  relation: string
}
export interface Observed extends Identity { assessment_id: string; evidence_id: string }
export interface Host extends Observed { hostname: string; addresses: string[] }
export interface Endpoint extends Observed {
  url: string; method: string; source: string; content_type: string
  authentication: string; parameters: JsonObject[]; details: JsonObject; in_scope: boolean
}
export interface Technology extends Observed {
  name: string; category: string; version: string | null; confidence: Confidence
  rationale: string; endpoint_id: string | null
}
export interface Transaction extends Observed {
  request_evidence_id: string; endpoint_id: string | null
  method: string; url: string; status_code: number | null; elapsed_ms: number
  request: { method: string; url: string; headers: JsonObject; query: Json; body_metadata: Json; timestamp: string }
  response: {
    status_code: number | null; headers: JsonObject; content_type: string; content_length: number
    body_hash: string; body: string; elapsed_ms: number; redirect: Json; truncated: boolean; error?: string
  }
}
export interface DNS extends Observed { hostname: string; record_type: string; ttl: number | null; resolver: string; records: Json[] }
export interface TLS extends Observed { hostname: string; details: JsonObject }
export interface Header extends Observed { name: string; present: boolean; value: string; rationale: string }
export interface Cookie extends Observed { name: string; attributes: JsonObject }
export interface Controls { headers: Header[]; cookies: Cookie[]; cors: Evidence[] }
export interface DetectionRule {
  id: string; version: string; name: string; category: string; description: string
  severity: Severity; confidence: Confidence; required_evidence: string[]
  request_type: string; safety_level: string; remediation: string; references: string[]
}
export interface Finding extends Identity {
  assessment_id: string; evidence_id: string; endpoint_id: string | null
  rule_id: string; rule_version: string; title: string; category: string
  severity: Severity; confidence: Confidence; status: FindingStatus
  description: string; rationale: string; impact: string; remediation: string; references: string[]
  affected_asset: string; automated: JsonObject; analyst_assessment: string
  analyst_severity: Severity | null; analyst_confidence: Confidence | null
  priority_override: Severity | null; override_reason: string
}
export interface FindingUpdate {
  status: FindingStatus
  analyst_assessment: string
  analyst_severity: Severity | null
  analyst_confidence: Confidence | null
  priority_override: Severity | null
  override_reason: string
}
export interface Note extends Identity { assessment_id: string; finding_id: string | null; case_id: string | null; author: string; content: string; evidence_id: string }
export interface Risk {
  factors: { severity: Severity; confidence: Confidence; exposure: string; asset_importance: string; authentication_context: string; potential_impact: string }
  score: number; automated_priority: Severity; priority: Severity; explanation: string; override_reason: string
}
export interface FindingDetail extends Finding { evidence: Evidence[]; transactions: Transaction[]; rule: DetectionRule; notes: Note[]; risk: Risk }
export interface EvidenceDetail extends Evidence { findings: Finding[]; endpoints: Endpoint[]; transactions: Transaction[]; lineage: EvidenceLineage[] }
export interface TransactionDetail extends Transaction { evidence: Evidence[] }
export interface TimelineEvent extends Identity { assessment_id: string; event: string; message: string; data: JsonObject }
export interface Case extends Identity {
  assessment_id: string; title: string; description: string; scope: Scope
  status: CaseStatus; priority: Severity; assigned_analyst: string
}
export interface CaseDetail extends Case { findings: Finding[]; evidence: Evidence[]; notes: Note[]; timeline: TimelineEvent[] }
export interface CaseInput {
  title: string; description: string; priority: Severity; assigned_analyst: string; finding_ids: string[]; evidence_ids: string[]
}
export interface Report extends Identity {
  assessment_id: string; format: string; dataset: string; filename: string; sha256: string
}
export interface Graph {
  nodes: { id: string; label: string; kind: string; url?: string; evidence_id?: string }[]
  edges: { id: string; source: string; target: string; label: string }[]
}
