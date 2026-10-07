import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowRight, LockKeyhole } from 'lucide-react'
import { assessmentPath, useApi, useWrite } from '../lib/api'
import { assessmentIsReadOnly, confidences, findingStatuses, severities } from '../types'
import type { Assessment, Finding, FindingDetail, FindingUpdate, Severity } from '../types'
import { AssessmentPolicyNotice, AssessmentTrail, Badge, Empty, ErrorNotice, Field, JsonView, Meta, Notes, PageHeader, QueryState, RecordLink, Section, Success, date, human } from '../components/ui'
import { EvidenceTable, FindingsTable } from '../components/records'
import { TransactionViewer } from './inventory'

export function Findings() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Finding[]>(assessmentPath(assessmentId, 'findings'))
  const [params, setParams] = useSearchParams()
  const prioritized = params.get('view') === 'prioritized'
  const severity = params.get('severity') || ''
  const requestedStatus = params.get('status') || ''
  const status = prioritized && ['FALSE_POSITIVE', 'DISMISSED'].includes(requestedStatus) ? '' : requestedStatus
  const confidence = params.get('confidence') || ''
  const filter = (name: string, value: string) => setParams((previous) => { const next = new URLSearchParams(previous); if (value) next.set(name, value); else next.delete(name); return next })
  return <><PageHeader title="Findings" description="Deterministic observations awaiting analyst judgment. Severity and confidence are independent." /><div className="filter-line">
    <Field label="Finding view"><select value={prioritized ? 'prioritized' : ''} onChange={(e) => setParams((previous) => {
      const next = new URLSearchParams(previous)
      if (e.target.value) { next.set('view', e.target.value); if (['FALSE_POSITIVE', 'DISMISSED'].includes(next.get('status') || '')) next.delete('status') }
      else next.delete('view')
      return next
    })}><option value="">All observations · automated severity</option><option value="prioritized">Prioritized · effective severity</option></select></Field>
    <Field label="Severity"><select value={severity} onChange={(e) => filter('severity', e.target.value)}><option value="">All severities</option>{[...severities].reverse().map((v) => <option key={v} value={v}>{human(v)}</option>)}</select></Field>
    <Field label="Confidence"><select value={confidence} onChange={(e) => filter('confidence', e.target.value)}><option value="">All confidence levels</option>{confidences.map((v) => <option key={v} value={v}>{human(v)}</option>)}</select></Field>
    <Field label="Analyst status"><select value={status} onChange={(e) => filter('status', e.target.value)}><option value="">{prioritized ? 'All included review statuses' : 'All review statuses'}</option>{findingStatuses.filter((v) => !prioritized || !['FALSE_POSITIVE', 'DISMISSED'].includes(v)).map((v) => <option key={v} value={v}>{human(v)}</option>)}</select></Field>
    {(severity || status || confidence || prioritized) && <button className="button" onClick={() => setParams({})}>Clear filters</button>}
  </div>{prioritized && <p className="notice">Effective severity uses the analyst override when present. False positives and dismissed findings are excluded, matching the overview chart. Original automated facts remain unchanged.</p>}<QueryState query={query}>{(data) => <FindingsTable severityBasis={prioritized ? 'effective' : 'automated'} records={data.filter((f) => (!prioritized || !['FALSE_POSITIVE', 'DISMISSED'].includes(f.status)) && (!severity || (prioritized ? f.analyst_severity || f.severity : f.severity) === severity) && (!status || f.status === status) && (!confidence || f.confidence === confidence))} />}</QueryState></>
}

function AnalystReview({ finding, readOnly }: { finding: FindingDetail; readOnly: boolean }) {
  const [value, setValue] = useState<FindingUpdate>({
    status: finding.status, analyst_assessment: finding.analyst_assessment,
    analyst_severity: finding.analyst_severity, analyst_confidence: finding.analyst_confidence,
    priority_override: finding.priority_override, override_reason: finding.override_reason,
  })
  const mutation = useWrite<FindingDetail, FindingUpdate>(`/findings/${finding.id}`, 'PATCH')
  const set = <K extends keyof FindingUpdate>(key: K, next: FindingUpdate[K]) => { setValue({ ...value, [key]: next }); mutation.reset() }
  const finalDisposition = ['CONFIRMED', 'FALSE_POSITIVE', 'DISMISSED'].includes(value.status)
  const reclassified = Boolean(value.analyst_severity || value.analyst_confidence || value.priority_override)
  const missingExplanation = reclassified && !(value.analyst_assessment.trim() || (value.priority_override && value.override_reason.trim()))
  const missingConclusion = finalDisposition && !value.analyst_assessment.trim()
  const missingPriorityReason = Boolean(value.priority_override) && !value.override_reason.trim()
  return <Section title="Analyst assessment" className="review-section">
    <p className="section-intro muted">Your decisions are recorded separately. Automated severity, confidence, and source observations are never overwritten.</p>
    <form onSubmit={(event) => { event.preventDefault(); if (!readOnly && !missingExplanation && !missingConclusion && !missingPriorityReason) mutation.mutate(value) }}><fieldset className="stack" disabled={readOnly}>
      <Field label="Review status"><select value={value.status} onChange={(e) => set('status', e.target.value as FindingUpdate['status'])}>{findingStatuses.map((s) => <option key={s} value={s}>{human(s)}</option>)}</select></Field>
      <Field label="Analyst conclusion" hint={finalDisposition ? 'Required for confirmed, false-positive, or dismissed dispositions. Explain what you verified and why.' : 'Explain what you verified, what remains uncertain, and your reasoning.'}><textarea required={finalDisposition} rows={6} maxLength={20000} value={value.analyst_assessment} onChange={(e) => set('analyst_assessment', e.target.value)} /></Field>
      <div className="form-grid"><Field label="Analyst severity" hint="Optional reclassification."><select value={value.analyst_severity || ''} onChange={(e) => set('analyst_severity', (e.target.value || null) as FindingUpdate['analyst_severity'])}><option value="">No reclassification</option>{severities.map((s) => <option value={s} key={s}>{human(s)}</option>)}</select></Field><Field label="Analyst confidence" hint="Independent of severity."><select value={value.analyst_confidence || ''} onChange={(e) => set('analyst_confidence', (e.target.value || null) as FindingUpdate['analyst_confidence'])}><option value="">No reclassification</option>{confidences.map((s) => <option value={s} key={s}>{human(s)}</option>)}</select></Field></div>
      <Field label="Priority override" hint="Leave unset to use the calculated priority."><select value={value.priority_override || ''} onChange={(e) => set('priority_override', (e.target.value || null) as Severity | null)}><option value="">Use automated priority</option>{severities.map((s) => <option value={s} key={s}>{human(s)}</option>)}</select></Field>
      <Field label="Override reason" hint={value.priority_override ? 'Required. Explain the contextual reason for this priority.' : 'No priority override is applied.'}><textarea rows={3} required={Boolean(value.priority_override)} maxLength={10000} value={value.override_reason} onChange={(e) => set('override_reason', e.target.value)} /></Field>
      {missingExplanation && <p className="field-hint">Explain severity or confidence reclassification in the analyst conclusion. A priority override requires an explicit override reason.</p>}
      <ErrorNotice error={mutation.error} />{mutation.isSuccess && <Success>Analyst review saved. Automated facts remain unchanged.</Success>}
      <button className="button primary" disabled={readOnly || mutation.isPending || missingConclusion || missingExplanation || missingPriorityReason}>{mutation.isPending ? 'Saving review…' : 'Save analyst review'}</button>
    </fieldset></form>
  </Section>
}

function ReferenceLinks({ references }: { references: string[] }) {
  return references.length ? <ul className="reference-list">{references.map((reference, i) => <li key={`${reference}-${i}`}>{/^https?:\/\//i.test(reference) ? <a href={reference} target="_blank" rel="noopener noreferrer">{reference}<span className="sr-only"> (opens a new tab)</span></a> : reference}</li>)}</ul> : <p className="muted">No external references recorded.</p>
}
export function FindingDetailPage() {
  const { id = '' } = useParams()
  const query = useApi<FindingDetail>(`/findings/${id}`)
  const assessment = useApi<Assessment>(assessmentPath(query.data?.assessment_id || ''), Boolean(query.data))
  const readOnly = assessmentIsReadOnly(assessment.data)
  return <QueryState query={query}>{(finding) => <><AssessmentTrail id={finding.assessment_id} /><PageHeader title={finding.title} description={<span className="mono">{finding.affected_asset}</span>} actions={<Badge value={finding.status} />} />
    <AssessmentPolicyNotice query={assessment} />
    <div className="finding-facts"><div><span className="muted">Automated severity</span><Badge value={finding.severity} severity /></div><div><span className="muted">Automated confidence</span><Badge value={finding.confidence} /></div><div><span className="muted">Detection rule</span><span className="mono">{finding.rule_id} · v{finding.rule_version}</span></div><div className="immutable-label"><LockKeyhole size={14} />Immutable automated facts</div></div>
    <section className="rationale-panel"><h2>Why WebScope flagged this</h2><p>{finding.rationale}</p><div className="row-between"><span>{finding.category} · observed {date(finding.created_at)}</span><RecordLink id={finding.evidence_id}>Inspect triggering evidence <ArrowRight size={14} /></RecordLink></div></section>
    <div className="finding-layout"><div className="finding-main"><Section title="Automated observation"><p className="preserve description-copy">{finding.description}</p><Meta items={[['Affected asset', <span className="mono">{finding.affected_asset}</span>], ['Affected endpoint', finding.endpoint_id ? <Link to={`${assessmentPath(finding.assessment_id, 'endpoints')}#endpoint-${finding.endpoint_id}`}>Open endpoint inventory record</Link> : 'No endpoint relationship recorded']]} /><details><summary>Original automated facts</summary><JsonView value={finding.automated} /></details></Section>
      <Section title="Supporting evidence"><EvidenceTable records={finding.evidence} /></Section>
      <Section title="HTTP request & response">{finding.transactions.length ? finding.transactions.map((transaction) => <details className="transaction-detail" key={transaction.id} open={finding.transactions.length === 1}><summary><span className="method">{transaction.method}</span> <span className="mono">{transaction.url}</span> · {transaction.status_code ?? 'Failed'}</summary><TransactionViewer transaction={transaction} /><RecordLink kind="transactions" id={transaction.id}>Open full transaction</RecordLink></details>) : <Empty title="No HTTP transaction linked">This finding may be supported by DNS, TLS, imported inventory, or another non-HTTP observation. Inspect its source evidence.</Empty>}</Section>
      <Section title="Potential impact"><p className="preserve">{finding.impact}</p></Section><Section title="Remediation"><p className="preserve">{finding.remediation}</p></Section>
      <Section title="Detection rule"><Meta items={[['Rule ID', <span className="mono">{finding.rule.id}</span>], ['Version used', finding.rule_version], ['Rule name', finding.rule.name], ['Safety level', human(finding.rule.safety_level)], ['Request type', finding.rule.request_type], ['Required evidence', finding.rule.required_evidence.map(human).join(', ')]]} /><p>{finding.rule.description}</p><ReferenceLinks references={finding.references} /></Section>
      <Notes notes={finding.notes} path={`/findings/${finding.id}/notes`} readOnly={readOnly} />
    </div><aside className="finding-review"><Section title="Risk assessment"><div className="risk-priority"><span>Current priority</span><Badge value={finding.risk.priority} severity /></div><Meta items={[
      ['Severity', human(finding.risk.factors.severity)], ['Confidence', human(finding.risk.factors.confidence)],
      ['Exposure', human(finding.risk.factors.exposure)], ['Asset importance', human(finding.risk.factors.asset_importance)],
      ['Authentication context', human(finding.risk.factors.authentication_context)], ['Potential impact', finding.risk.factors.potential_impact],
      ['Calculated score', finding.risk.score], ['Automated priority', <Badge value={finding.risk.automated_priority} severity />],
    ]} /><p className="risk-explanation">{finding.risk.explanation}</p>{finding.risk.override_reason && <div className="notice"><div><strong>Analyst override</strong><p>{finding.risk.override_reason}</p></div></div>}</Section><AnalystReview key={finding.id} finding={finding} readOnly={readOnly} /><Link className="text-link" to={`${assessmentPath(finding.assessment_id)}/cases`}>View investigation cases <ArrowRight size={14} /></Link></aside></div>
  </>}</QueryState>
}
