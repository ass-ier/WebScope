import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import type { Endpoint, Evidence, Finding, Technology, TimelineEvent, Transaction } from '../types'
import { Badge, DataTable, Empty, JsonView, RecordLink, date, human } from './ui'

export function EvidenceTable({ records }: { records: Evidence[] }) {
  return <DataTable rows={records} label="Evidence" search={(r) => `${r.id} ${r.type} ${r.source} ${r.summary}`} emptyTitle="No evidence collected" emptyDescription="Run authorized collection or add inventory to establish a source record." columns={[
    { key: 'summary', label: 'Observation', render: (r) => <><RecordLink id={r.id}>{r.summary}</RecordLink><div className="cell-secondary mono">{r.source}</div></> },
    { key: 'type', label: 'Type', sort: (r) => r.type, render: (r) => <Badge value={r.type} /> },
    { key: 'collector', label: 'Collector', render: (r) => <span className="mono">{r.collector}</span> },
    { key: 'created', label: 'Collected', sort: (r) => r.created_at, render: (r) => <time dateTime={r.created_at}>{date(r.created_at)}</time> },
  ]} />
}
export function FindingsTable({ records, filters, severityBasis = 'automated' }: { records: Finding[]; filters?: React.ReactNode; severityBasis?: 'automated' | 'effective' }) {
  const severity = (record: Finding) => severityBasis === 'effective' ? record.analyst_severity || record.severity : record.severity
  return <DataTable rows={records} label="Findings" filters={filters} search={(r) => `${r.title} ${r.affected_asset} ${r.rule_id} ${r.category}`} emptyTitle="No findings in this view" emptyDescription="Run deterministic analysis on collected evidence. No findings does not establish that a target is secure." columns={[
    { key: 'finding', label: 'Finding / affected asset', render: (r) => <><RecordLink kind="findings" id={r.id}>{r.title}</RecordLink><div className="cell-secondary mono">{r.affected_asset}</div></> },
    { key: 'severity', label: severityBasis === 'effective' ? 'Effective severity' : 'Severity', sort: (r) => ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(severity(r)), render: (r) => <><Badge value={severity(r)} severity />{severityBasis === 'effective' && r.analyst_severity && <div className="cell-secondary">Analyst override · automated {human(r.severity)}</div>}</> },
    { key: 'confidence', label: 'Confidence', sort: (r) => r.confidence, render: (r) => human(r.confidence) },
    { key: 'status', label: 'Analyst status', sort: (r) => r.status, render: (r) => <Badge value={r.status} /> },
    { key: 'rule', label: 'Rule', render: (r) => <span className="mono">{r.rule_id} <span className="muted">v{r.rule_version}</span></span> },
    { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
  ]} />
}
export function EndpointsTable({ records }: { records: Endpoint[] }) {
  const location = useLocation()
  useEffect(() => {
    if (!location.hash.startsWith('#endpoint-')) return
    const element = document.getElementById(location.hash.slice(1))
    if (element instanceof HTMLDetailsElement) { element.open = true; element.scrollIntoView({ block: 'center' }) }
  }, [records, location.hash])
  return <DataTable rows={records} label="Endpoints" search={(r) => `${r.url} ${r.method} ${r.source} ${r.authentication} ${r.content_type}`} emptyTitle="No endpoints in inventory" emptyDescription="Add an endpoint, import an OpenAPI document, or explicitly run discovery." columns={[
    { key: 'method', label: 'Method', sort: (r) => r.method, render: (r) => <span className="method">{r.method}</span> },
    { key: 'url', label: 'Endpoint / details', sort: (r) => r.url, render: (r) => <details id={`endpoint-${r.id}`} className="record-details"><summary className="mono">{r.url}</summary><div className="details-content"><dl className="inline-meta"><dt>Content type</dt><dd>{r.content_type || 'Unknown'}</dd><dt>Source</dt><dd>{r.source}</dd><dt>Authentication</dt><dd>{human(r.authentication)}</dd><dt>Observed</dt><dd>{date(r.created_at)}</dd></dl><h3>Parameters</h3><JsonView value={r.parameters} label="Endpoint parameters" /><h3>API schema, security & relationships</h3><JsonView value={r.details} label="Endpoint details" /></div></details> },
    { key: 'source', label: 'Source', sort: (r) => r.source, render: (r) => human(r.source) },
    { key: 'auth', label: 'Authentication', render: (r) => human(r.authentication) },
    { key: 'scope', label: 'Scope', render: (r) => <Badge value={r.in_scope ? 'IN_SCOPE' : 'OUT_OF_SCOPE'} /> },
    { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
  ]} />
}
export function TechnologyTable({ records }: { records: Technology[] }) {
  return <DataTable rows={records} label="Technologies" search={(r) => `${r.name} ${r.category} ${r.version || ''} ${r.rationale}`} emptyTitle="No technology observations" emptyDescription="Analyze collected headers, pages, and scripts. Technology matches always retain confidence and source evidence." columns={[
    { key: 'name', label: 'Technology', sort: (r) => r.name, render: (r) => <><strong>{r.name}</strong><div className="cell-secondary">{r.category}</div></> },
    { key: 'version', label: 'Version', render: (r) => <span className="mono">{r.version || 'Not disclosed'}</span> },
    { key: 'confidence', label: 'Confidence', sort: (r) => r.confidence, render: (r) => <Badge value={r.confidence} /> },
    { key: 'rationale', label: 'Observed signal', render: (r) => r.rationale },
    { key: 'endpoint', label: 'Endpoint', render: (r) => r.endpoint_id ? <Link to={`/assessments/${r.assessment_id}/endpoints#endpoint-${r.endpoint_id}`}>View endpoint</Link> : '—' },
    { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
  ]} />
}
export function TransactionTable({ records }: { records: Transaction[] }) {
  return <DataTable rows={records} label="HTTP transactions" search={(r) => `${r.url} ${r.method} ${r.status_code ?? ''}`} emptyTitle="No HTTP transactions" emptyDescription="Transactions appear after explicit Safe HTTP collection. Passive mode never sends target requests." columns={[
    { key: 'method', label: 'Method', render: (r) => <span className="method">{r.method}</span> },
    { key: 'request', label: 'Request URL', render: (r) => <RecordLink kind="transactions" id={r.id}><span className="mono">{r.url}</span></RecordLink> },
    { key: 'status', label: 'Status', sort: (r) => r.status_code || 0, render: (r) => r.status_code ?? <Badge value="REQUEST_FAILED" /> },
    { key: 'timing', label: 'Duration', sort: (r) => r.elapsed_ms, render: (r) => <span className="mono">{r.elapsed_ms.toFixed(1)} ms</span> },
    { key: 'created', label: 'Captured', sort: (r) => r.created_at, render: (r) => date(r.created_at) },
    { key: 'evidence', label: 'Response evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
  ]} />
}
export function TimelineList({ records }: { records: TimelineEvent[] }) {
  if (!records.length) return <Empty title="No activity recorded">Assessment actions and analyst decisions will appear here.</Empty>
  return <ol className="timeline">{[...records].sort((a, b) => b.created_at.localeCompare(a.created_at)).map((event) => <li key={event.id}><span className="timeline-dot" aria-hidden="true" /><div><div className="row-between"><strong>{human(event.event)}</strong><time dateTime={event.created_at}>{date(event.created_at)}</time></div><p>{event.message}</p>{Object.keys(event.data).length > 0 && <details><summary>Event details</summary><JsonView value={event.data} /></details>}</div></li>)}</ol>
}
