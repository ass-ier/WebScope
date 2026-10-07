import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Camera, Plus, Upload, X } from 'lucide-react'
import { assessmentPath, useApi, useWrite } from '../lib/api'
import { assessmentIsReadOnly } from '../types'
import type { Assessment, Controls, DNS, Endpoint, Evidence, EvidenceDetail, Json, JsonObject, ScreenshotEvidence, TLS, Technology, TimelineEvent, Transaction, TransactionDetail } from '../types'
import { AssessmentPolicyNotice, AssessmentTrail, Badge, DataTable, ErrorNotice, Field, JsonView, Loading, Meta, PageHeader, QueryState, RecordLink, Section, Success, Tabs, date, human, shortId } from '../components/ui'
import { EndpointsTable, EvidenceTable, FindingsTable, TechnologyTable, TimelineList, TransactionTable } from '../components/records'

export function Endpoints() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Endpoint[]>(assessmentPath(assessmentId, 'endpoints'))
  const assessment = useApi<Assessment>(assessmentPath(assessmentId))
  const readOnly = assessmentIsReadOnly(assessment.data)
  const [form, setForm] = useState<'manual' | 'openapi' | null>(null)
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [parameters, setParameters] = useState('[]')
  const [document, setDocument] = useState('')
  const [error, setError] = useState('')
  const manual = useWrite<Endpoint>(assessmentPath(assessmentId, 'endpoints'))
  const imported = useWrite<unknown>(assessmentPath(assessmentId, 'openapi'))
  function parseObject(text: string): JsonObject {
    const value: unknown = JSON.parse(text)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('The OpenAPI document must be a JSON object.')
    return value as JsonObject
  }
  return <><PageHeader title="Endpoint inventory" description="Observed and supplied endpoints. Adding inventory does not send requests." actions={<><button className="button" disabled={readOnly} onClick={() => { setForm('openapi'); setError('') }}><Upload size={16} />Import OpenAPI</button><button className="button primary" disabled={readOnly} onClick={() => { setForm('manual'); setError('') }}><Plus size={16} />Add endpoint</button></>} />
    <AssessmentPolicyNotice query={assessment} />
    {form && !readOnly && <Section title={form === 'manual' ? 'Add a supplied endpoint' : 'Import an OpenAPI document'} action={<button className="icon-button" aria-label="Close endpoint form" onClick={() => setForm(null)}><X size={18} /></button>}><form className="stack" onSubmit={(event) => {
      event.preventDefault(); if (readOnly) return; setError('')
      try {
        if (form === 'manual') {
          const parsed: unknown = JSON.parse(parameters)
          if (!Array.isArray(parsed) || parsed.some((p) => !p || typeof p !== 'object' || Array.isArray(p))) throw new Error('Parameters must be a JSON array of objects.')
          manual.mutate({ url, method, parameters: parsed }, { onSuccess: () => { setUrl(''); setForm(null) } })
        } else imported.mutate({ document: parseObject(document) }, { onSuccess: () => { setDocument(''); setForm(null) } })
      } catch (e) { setError(e instanceof Error ? e.message : 'Invalid JSON.') }
    }}>
      {form === 'manual' ? <><div className="form-grid"><Field label="Endpoint URL"><input required type="url" maxLength={4096} value={url} onChange={(e) => setUrl(e.target.value)} /></Field><Field label="HTTP method" hint="The method is recorded only; this does not invoke it."><select value={method} onChange={(e) => setMethod(e.target.value)}>{['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m}>{m}</option>)}</select></Field></div><Field label="Parameters (JSON)" hint="Optional array of parameter objects."><textarea className="mono" rows={3} value={parameters} onChange={(e) => setParameters(e.target.value)} /></Field></> : <>
        <p className="muted">Import JSON-format OpenAPI to record methods, parameters, response schemas, and security requirements. Imported endpoints remain subject to scope; nothing is executed.</p>
        <Field label="OpenAPI JSON file" hint="Maximum 2 MB. JSON only; convert YAML locally before importing."><input type="file" accept=".json,application/json" onChange={async (e) => {
          const file = e.target.files?.[0]
          if (!file) return
          if (file.size > 2_000_000) { setError('The document exceeds the 2 MB import limit.'); return }
          try { setDocument(await file.text()); setError('') } catch { setError('Could not read the selected file. Choose it again or paste JSON below.') }
        }} /></Field><Field label="OpenAPI document"><textarea required className="mono" rows={10} spellCheck={false} value={document} onChange={(e) => setDocument(e.target.value)} /></Field>
      </>}
      <ErrorNotice error={error || (form === 'manual' ? manual.error : imported.error)} /><div className="actions"><button className="button primary" disabled={manual.isPending || imported.isPending}>{manual.isPending || imported.isPending ? 'Saving inventory…' : form === 'manual' ? 'Save endpoint' : 'Import inventory'}</button><button className="button" type="button" onClick={() => setForm(null)}>Cancel</button></div>
    </form></Section>}
    {manual.isSuccess && <Success>Endpoint saved with source evidence. No request was sent.</Success>}{imported.isSuccess && <Success>OpenAPI inventory imported. No endpoints were executed.</Success>}
    <QueryState query={query}>{(data) => <EndpointsTable records={data} />}</QueryState>
  </>
}

export function Technologies() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Technology[]>(assessmentPath(assessmentId, 'technologies'))
  return <><PageHeader title="Technologies" description="Evidence-backed fingerprinting. A detected technology is not itself a vulnerability." /><QueryState query={query}>{(data) => <TechnologyTable records={data} />}</QueryState></>
}
export function Transactions() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Transaction[]>(assessmentPath(assessmentId, 'transactions'))
  return <><PageHeader title="HTTP transactions" description="The recorded request and response, with sensitive values redacted at collection." /><QueryState query={query}>{(data) => <TransactionTable records={data} />}</QueryState></>
}
export function EvidenceExplorer() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Evidence[]>(assessmentPath(assessmentId, 'evidence'))
  const [type, setType] = useState('')
  return <><PageHeader title="Evidence explorer" description="Inspect what was observed, where it came from, and the records it supports." /><QueryState query={query}>{(data) => <><div className="filter-line"><Field label="Evidence type"><select value={type} onChange={(e) => setType(e.target.value)}><option value="">All evidence types</option>{[...new Set(data.map((r) => r.type))].sort().map((t) => <option key={t} value={t}>{human(t)}</option>)}</select></Field></div><EvidenceTable records={data.filter((r) => !type || r.type === type)} /></>}</QueryState></>
}

function rawHeaders(headers: JsonObject) { return Object.entries(headers).map(([name, value]) => `${name}: ${typeof value === 'string' ? value : JSON.stringify(value)}`).join('\n') }
export function TransactionViewer({ transaction }: { transaction: Transaction }) {
  const requestRaw = `${transaction.request.method} ${transaction.request.url}\n${rawHeaders(transaction.request.headers)}\n\nBody metadata: ${JSON.stringify(transaction.request.body_metadata)}`
  const responseRaw = `Status: ${transaction.response.status_code ?? 'No response'}\n${rawHeaders(transaction.response.headers)}\n\n${transaction.response.body || ''}`
  return <>
    {transaction.response.error && <ErrorNotice error={transaction.response.error} />}
    {transaction.response.truncated && <div className="notice">Response body was truncated at the configured capture limit. The displayed body is not the complete response.</div>}
    <div className="request-response"><Section title="HTTP request"><div className="request-line mono">{transaction.method} {transaction.url}</div><Tabs label="Request view" items={[
      { key: 'structured', label: 'Structured', content: <JsonView value={transaction.request} label="Structured HTTP request" /> },
      { key: 'raw', label: 'Raw request', content: <pre className="code-block" tabIndex={0} aria-label="Raw HTTP request"><code>{requestRaw}</code></pre> },
    ]} /></Section><Section title="HTTP response"><div className="request-line mono">{transaction.status_code ?? 'Request failed'} · {transaction.elapsed_ms.toFixed(1)} ms</div><Tabs label="Response view" items={[
      { key: 'structured', label: 'Structured', content: <JsonView value={transaction.response} label="Structured HTTP response" /> },
      { key: 'raw', label: 'Raw response', content: <pre className="code-block" tabIndex={0} aria-label="Raw HTTP response"><code>{responseRaw}</code></pre> },
    ]} /></Section></div>
    <Meta items={[['Response content type', transaction.response.content_type || 'Not reported'], ['Response bytes', transaction.response.content_length], ['Body SHA-256', <span className="mono break-all">{transaction.response.body_hash || 'Not recorded'}</span>], ['Request evidence', <RecordLink id={transaction.request_evidence_id} />], ['Response evidence', <RecordLink id={transaction.evidence_id} />]]} />
  </>
}
export function TransactionDetailPage() {
  const { id = '' } = useParams()
  const query = useApi<TransactionDetail>(`/transactions/${id}`)
  return <QueryState query={query}>{(data) => <><AssessmentTrail id={data.assessment_id} /><PageHeader title="HTTP transaction" description={<span className="mono">{data.id}</span>} /><p className="notice">Target content is displayed as inert text. Sensitive headers and tokens are redacted by the collector.</p><TransactionViewer transaction={data} />{data.endpoint_id && <p><Link to={`${assessmentPath(data.assessment_id, 'endpoints')}#endpoint-${data.endpoint_id}`}>Open affected endpoint</Link></p>}<Section title="Supporting evidence"><EvidenceTable records={data.evidence} /></Section></>}</QueryState>
}
function RedactedCapture({ id }: { id: string }) {
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const imageUrl = `/api/evidence/${encodeURIComponent(id)}/image`
  return <figure className="evidence-capture">
    <figcaption>Redacted evidence capture · not a target-browser screenshot</figcaption>
    <p className="field-hint">Rendered from already-redacted persisted text. No target page was opened and no target JavaScript was executed. Follow the source evidence link for the complete text.</p>
    {loading && <Loading label="Loading redacted capture…" />}
    {failed ? <ErrorNotice error="The redacted evidence image could not be loaded. Check the local API and retry." retry={() => { setAttempt(attempt + 1); setFailed(false); setLoading(true) }} /> :
      <div className="capture-image-scroll" tabIndex={0} role="region" aria-label="Redacted evidence capture image"><img key={attempt} src={imageUrl} alt="Redacted persisted evidence text capture" onLoad={() => setLoading(false)} onError={() => { setFailed(true); setLoading(false) }} /></div>}
    <a className="text-link" href={imageUrl} target="_blank" rel="noopener noreferrer">Open full-size redacted capture<span className="sr-only"> (opens a new tab)</span></a>
  </figure>
}
export function EvidenceDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const query = useApi<EvidenceDetail>(`/evidence/${id}`)
  const assessment = useApi<Assessment>(assessmentPath(query.data?.assessment_id || ''), Boolean(query.data))
  const readOnly = assessmentIsReadOnly(assessment.data)
  const capture = useWrite<ScreenshotEvidence, Record<string, never>>(`/evidence/${id}/capture`)
  const resetCapture = capture.reset
  useEffect(() => { resetCapture() }, [id, resetCapture])
  return <QueryState query={query}>{(data) => {
    const isScreenshot = data.type === 'SCREENSHOT'
    const visibleData = Object.fromEntries(Object.entries(data.data).filter(([key]) => key !== 'image_base64'))
    return <><AssessmentTrail id={data.assessment_id} /><PageHeader title={data.summary} description={<>Evidence <span className="mono">{shortId(data.id)}</span></>} actions={<><Badge value={data.type} />{!isScreenshot && <button className="button" disabled={readOnly || capture.isPending} onClick={() => capture.mutate({}, { onSuccess: (result) => navigate(`/evidence/${encodeURIComponent(result.id)}`) })}><Camera size={15} />{capture.isPending ? 'Capturing persisted text…' : 'Capture redacted evidence'}</button>}</>} />
      <AssessmentPolicyNotice query={assessment} /><ErrorNotice error={capture.error} />
      {!isScreenshot && <p className="field-hint">Capture creates a PNG from persisted redacted text only. It does not open or request the target.</p>}
      <Meta items={[['Source', <span className="mono">{data.source}</span>], ['Collected', date(data.created_at)], ['Collector', <span className="mono">{data.collector}</span>], ['Evidence ID', <span className="mono break-all">{data.id}</span>], ['SHA-256', <span className="mono break-all">{data.sha256}</span>]]} />
      {isScreenshot && <RedactedCapture key={data.id} id={data.id} />}
      <Section title={isScreenshot ? 'Capture metadata' : 'Source evidence'}><p className="muted section-intro">{isScreenshot ? 'The image is shown above. Embedded image bytes are omitted from this metadata view.' : 'Captured content is rendered as text, never executed. Sensitive values remain redacted.'}</p><Tabs label="Evidence view" items={[
        { key: 'structured', label: 'Structured', content: <JsonView value={visibleData} label="Structured evidence" /> },
        ...(!isScreenshot ? [{ key: 'raw', label: 'Raw evidence', content: <pre className="code-block evidence-raw" tabIndex={0} aria-label="Raw evidence"><code>{data.raw || 'No raw text was captured for this record. Inspect structured evidence instead.'}</code></pre> }] : []),
      ]} /></Section>
      <Section title="Evidence lineage"><DataTable rows={(data.lineage || []).map((link, index) => ({ ...link, id: `${link.parent_id}:${link.child_id}:${index}` }))} label="Evidence lineage" emptyTitle="No source or derived evidence links" emptyDescription="Derived observations and redacted captures retain links to their source evidence." columns={[
        { key: 'source', label: 'Source evidence', render: (link) => <RecordLink id={link.parent_id} /> },
        { key: 'relation', label: 'Relationship', render: (link) => human(link.relation) },
        { key: 'derived', label: 'Derived evidence', render: (link) => <RecordLink id={link.child_id} /> },
      ]} /></Section>
      <Section title="Related findings"><FindingsTable records={data.findings} /></Section><Section title="Related endpoints"><EndpointsTable records={data.endpoints} /></Section><Section title="Related transactions"><TransactionTable records={data.transactions} /></Section>
    </>
  }}</QueryState>
}

export function SecurityControls() {
  const { assessmentId = '' } = useParams()
  const controls = useApi<Controls>(assessmentPath(assessmentId, 'controls'))
  const dns = useApi<DNS[]>(assessmentPath(assessmentId, 'dns'))
  const tls = useApi<TLS[]>(assessmentPath(assessmentId, 'tls'))
  return <><PageHeader title="Security controls" description="Configuration observations, not blanket vulnerability claims. Follow the evidence before drawing a conclusion." /><Tabs label="Security control groups" items={[
    { key: 'headers', label: 'Headers', content: <QueryState query={controls}>{(data) => <DataTable rows={data.headers} label="Security headers" emptyTitle="No header observations" emptyDescription="Collect and analyze an HTTP response to inspect response security controls." search={(r) => `${r.name} ${r.value} ${r.rationale}`} columns={[
      { key: 'name', label: 'Header', sort: (r) => r.name, render: (r) => <span className="mono">{r.name}</span> },
      { key: 'present', label: 'Observation', render: (r) => <Badge value={r.present ? 'PRESENT' : 'NOT_OBSERVED'} /> },
      { key: 'value', label: 'Value / rationale', render: (r) => <><div className="mono break-all">{r.value || '—'}</div><div className="cell-secondary">{r.rationale}</div></> },
      { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
    ]} />}</QueryState> },
    { key: 'cookies', label: 'Cookies', content: <QueryState query={controls}>{(data) => <DataTable rows={data.cookies} label="Cookies" search={(r) => r.name} emptyTitle="No cookies observed" emptyDescription="Cookie values are redacted. Security attributes are retained for review." columns={[
      { key: 'name', label: 'Cookie name', render: (r) => <span className="mono">{r.name}</span> },
      { key: 'attributes', label: 'Security attributes & scope', render: (r) => <JsonView value={r.attributes} label={`Attributes for ${r.name}`} /> },
      { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
    ]} />}</QueryState> },
    { key: 'cors', label: 'CORS', content: <><p className="notice">A wildcard origin alone does not establish a vulnerability. Review credential behavior, response context, and the exact observed headers.</p><QueryState query={controls}>{(data) => <DataTable rows={data.cors} label="CORS observations" search={(r) => `${r.source} ${r.summary} ${JSON.stringify(r.data)}`} emptyTitle="No CORS observations" emptyDescription="Collect response headers or explicitly confirm a safe CORS check to record the observed policy." columns={[
      { key: 'origin', label: 'Allowed origin', render: (r) => <><span className="mono">{observationText(r.data.origin)}</span><div className="cell-secondary mono">{r.source}</div></> },
      { key: 'credentials', label: 'Allow credentials', render: (r) => <span className="mono">{observationText(r.data.allow_credentials)}</span> },
      { key: 'methods', label: 'Allowed methods', render: (r) => <span className="mono">{observationText(r.data.methods)}</span> },
      { key: 'headers', label: 'Allowed headers', render: (r) => <span className="mono">{observationText(r.data.headers)}</span> },
      { key: 'context', label: 'Request / vary', render: (r) => <><div className="mono">{observationText(r.data.request_origin)}</div><div className="cell-secondary">Vary: {observationText(r.data.vary)}</div></> },
      { key: 'evidence', label: 'Evidence', render: (r) => <div className="stack"><RecordLink id={r.id}>CORS observation</RecordLink>{typeof r.data.source_evidence_id === 'string' && <RecordLink id={r.data.source_evidence_id}>Source response</RecordLink>}</div> },
    ]} />}</QueryState></> },
    { key: 'dns', label: 'DNS', content: <QueryState query={dns}>{(data) => <DataTable rows={data} label="DNS records" search={(r) => `${r.hostname} ${r.record_type} ${JSON.stringify(r.records)}`} emptyTitle="No DNS observations" emptyDescription="Enable DNS in a Safe HTTP assessment and explicitly run discovery. Passive mode performs no DNS requests." columns={[
      { key: 'host', label: 'Hostname', render: (r) => <span className="mono">{r.hostname}</span> },
      { key: 'type', label: 'Type', render: (r) => <Badge value={r.record_type} /> },
      { key: 'records', label: 'Records', render: (r) => <JsonView value={r.records} /> },
      { key: 'resolver', label: 'Resolver / TTL', render: (r) => <><span className="mono">{r.resolver}</span><div className="cell-secondary">TTL: {r.ttl === null ? 'Not reported' : `${r.ttl}s`}</div></> },
      { key: 'time', label: 'Observed', render: (r) => date(r.created_at) },
      { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
    ]} />}</QueryState> },
    { key: 'tls', label: 'TLS', content: <QueryState query={tls}>{(data) => <DataTable rows={data} label="TLS observations" search={(r) => `${r.hostname} ${JSON.stringify(r.details)}`} emptyTitle="No TLS observations" emptyDescription="TLS collection requires an HTTPS target, enabled TLS collection, and an explicit Safe HTTP discovery run." columns={[
      { key: 'hostname', label: 'Hostname', render: (r) => <span className="mono">{r.hostname}</span> },
      { key: 'certificate', label: 'Certificate & connection details', render: (r) => <details className="record-details"><summary>Inspect certificate</summary><JsonView value={r.details} label="Certificate details" /></details> },
      { key: 'time', label: 'Observed', render: (r) => date(r.created_at) },
      { key: 'evidence', label: 'Evidence', render: (r) => <RecordLink id={r.evidence_id} /> },
    ]} />}</QueryState> },
  ]} /></>
}
function observationText(value: Json | undefined) {
  return value === undefined || value === null || value === '' ? 'Not observed' : typeof value === 'string' ? value : JSON.stringify(value)
}
export function Timeline() {
  const { assessmentId = '' } = useParams()
  const query = useApi<TimelineEvent[]>(assessmentPath(assessmentId, 'timeline'))
  return <><PageHeader title="Assessment timeline" description="A chronological audit trail of collection, analysis, analyst decisions, and exports." /><QueryState query={query}>{(data) => <TimelineList records={data} />}</QueryState></>
}
