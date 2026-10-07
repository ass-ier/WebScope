import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Download, Plus, X } from 'lucide-react'
import { assessmentPath, downloadReport, useApi, useWrite } from '../lib/api'
import { assessmentIsReadOnly, caseStatuses, caseTransitions, severities } from '../types'
import type { Assessment, Case, CaseDetail, CaseInput, CaseStatus, Configuration, DetectionRule, Evidence, Finding, Report, Severity } from '../types'
import { AssessmentPolicyNotice, AssessmentTrail, Badge, DataTable, ErrorNotice, Field, JsonView, Meta, Notes, PageHeader, QueryState, RecordLink, Section, Success, date, human, shortId } from '../components/ui'
import { EvidenceTable, FindingsTable, TimelineList } from '../components/records'
import { ConfigurationForm } from '../components/ConfigurationForm'

function RecordPicker({ title, records, selected, onChange }: { title: string; records: { id: string; label: string }[]; selected: string[]; onChange: (value: string[]) => void }) {
  const [search, setSearch] = useState('')
  const visible = records.filter((r) => `${r.label} ${r.id}`.toLowerCase().includes(search.toLowerCase()))
  return <fieldset className="record-picker"><legend>{title} <span className="muted">({selected.length} linked)</span></legend><label className="field"><span className="sr-only">Search {title.toLowerCase()} to link</span><input type="search" placeholder={`Search ${title.toLowerCase()}…`} value={search} onChange={(e) => setSearch(e.target.value)} /></label><div className="picker-list">{visible.length ? visible.map((r) => <label className="picker-item" key={r.id}><input type="checkbox" checked={selected.includes(r.id)} disabled={selected.length >= 200 && !selected.includes(r.id)} onChange={(e) => onChange(e.target.checked ? [...selected, r.id] : selected.filter((id) => id !== r.id))} /><span>{r.label}<span className="mono cell-secondary">{shortId(r.id)}</span></span></label>) : <p className="muted">No matching records available in this assessment.</p>}</div></fieldset>
}
function CaseForm({ assessmentId, existing, onSaved }: { assessmentId: string; existing?: CaseDetail; onSaved: (record: Case) => void }) {
  const [value, setValue] = useState<CaseInput>({
    title: existing?.title || '', description: existing?.description || '', assigned_analyst: existing?.assigned_analyst || '',
    priority: existing?.priority || 'MEDIUM', finding_ids: existing?.findings.map((r) => r.id) || [], evidence_ids: existing?.evidence.map((r) => r.id) || [],
  })
  const [status, setStatus] = useState<CaseStatus>(existing?.status || 'OPEN')
  const findings = useApi<Finding[]>(assessmentPath(assessmentId, 'findings'))
  const evidence = useApi<Evidence[]>(assessmentPath(assessmentId, 'evidence'))
  const assessment = useApi<Assessment>(assessmentPath(assessmentId))
  const readOnly = assessmentIsReadOnly(assessment.data)
  const mutation = useWrite<Case>(existing ? `/cases/${existing.id}` : assessmentPath(assessmentId, 'cases'), existing ? 'PATCH' : 'POST')
  const set = <K extends keyof CaseInput>(key: K, next: CaseInput[K]) => setValue({ ...value, [key]: next })
  return <form onSubmit={(event) => { event.preventDefault(); if (!readOnly) mutation.mutate(existing ? { ...value, status } : value, { onSuccess: onSaved }) }}><AssessmentPolicyNotice query={assessment} /><fieldset disabled={readOnly} className="stack">
    <div className="form-grid"><Field label="Case title"><input required maxLength={160} value={value.title} onChange={(e) => set('title', e.target.value)} /></Field><Field label="Assigned analyst"><input maxLength={100} value={value.assigned_analyst} onChange={(e) => set('assigned_analyst', e.target.value)} /></Field><Field label="Case priority"><select value={value.priority} onChange={(e) => set('priority', e.target.value as Severity)}>{severities.map((s) => <option value={s} key={s}>{human(s)}</option>)}</select></Field>{existing && <Field label="Case status" hint="Only the current stage and valid next or previous transitions are available."><select value={status} onChange={(e) => setStatus(e.target.value as CaseStatus)}>{caseStatuses.filter((s) => s === existing.status || caseTransitions[existing.status].includes(s)).map((s) => <option value={s} key={s}>{human(s)}</option>)}</select></Field>}<Field label="Case description" className="span-all"><textarea rows={4} maxLength={10000} value={value.description} onChange={(e) => set('description', e.target.value)} /></Field></div>
    <div className="form-grid"><QueryState query={findings}>{(data) => <RecordPicker title="Findings" records={data.map((r) => ({ id: r.id, label: r.title }))} selected={value.finding_ids} onChange={(next) => set('finding_ids', next)} />}</QueryState><QueryState query={evidence}>{(data) => <RecordPicker title="Evidence" records={data.map((r) => ({ id: r.id, label: r.summary }))} selected={value.evidence_ids} onChange={(next) => set('evidence_ids', next)} />}</QueryState></div>
    <ErrorNotice error={mutation.error} /><div><button className="button primary" disabled={readOnly || mutation.isPending || !value.title.trim() || findings.isPending || evidence.isPending || findings.isError || evidence.isError}>{mutation.isPending ? 'Saving…' : existing ? 'Save case' : 'Create case'}</button></div></fieldset>
  </form>
}
export function Cases() {
  const { assessmentId } = useParams()
  const query = useApi<Case[]>(assessmentId ? assessmentPath(assessmentId, 'cases') : '/cases')
  const assessments = useApi<Assessment[]>('/assessments', !assessmentId)
  const assessment = useApi<Assessment>(assessmentPath(assessmentId || ''), Boolean(assessmentId))
  const readOnly = Boolean(assessmentId) && assessmentIsReadOnly(assessment.data)
  const [create, setCreate] = useState(false)
  const [chosenId, setChosenId] = useState(assessmentId || '')
  const [status, setStatus] = useState('')
  const navigate = useNavigate()
  return <><PageHeader title={assessmentId ? 'Investigation cases' : 'All investigation cases'} description="Connect related findings and evidence to an owned investigation and lifecycle." actions={<button className="button primary" disabled={readOnly} onClick={() => setCreate(true)}><Plus size={16} />New case</button>} />
    {assessmentId && <AssessmentPolicyNotice query={assessment} />}
    {create && !readOnly && <Section title="Create an investigation case" action={<button className="icon-button" aria-label="Close case form" onClick={() => setCreate(false)}><X size={18} /></button>}>{!assessmentId && <QueryState query={assessments}>{(data) => <Field label="Assessment"><select value={chosenId} onChange={(e) => setChosenId(e.target.value)}><option value="">Select an assessment</option>{data.map((a) => <option key={a.id} value={a.id} disabled={assessmentIsReadOnly(a)}>{a.name}{assessmentIsReadOnly(a) ? ` · ${human(a.status)} (read-only)` : ''}</option>)}</select></Field>}</QueryState>}{chosenId ? <CaseForm key={chosenId} assessmentId={chosenId} onSaved={(record) => navigate(`/cases/${record.id}`)} /> : <p className="muted">Select the assessment whose findings and evidence belong to this case. <Link to="/assessments/new">Create an assessment</Link> if needed.</p>}</Section>}
    <div className="filter-line"><Field label="Case lifecycle"><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All lifecycle stages</option>{caseStatuses.map((s) => <option key={s} value={s}>{human(s)}</option>)}</select></Field></div>
    <QueryState query={query}>{(records) => <DataTable rows={records.filter((r) => !status || r.status === status)} label="Cases" search={(r) => `${r.title} ${r.assigned_analyst} ${r.description}`} emptyTitle="No cases in this view" emptyDescription="Create a case to group findings, preserve evidence, and track an investigation through remediation and verification." columns={[
      { key: 'title', label: 'Case', sort: (r) => r.title, render: (r) => <><RecordLink kind="cases" id={r.id}>{r.title}</RecordLink><div className="cell-secondary">{r.description}</div></> },
      { key: 'priority', label: 'Priority', render: (r) => <Badge severity value={r.priority} /> },
      { key: 'status', label: 'Lifecycle', sort: (r) => r.status, render: (r) => <Badge value={r.status} /> },
      { key: 'analyst', label: 'Assigned analyst', sort: (r) => r.assigned_analyst, render: (r) => r.assigned_analyst || 'Unassigned' },
      { key: 'assessment', label: 'Assessment', render: (r) => <Link className="mono" to={assessmentPath(r.assessment_id)}>{shortId(r.assessment_id)}</Link> },
      { key: 'created', label: 'Created', sort: (r) => r.created_at, render: (r) => date(r.created_at) },
    ]} />}</QueryState>
  </>
}
export function CaseDetailPage() {
  const { id = '' } = useParams()
  const query = useApi<CaseDetail>(`/cases/${id}`)
  const assessment = useApi<Assessment>(assessmentPath(query.data?.assessment_id || ''), Boolean(query.data))
  const readOnly = assessmentIsReadOnly(assessment.data)
  const [editing, setEditing] = useState(false)
  const [saved, setSaved] = useState(false)
  return <QueryState query={query}>{(record) => <><AssessmentTrail id={record.assessment_id} /><PageHeader title={record.title} description={<>Case <span className="mono">{record.id}</span></>} actions={<><Badge value={record.status} /><button className="button primary" disabled={readOnly} onClick={() => setEditing(!editing)}>{editing ? 'Close editor' : 'Edit case & links'}</button></>} />{saved && <Success>Case saved.</Success>}<AssessmentPolicyNotice query={assessment} />
    <div className="case-lifecycle" aria-label="Case lifecycle">{caseStatuses.map((status) => <span key={status} aria-current={status === record.status ? 'step' : undefined} className={status === record.status ? 'current' : ''}>{human(status)}</span>)}</div>
    {editing && !readOnly && <Section title="Case details & linked records"><CaseForm existing={record} assessmentId={record.assessment_id} onSaved={() => { setEditing(false); setSaved(true) }} /></Section>}
    <Section title="Investigation context"><p className="preserve">{record.description || 'No case description recorded.'}</p><Meta items={[['Priority', <Badge value={record.priority} severity />], ['Assigned analyst', record.assigned_analyst || 'Unassigned'], ['Created', date(record.created_at)], ['Assessment', <Link to={assessmentPath(record.assessment_id)}>Open assessment</Link>]]} /><details><summary>Recorded scope</summary><JsonView value={record.scope} /></details></Section>
    <Section title="Linked findings"><FindingsTable records={record.findings} /></Section><Section title="Linked evidence"><EvidenceTable records={record.evidence} /></Section><Notes notes={record.notes} path={`/cases/${record.id}/notes`} readOnly={readOnly} /><Section title="Case timeline"><TimelineList records={record.timeline} /></Section>
  </>}</QueryState>
}

export function Reports() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Report[]>(assessmentPath(assessmentId, 'reports'))
  const assessment = useApi<Assessment>(assessmentPath(assessmentId))
  const readOnly = assessmentIsReadOnly(assessment.data)
  const [format, setFormat] = useState('markdown')
  const [dataset, setDataset] = useState('assessment')
  const [downloadId, setDownloadId] = useState('')
  const [downloadError, setDownloadError] = useState<Error | null>(null)
  const mutation = useWrite<Report>(assessmentPath(assessmentId, 'reports'))
  const download = async (report: Report) => {
    setDownloadId(report.id); setDownloadError(null)
    try { await downloadReport(report.id, report.filename) }
    catch (e) { setDownloadError(e instanceof Error ? e : new Error('Download failed. Try again.')) }
    finally { setDownloadId('') }
  }
  return <><PageHeader title="Reports & exports" description="Generate reproducible assessment artifacts from saved evidence and analyst conclusions." />
    <AssessmentPolicyNotice query={assessment} />
    <Section title="Generate a report"><form className="report-form" onSubmit={(event) => { event.preventDefault(); if (!readOnly) mutation.mutate({ format, dataset }) }}><Field label="Report format"><select disabled={readOnly} value={format} onChange={(e) => setFormat(e.target.value)}><option value="markdown">Markdown · technical report</option><option value="json">JSON · machine-readable</option><option value="pdf">PDF · assessment document</option><option value="csv">CSV · tabular export</option></select></Field><Field label="Report dataset"><select disabled={readOnly} value={dataset} onChange={(e) => setDataset(e.target.value)}><option value="assessment">Complete assessment</option><option value="endpoints">Endpoint inventory</option><option value="findings">Findings</option><option value="technologies">Technology inventory</option><option value="evidence">Evidence index</option></select></Field><button className="button primary" disabled={readOnly || mutation.isPending}>{mutation.isPending ? 'Generating…' : 'Generate report'}</button></form><p className="field-hint">Reports preserve the distinction between automated findings and analyst conclusions. CSV is suited to individual inventory datasets. Generate new artifacts before archiving; existing downloads remain available.</p><ErrorNotice error={mutation.error} />{mutation.isSuccess && <Success>Report generated. Download the saved artifact below.</Success>}</Section>
    <ErrorNotice error={downloadError} /><Section title="Generated artifacts"><QueryState query={query}>{(records) => <DataTable rows={records} label="Reports" search={(r) => `${r.filename} ${r.format} ${r.dataset}`} emptyTitle="No reports generated" emptyDescription="Choose a format and dataset above. Reports are generated by the backend from persisted assessment records." columns={[
      { key: 'filename', label: 'Artifact / SHA-256', render: (r) => <><strong>{r.filename}</strong><div className="cell-secondary mono break-all">{r.sha256}</div></> },
      { key: 'format', label: 'Format', render: (r) => <Badge value={r.format.toUpperCase()} /> },
      { key: 'dataset', label: 'Dataset', render: (r) => human(r.dataset) },
      { key: 'created', label: 'Generated', sort: (r) => r.created_at, render: (r) => date(r.created_at) },
      { key: 'download', label: 'Download', render: (r) => <button className="button small" disabled={Boolean(downloadId)} onClick={() => void download(r)} aria-label={`Download ${r.filename}`}><Download size={14} />{downloadId === r.id ? 'Downloading…' : 'Download'}</button> },
    ]} />}</QueryState></Section>
  </>
}

function SettingsEditor({ config }: { config: Configuration }) {
  const [value, setValue] = useState(config)
  const [error, setError] = useState('')
  const mutation = useWrite<Configuration, Configuration>('/settings', 'PATCH')
  return <form className="editor-form" onSubmit={(event) => {
    event.preventDefault(); setError('')
    if (value.safe_paths.some((path) => !path.startsWith('/') || path.startsWith('//') || path.includes('?') || path.includes('#'))) { setError('Safe paths must begin with / and contain no host, query, or fragment.'); return }
    mutation.mutate(value)
  }}><ConfigurationForm value={value} onChange={(next) => { setValue(next); mutation.reset() }} /><ErrorNotice error={error || mutation.error} />{mutation.isSuccess && <Success>Workstation defaults saved. Existing assessment policies are unchanged.</Success>}<div className="form-actions"><span className="muted">Defaults apply to new assessments only.</span><button className="button primary" disabled={mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save defaults'}</button></div></form>
}
export function SettingsPage() {
  const query = useApi<Configuration>('/settings')
  const rules = useApi<DetectionRule[]>('/rules')
  return <><PageHeader title="Workstation settings" description="Persist default collection policy and inspect the installed deterministic rules." /><QueryState query={query}>{(data) => <SettingsEditor config={data} />}</QueryState><Section title="Detection rule registry"><QueryState query={rules}>{(data) => <DataTable rows={data} label="Detection rules" search={(r) => `${r.id} ${r.name} ${r.description}`} emptyTitle="No rules installed" columns={[
    { key: 'rule', label: 'Rule / version', render: (r) => <><span className="mono">{r.id} · v{r.version}</span><div className="cell-secondary">{r.name}</div></> },
    { key: 'severity', label: 'Severity', render: (r) => <Badge value={r.severity} severity /> },
    { key: 'confidence', label: 'Confidence', render: (r) => human(r.confidence) },
    { key: 'safety', label: 'Safety', render: (r) => <><Badge value={r.safety_level} /><div className="cell-secondary">{r.request_type}</div></> },
    { key: 'details', label: 'Definition', render: (r) => <details><summary>Inspect rule</summary><JsonView value={r} /></details> },
  ]} />}</QueryState></Section></>
}
