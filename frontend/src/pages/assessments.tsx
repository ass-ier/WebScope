import { lazy, Suspense, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, CheckCircle2, FileSearch, Play, Plus, Settings2, ShieldCheck } from 'lucide-react'
import { assessmentPath, useApi, useWrite } from '../lib/api'
import type { Assessment, AssessmentCreate, Configuration, Endpoint, Evidence, Host, Note, Technology, TimelineEvent } from '../types'
import { assessmentIsReadOnly, severities } from '../types'
import { AssessmentPolicyNotice, Badge, CheckField, ConfirmDialog, DataTable, Empty, ErrorNotice, Field, Loading, Meta, Notes, PageHeader, QueryState, Section, Success, date, human } from '../components/ui'
import { ConfigurationForm, ListInput } from '../components/ConfigurationForm'
import { EndpointsTable, EvidenceTable, TechnologyTable, TimelineList } from '../components/records'

const GraphPreview = lazy(() => import('./AttackSurface').then((module) => ({ default: module.GraphPreview })))

function AssessmentTable({ assessments }: { assessments: Assessment[] }) {
  return <DataTable rows={assessments} label="Assessments" search={(a) => `${a.name} ${a.target} ${a.status}`} emptyTitle="Your investigation starts with scope" emptyDescription="Create an assessment to record authorization, set boundaries, and begin collecting evidence." columns={[
    { key: 'name', label: 'Assessment / target', sort: (a) => a.name, render: (a) => <><Link className="table-title" to={assessmentPath(a.id)}>{a.name}<ArrowRight size={14} /></Link><div className="cell-secondary mono">{a.target}</div></> },
    { key: 'status', label: 'Status', sort: (a) => a.status, render: (a) => <Badge value={a.status} /> },
    { key: 'mode', label: 'Collection', render: (a) => <Badge value={a.config.mode} /> },
    { key: 'findings', label: 'Findings', sort: (a) => a.counts.findings, render: (a) => <Link to={`${assessmentPath(a.id)}/findings`}>{a.counts.findings}</Link> },
    { key: 'evidence', label: 'Evidence', sort: (a) => a.counts.evidence, render: (a) => <Link to={`${assessmentPath(a.id)}/evidence`}>{a.counts.evidence}</Link> },
    { key: 'updated', label: 'Updated', sort: (a) => a.updated_at, render: (a) => date(a.updated_at) },
  ]} />
}

export function Dashboard() {
  const query = useApi<Assessment[]>('/assessments')
  return <><PageHeader title="Investigation workspace" description="From an authorized target to a defensible conclusion." actions={<Link className="button primary" to="/assessments/new"><Plus size={16} />New assessment</Link>} />
    <QueryState query={query}>{(assessments) => {
      const totals = assessments.reduce((sum, a) => ({ evidence: sum.evidence + a.counts.evidence, findings: sum.findings + a.counts.findings, cases: sum.cases + a.counts.cases }), { evidence: 0, findings: 0, cases: 0 })
      return <><div className="workspace-summary" aria-label="Workspace totals"><div><strong>{assessments.length}</strong><span>Assessments</span></div><div><strong>{totals.evidence}</strong><span>Evidence records</span></div><div><strong>{totals.findings}</strong><span>Automated findings</span></div><div><strong>{totals.cases}</strong><span>Investigation cases</span></div></div>
        {assessments.length === 0 && <div className="onboarding"><ShieldCheck size={34} strokeWidth={1.4} aria-hidden="true" /><div><h2>Start with authorization. Stay with the evidence.</h2><p>Create a scoped assessment. Collection never starts automatically; you decide when to discover, analyze, and run safe checks.</p><Link className="text-link" to="/assessments/new">Define your first assessment <ArrowRight size={16} /></Link></div></div>}
        <Section title="Assessments" action={<Link to="/assessments">View all <ArrowRight size={13} /></Link>}><AssessmentTable assessments={[...assessments].sort((a, b) => b.updated_at.localeCompare(a.updated_at))} /></Section>
        <div className="principle-strip"><div><h3>Observed, not assumed</h3><p>Every automated finding links to source evidence and a versioned detection rule.</p></div><div><h3>Your conclusion stays yours</h3><p>Review status, notes, and risk overrides are distinct from immutable automated facts.</p></div></div>
      </>
    }}</QueryState></>
}

export function Assessments() {
  const query = useApi<Assessment[]>('/assessments')
  const [status, setStatus] = useState('')
  return <><PageHeader title="Assessments" description="Scope, authorization, and evidence for each investigation." actions={<Link className="button primary" to="/assessments/new"><Plus size={16} />New assessment</Link>} /><div className="filter-line"><Field label="Assessment status"><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option>{['DRAFT', 'READY', 'RUNNING', 'COMPLETED', 'FAILED', 'ARCHIVED'].map((s) => <option key={s}>{s}</option>)}</select></Field></div><QueryState query={query}>{(data) => <AssessmentTable assessments={data.filter((a) => !status || a.status === status)} />}</QueryState></>
}

export function AssessmentEditor() {
  const { assessmentId } = useParams()
  const defaults = useApi<Configuration>('/settings', !assessmentId)
  const assessment = useApi<Assessment>(assessmentPath(assessmentId || ''), Boolean(assessmentId))
  return <><PageHeader title={assessmentId ? 'Edit assessment policy' : 'Create assessment'} description="Define the authorized boundary before any target network activity." />{assessmentId ? <QueryState query={assessment}>{(data) => assessmentIsReadOnly(data) ? <AssessmentPolicyNotice query={assessment} /> : <AssessmentForm key={data.id} assessment={data} config={data.config} />}</QueryState> : <QueryState query={defaults}>{(config) => <AssessmentForm config={config} />}</QueryState>}</>
}

function AssessmentForm({ assessment, config: initial }: { assessment?: Assessment; config: Configuration }) {
  const navigate = useNavigate()
  const [name, setName] = useState(assessment?.name || '')
  const [description, setDescription] = useState(assessment?.description || '')
  const [target, setTarget] = useState(assessment?.target || '')
  const [scope, setScope] = useState(assessment?.scope || { allowed_hosts: [], excluded_hosts: [], excluded_paths: [] })
  const [config, setConfig] = useState(initial)
  const [authorized, setAuthorized] = useState(assessment?.authorized || false)
  const [note, setNote] = useState(assessment?.authorization_note || '')
  const [reauthorized, setReauthorized] = useState(false)
  const [error, setError] = useState('')
  const scopeChanged = Boolean(assessment && JSON.stringify(scope) !== JSON.stringify(assessment.scope))
  const boundaryChanged = scopeChanged || Boolean(assessment && config.allow_private_network !== assessment.config.allow_private_network)
  const write = useWrite<Assessment>(assessment ? assessmentPath(assessment.id) : '/assessments', assessment ? 'PATCH' : 'POST')
  return <form className="editor-form" onSubmit={(event) => {
    event.preventDefault()
    setError('')
    if (!scope.allowed_hosts.length) { setError('Add at least one explicitly allowed hostname.'); return }
    if (authorized && !note.trim()) { setError('Record an authorization note before continuing.'); return }
    if (boundaryChanged && (!reauthorized || !authorized || !note.trim())) { setError('Explicitly reauthorize the changed scope or private-network policy and record an authorization note.'); return }
    if (config.safe_paths.some((path) => !path.startsWith('/') || path.startsWith('//') || path.includes('?') || path.includes('#'))) { setError('Safe paths must begin with / and contain no host, query, or fragment.'); return }
    const payload: AssessmentCreate = { name: name.trim(), description, target, scope, config, authorized, authorization_note: note.trim() }
    const update = assessment ? {
      ...(name.trim() !== assessment.name ? { name: name.trim() } : {}),
      ...(description !== assessment.description ? { description } : {}),
      ...(JSON.stringify(config) !== JSON.stringify(assessment.config) ? { config } : {}),
      ...(scopeChanged ? { scope } : {}),
      ...(boundaryChanged || authorized !== assessment.authorized ? { authorized } : {}),
      ...(boundaryChanged || note.trim() !== assessment.authorization_note ? { authorization_note: note.trim() } : {}),
    } : payload
    write.mutate(update, { onSuccess: (result) => navigate(assessmentPath(result.id)) })
  }}>
    <Section title="Assessment identity"><div className="form-grid"><Field label="Assessment name"><input required maxLength={160} value={name} onChange={(e) => setName(e.target.value)} placeholder="Customer portal review" /></Field><Field label="Target URL" hint={assessment ? 'Target is immutable. Create a new assessment to change it.' : 'Use a complete HTTP or HTTPS URL.'}><input required type="url" maxLength={4096} readOnly={Boolean(assessment)} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://app.example.com" /></Field><Field label="Description" className="span-all"><textarea rows={3} maxLength={10000} value={description} onChange={(e) => setDescription(e.target.value)} /></Field></div></Section>
    <Section title="Scope boundaries"><p className="muted section-intro">Every outbound request and redirect must pass scope validation. Hosts outside the allowlist are never followed.</p><div className="form-grid three"><ListInput label="Allowed hosts" required value={scope.allowed_hosts} onChange={(allowed_hosts) => { setScope({ ...scope, allowed_hosts }); setReauthorized(false) }} hint="One exact hostname per line, without a scheme or path." placeholder="app.example.com" /><ListInput label="Excluded hosts" value={scope.excluded_hosts} onChange={(excluded_hosts) => { setScope({ ...scope, excluded_hosts }); setReauthorized(false) }} hint="Explicit denials take precedence." /><ListInput label="Excluded paths" value={scope.excluded_paths} onChange={(excluded_paths) => { setScope({ ...scope, excluded_paths }); setReauthorized(false) }} hint="One absolute path per line." placeholder="/admin" /></div></Section>
    <ConfigurationForm value={config} onChange={(next) => { if (next.allow_private_network !== config.allow_private_network) setReauthorized(false); setConfig(next) }} />
    <Section title="Authorization"><div className="authorization-panel"><CheckField label="I am authorized to assess this target and scope" checked={authorized} onChange={setAuthorized} hint="Only assess systems you own or have explicit permission to test." /><Field label="Authorization note" hint="Document the owner, permission or engagement reference, and any additional restrictions."><textarea rows={3} required={authorized || boundaryChanged} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} /></Field>{boundaryChanged && <><p className="field-hint">Changing scope or private-network permission invalidates prior target validation. The assessment returns to DRAFT; validate it again before collection.</p><CheckField label="I explicitly reauthorize the updated scope and network policy" checked={reauthorized} onChange={setReauthorized} /></>}</div></Section>
    <ErrorNotice error={error || write.error} /><div className="form-actions"><Link className="button" to={assessment ? assessmentPath(assessment.id) : '/assessments'}>Cancel</Link><span className="muted">Saving does not initiate collection. New assessments start in DRAFT.</span><button className="button primary" disabled={write.isPending || (!assessment && !authorized) || (boundaryChanged && (!reauthorized || !authorized || !note.trim()))}>{write.isPending ? 'Saving…' : assessment ? 'Save assessment policy' : 'Create assessment'}</button></div>
  </form>
}

function AssessmentActions({ assessment }: { assessment: Assessment }) {
  const [action, setAction] = useState<'discover' | 'checks' | null>(null)
  const [cors, setCors] = useState(false)
  const validate = useWrite<Assessment>(assessmentPath(assessment.id, 'validate'))
  const discover = useWrite<Assessment>(assessmentPath(assessment.id, 'discover'))
  const analyze = useWrite<Assessment>(assessmentPath(assessment.id, 'analyze'))
  const checks = useWrite<Assessment>(assessmentPath(assessment.id, 'checks'))
  const locked = assessment.status === 'ARCHIVED' || assessment.status === 'RUNNING'
  const pending = validate.isPending || discover.isPending || analyze.isPending || checks.isPending
  const validated = ['READY', 'COMPLETED', 'FAILED'].includes(assessment.status)
  const networkAllowed = assessment.authorized && assessment.config.mode === 'SAFE_HTTP' && validated && !locked
  const active = action === 'checks' ? checks : discover
  return <><div className="action-bar"><div className="actions"><button className="button" disabled={pending || locked || !assessment.authorized} onClick={() => validate.mutate({})}><CheckCircle2 size={15} />{validate.isPending ? 'Validating…' : 'Validate target'}</button><button className="button primary" disabled={pending || !networkAllowed} onClick={() => { discover.reset(); setAction('discover') }}><Play size={15} />Discover</button><button className="button" disabled={pending || locked} onClick={() => analyze.mutate({})}><FileSearch size={15} />{analyze.isPending ? 'Analyzing…' : 'Analyze evidence'}</button><button className="button" disabled={pending || !networkAllowed || assessment.config.safe_paths.length === 0} onClick={() => { checks.reset(); setAction('checks') }}><ShieldCheck size={15} />Safe checks</button></div>{!locked && <Link to={`${assessmentPath(assessment.id)}/edit`} className="text-link"><Settings2 size={14} />Edit policy</Link>}</div>
    <div className="collection-notice">{locked ? 'Assessment is read-only. Restore an archived assessment to draft before making changes.' : assessment.config.mode === 'PASSIVE' ? 'PASSIVE · No target network requests. Analyze existing evidence without authorization or network activity. Enable Safe HTTP in policy for collection.' : !assessment.authorized ? 'Authorization required. Record permission in assessment policy before collection.' : !validated ? 'DRAFT · Validate the authorized target to make it READY before discovery or safe checks. Validation itself sends no network requests.' : `${assessment.config.max_requests} requests maximum · ${assessment.config.rate_per_second}/second · ${assessment.config.timeout_seconds}s timeout · explicitly initiated only`}{!locked && assessment.config.safe_paths.length === 0 && <div>Safe checks require at least one explicitly configured safe path.</div>}</div>
    <ErrorNotice error={validate.error || analyze.error || (!action ? discover.error || checks.error : null)} />
    {validate.isSuccess && <Success>Target and scope validated.</Success>}{analyze.isSuccess && <Success>Deterministic analysis completed. Review the findings and supporting evidence.</Success>}
    {discover.isSuccess && <Success>Discovery completed. Inventory, evidence, and timeline are refreshed.</Success>}{checks.isSuccess && <Success>Safe checks completed. Review the recorded observations.</Success>}
    {action && <ConfirmDialog title={action === 'discover' ? 'Start scoped discovery?' : 'Run safe security checks?'} confirmLabel={action === 'discover' ? 'Start discovery' : 'Confirm safe checks'} onCancel={() => setAction(null)} pending={active.isPending} error={active.error} onConfirm={() => active.mutate(action === 'checks' ? { confirm: true, cors_origin: cors ? 'https://webscope.invalid' : null } : {}, { onSuccess: () => setAction(null) })}>
      <p>This action sends bounded, read-only requests to the authorized target.</p><Meta items={[['Target', <span className="mono">{assessment.target}</span>], ['Allowed hosts', assessment.scope.allowed_hosts.join(', ')], ['Request budget', assessment.config.max_requests], ['Rate', `${assessment.config.rate_per_second} requests / second`], ['Timeout', `${assessment.config.timeout_seconds} seconds`]]} />
      {action === 'checks' && <><h3>Explicit safe paths</h3><ul className="mono">{assessment.config.safe_paths.map((p) => <li key={p}>{p}</li>)}</ul><CheckField label="Check CORS with a synthetic Origin header" hint="Sends Origin: https://webscope.invalid to the target. It does not contact that domain." checked={cors} onChange={setCors} /></>}
      <p className="muted">Out-of-scope redirects are blocked and recorded. No credential guessing, data modification, or unrestricted crawling.</p>
    </ConfirmDialog>}
  </>
}

export function Overview() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Assessment>(assessmentPath(assessmentId))
  const evidence = useApi<Evidence[]>(assessmentPath(assessmentId, 'evidence'))
  const timeline = useApi<TimelineEvent[]>(assessmentPath(assessmentId, 'timeline'))
  const technologies = useApi<Technology[]>(assessmentPath(assessmentId, 'technologies'))
  const endpoints = useApi<Endpoint[]>(assessmentPath(assessmentId, 'endpoints'))
  const hosts = useApi<Host[]>(assessmentPath(assessmentId, 'hosts'))
  const notes = useApi<Note[]>(assessmentPath(assessmentId, 'notes'))
  const [removeOpen, setRemoveOpen] = useState(false)
  const remove = useWrite<void>(assessmentPath(assessmentId), 'DELETE')
  const archive = useWrite<Assessment>(assessmentPath(assessmentId), 'PATCH')
  const navigate = useNavigate()
  return <QueryState query={query}>{(assessment) => <><PageHeader title={assessment.name} description={<span className="mono">{assessment.target}</span>} actions={<Badge value={assessment.status} />} /><AssessmentActions assessment={assessment} />
    {assessment.description && <p className="description-copy">{assessment.description}</p>}
    <div className="inventory-strip">{(['hosts', 'endpoints', 'apis', 'technologies', 'transactions', 'evidence'] as const).map((kind) => <Link key={kind} to={`${assessmentPath(assessment.id)}/${kind === 'hosts' ? 'graph' : kind === 'apis' ? 'endpoints' : kind}`}><strong>{assessment.counts[kind]}</strong><span>{kind === 'apis' ? 'APIs' : human(kind)}</span><ArrowRight size={13} /></Link>)}</div>
    <div className="overview-grid"><Section title="Finding severity" action={<Link to={`${assessmentPath(assessment.id)}/findings?view=prioritized`}>Review findings <ArrowRight size={13} /></Link>}><p className="muted section-intro">Effective severity · analyst overrides applied · false positives and dismissed findings excluded</p>
      <div className="severity-chart">{[...severities].reverse().map((severity) => <Link to={`${assessmentPath(assessment.id)}/findings?severity=${severity}&view=prioritized`} className="severity-row" key={severity} aria-label={`${human(severity)}: ${assessment.severity_counts[severity]} prioritized ${assessment.severity_counts[severity] === 1 ? 'finding' : 'findings'}`}><Badge value={severity} severity /><span className="severity-track"><span className={`severity-fill severity-${severity.toLowerCase()}`} style={{ width: `${assessment.severity_counts[severity] / Math.max(...Object.values(assessment.severity_counts), 1) * 100}%` }} /></span><strong>{assessment.severity_counts[severity]}</strong></Link>)}</div>
    </Section>
    <Section title="Assessment boundary"><Meta items={[['Allowed hosts', assessment.scope.allowed_hosts.join(', ')], ['Excluded hosts', assessment.scope.excluded_hosts.join(', ') || 'None'], ['Excluded paths', assessment.scope.excluded_paths.join(', ') || 'None'], ['Authorization', assessment.authorized ? 'Recorded' : 'Not recorded'], ['Authorization note', assessment.authorization_note || 'Not recorded'], ['Created', date(assessment.created_at)]]} /></Section></div>
    <Section title="Observed hosts" action={<Link to={`${assessmentPath(assessment.id)}/graph`}>Open attack surface <ArrowRight size={13} /></Link>}><QueryState query={hosts}>{(data) => data.length ? <div className="host-list">{data.map((host) => <div key={host.id}><strong className="mono">{host.hostname}</strong><span className="mono muted">{host.addresses.join(', ') || 'No addresses recorded'}</span><Link to={`/evidence/${host.evidence_id}`}>Source evidence</Link></div>)}</div> : <Empty title="No hosts observed">Run scoped discovery to populate the attack-surface graph.</Empty>}</QueryState></Section>
    <Section title="Attack surface map" action={<Link to={`${assessmentPath(assessment.id)}/graph`}>Explore full graph <ArrowRight size={13} /></Link>}><Suspense fallback={<Loading label="Loading attack surface…" />}><GraphPreview assessmentId={assessment.id} /></Suspense></Section>
    <Section title="Endpoint inventory" action={<Link to={`${assessmentPath(assessment.id)}/endpoints`}>All endpoints <ArrowRight size={13} /></Link>}><QueryState query={endpoints}>{(records) => <EndpointsTable records={records.slice(0, 5)} />}</QueryState></Section>
    <Section title="Recent evidence" action={<Link to={`${assessmentPath(assessment.id)}/evidence`}>All evidence <ArrowRight size={13} /></Link>}><QueryState query={evidence}>{(records) => <EvidenceTable records={[...records].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 5)} />}</QueryState></Section>
    <Section title="Technology observations"><QueryState query={technologies}>{(records) => <TechnologyTable records={records} />}</QueryState></Section>
    <Section title="Recent activity" action={<Link to={`${assessmentPath(assessment.id)}/timeline`}>Full timeline <ArrowRight size={13} /></Link>}><QueryState query={timeline}>{(records) => <TimelineList records={[...records].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 5)} />}</QueryState></Section>
    <QueryState query={notes}>{(records) => <Notes notes={records} path={assessmentPath(assessment.id, 'notes')} readOnly={assessmentIsReadOnly(assessment)} />}</QueryState>
    <Section title="Assessment lifecycle"><div className="actions"><button className="button" disabled={archive.isPending || assessment.status === 'RUNNING'} onClick={() => archive.mutate({ status: assessment.status === 'ARCHIVED' ? 'DRAFT' : 'ARCHIVED' })}>{assessment.status === 'ARCHIVED' ? 'Restore to draft' : 'Archive assessment'}</button><button className="button danger" disabled={assessment.status !== 'ARCHIVED' || archive.isPending} onClick={() => setRemoveOpen(true)}>Delete assessment</button></div><p className="field-hint">Archive the assessment before permanent deletion. Restoration returns it to DRAFT and requires target validation before collection.</p><ErrorNotice error={archive.error} /></Section>
    {removeOpen && <ConfirmDialog title="Delete this assessment?" danger confirmLabel="Delete assessment" onCancel={() => setRemoveOpen(false)} pending={remove.isPending} error={remove.error} onConfirm={() => remove.mutate(undefined, { onSuccess: () => navigate('/assessments') })}><p>This permanently deletes <strong>{assessment.name}</strong> and its evidence, findings, notes, cases, and reports. This cannot be undone.</p></ConfirmDialog>}
  </>}</QueryState>
}
