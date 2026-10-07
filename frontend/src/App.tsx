import { Component, lazy, Suspense, useEffect, useState } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { Link, NavLink, Route, Routes, useLocation, useMatch, useNavigate } from 'react-router-dom'
import { Activity, Boxes, Cable, ChevronRight, CircleDot, ClipboardList, FileDown, FileSearch, Fingerprint, FolderOpen, LayoutDashboard, ListTree, Menu, Network, Plus, Settings, Shield, Waypoints, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api, useApi } from './lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { SessionGate, useWorkspace } from './lib/session'
import type { Assessment } from './types'
import { Badge, ConfirmDialog, Empty, Loading, date } from './components/ui'
import { AssessmentEditor, Assessments, Dashboard, Overview } from './pages/assessments'
import { Endpoints, EvidenceDetailPage, EvidenceExplorer, SecurityControls, Technologies, Timeline, TransactionDetailPage, Transactions } from './pages/inventory'
import { FindingDetailPage, Findings } from './pages/findings'
import { CaseDetailPage, Cases, Reports, SettingsPage } from './pages/workflow'
import { UploadData } from './pages/uploads'

const AttackSurface = lazy(() => import('./pages/AttackSurface'))
const assessmentLinks: [string, string, LucideIcon][] = [
  ['', 'Overview', LayoutDashboard], ['graph', 'Attack surface', Network], ['endpoints', 'Endpoints', ListTree],
  ['technologies', 'Technologies', Boxes], ['transactions', 'HTTP transactions', Cable], ['controls', 'Security controls', Shield],
  ['findings', 'Findings', CircleDot], ['evidence', 'Evidence explorer', Fingerprint], ['timeline', 'Timeline', Activity],
  ['cases', 'Cases', FolderOpen], ['reports', 'Reports', FileDown],
]

class ErrorBoundary extends Component<{ children: ReactNode }, { error: boolean }> {
  state = { error: false }
  static getDerivedStateFromError() { return { error: true } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('WebScope view failed', error, info.componentStack) }
  render() {
    return this.state.error ? <main className="fatal-error"><h1>This view could not be displayed</h1><p>Your saved records have not been changed. Reload to reconnect to the local API.</p><button className="button primary" onClick={() => window.location.reload()}>Reload workstation</button></main> : this.props.children
  }
}

function Shell({ children }: { children: ReactNode }) {
  const session = useWorkspace()
  const cache = useQueryClient()
  const navigate = useNavigate()
  const [ending, setEnding] = useState(false)
  const end = useMutation({
    mutationFn: () => api<void>('/session', 'DELETE', {}),
    onSuccess: () => { cache.clear(); navigate('/'); setEnding(false) },
  })
  const location = useLocation()
  const assessmentMatch = useMatch('/assessments/:assessmentId/*')
  const findingMatch = useMatch('/findings/:id')
  const evidenceMatch = useMatch('/evidence/:id')
  const transactionMatch = useMatch('/transactions/:id')
  const caseMatch = useMatch('/cases/:id')
  const directId = assessmentMatch?.params.assessmentId === 'new' ? undefined : assessmentMatch?.params.assessmentId
  const detailPath = findingMatch ? `/findings/${findingMatch.params.id}` : evidenceMatch ? `/evidence/${evidenceMatch.params.id}` : transactionMatch ? `/transactions/${transactionMatch.params.id}` : caseMatch ? `/cases/${caseMatch.params.id}` : ''
  const detail = useApi<{ assessment_id: string }>(detailPath, Boolean(detailPath))
  const assessmentId = directId || detail.data?.assessment_id
  const assessment = useApi<Assessment>(`/assessments/${assessmentId}`, Boolean(assessmentId))
  const health = useApi<{ status: string }>('/health')
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
    document.getElementById('sidebar')?.querySelector('a')?.focus()
    const dismiss = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', dismiss)
    return () => { document.removeEventListener('keydown', dismiss); previous?.focus() }
  }, [open])
  useEffect(() => {
    document.title = `WebScope${assessment.data ? ` · ${assessment.data.name}` : ' · Assessment workstation'}`
  }, [assessment.data])
  useEffect(() => {
    setOpen(false)
    if (!location.hash) window.scrollTo(0, 0)
  }, [location.pathname, location.hash])
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <header className="mobile-header"><Link to="/" className="brand"><Waypoints size={22} />WebScope</Link><button className="icon-button" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-expanded={open} aria-controls="sidebar" onClick={() => setOpen(!open)}>{open ? <X size={21} /> : <Menu size={21} />}</button></header>
    {open && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setOpen(false)} />}
    <aside id="sidebar" className={`sidebar ${open ? 'is-open' : ''}`}>
      <Link className="brand" to="/"><Waypoints size={25} strokeWidth={1.6} aria-hidden="true" /><span>WebScope</span></Link>
      <div className="workspace-label">Assessment workstation</div>
      <nav aria-label="Workspace" className="nav-group">
        <NavLink to="/" end><LayoutDashboard size={17} />Dashboard</NavLink>
        <NavLink to="/assessments" end><ClipboardList size={17} />Assessments</NavLink>
        <NavLink to="/cases" end><FolderOpen size={17} />All cases</NavLink>
        <NavLink to="/uploads" end><FileSearch size={17} />Upload data</NavLink>
      </nav>
      {assessmentId && <><div className="nav-context"><span>Current assessment</span><strong title={assessment.data?.name}>{assessment.data?.name || 'Loading…'}</strong></div><nav className="nav-group assessment-nav" aria-label="Assessment">{assessmentLinks.map(([path, title, Icon]) => <NavLink key={path} to={`/assessments/${assessmentId}${path ? `/${path}` : ''}`} end><Icon size={16} aria-hidden="true" />{title}{assessment.data && (path === 'findings' || path === 'evidence') && <span className="nav-count">{assessment.data.counts[path]}</span>}</NavLink>)}</nav></>}
      {!assessmentId && <div className="sidebar-guide"><Shield size={19} aria-hidden="true" /><p>Define scope.<br />Collect evidence.<br />Make the call.</p><Link to="/assessments/new"><Plus size={14} />New assessment</Link></div>}
      <div className="sidebar-footer"><NavLink to="/settings"><Settings size={17} />Settings</NavLink><div className="connection" role="status"><span className={`connection-dot ${health.isSuccess ? 'connected' : ''}`} />{health.isSuccess ? 'API connected' : health.isError ? 'API unavailable' : 'Connecting to API…'}</div></div>
    </aside>
    <div className="main-shell" inert={open}><div className="context-bar"><div><span className="muted">Workspace</span><ChevronRight size={13} />{assessment.data ? <><Link to={`/assessments/${assessmentId}`}>{assessment.data.name}</Link><span className="context-target mono">{assessment.data.target}</span></> : <span>Temporary investigations</span>}</div>{assessment.data ? <Badge value={assessment.data.config.mode} /> : <span className="local-label">Evidence-driven · no sign-in</span>}</div>
      {session?.temporary && <section className="session-banner" aria-label="Temporary workspace notice">
        <div><strong>Temporary session — export to keep your work</strong><p>Expires {date(session.expires_at)}. End session deletes uploads and results immediately.</p>
          {!session.network_enabled && <p>Hosted import-only mode: upload captured data; website scanning is disabled.</p>}
          <details><summary>Retention and privacy</summary><p>{session.retention_notice}</p><p>Tabs in this browser profile share the session. Clearing its cookie loses access; no sign-in or recovery is available.</p></details></div>
        <div className="actions"><Link className="button small" to="/uploads">Upload data</Link><button className="button small" onClick={() => setEnding(true)}>End session</button></div>
      </section>}
      <main id="main-content" tabIndex={-1}>{children}</main><footer className="workstation-footer"><span>WebScope</span><span>Temporary uploads. Automated observations are not analyst conclusions.</span></footer></div>
    {ending && <ConfirmDialog title="Delete this temporary workspace?" confirmLabel="Delete session data" onCancel={() => setEnding(false)} onConfirm={() => end.mutate()} pending={end.isPending} error={end.error} danger>
      <p>All uploads, assessments, notes, cases and generated reports in this session will be deleted. This affects every tab sharing this browser session.</p><p>Download reports first. There is no account or recovery link.</p>
    </ConfirmDialog>}
  </div>
}

export default function App() {
  return <ErrorBoundary><SessionGate><Shell><Suspense fallback={<Loading label="Loading view…" />}><Routes>
    <Route path="/" element={<Dashboard />} />
    <Route path="/assessments" element={<Assessments />} />
    <Route path="/assessments/new" element={<AssessmentEditor />} />
    <Route path="/assessments/:assessmentId" element={<Overview />} />
    <Route path="/assessments/:assessmentId/edit" element={<AssessmentEditor />} />
    <Route path="/assessments/:assessmentId/graph" element={<AttackSurface />} />
    <Route path="/assessments/:assessmentId/endpoints" element={<Endpoints />} />
    <Route path="/assessments/:assessmentId/technologies" element={<Technologies />} />
    <Route path="/assessments/:assessmentId/transactions" element={<Transactions />} />
    <Route path="/assessments/:assessmentId/controls" element={<SecurityControls />} />
    <Route path="/assessments/:assessmentId/findings" element={<Findings />} />
    <Route path="/assessments/:assessmentId/evidence" element={<EvidenceExplorer />} />
    <Route path="/assessments/:assessmentId/timeline" element={<Timeline />} />
    <Route path="/assessments/:assessmentId/cases" element={<Cases />} />
    <Route path="/assessments/:assessmentId/reports" element={<Reports />} />
    <Route path="/findings/:id" element={<FindingDetailPage />} />
    <Route path="/evidence/:id" element={<EvidenceDetailPage />} />
    <Route path="/transactions/:id" element={<TransactionDetailPage />} />
    <Route path="/cases" element={<Cases />} />
    <Route path="/cases/:id" element={<CaseDetailPage />} />
    <Route path="/settings" element={<SettingsPage />} />
    <Route path="/uploads" element={<UploadData />} />
    <Route path="*" element={<Empty title="View not found" action={<Link className="button primary" to="/assessments">Open assessments</Link>}><FileSearch size={16} /> Check the address or open an assessment.</Empty>} />
  </Routes></Suspense></Shell></SessionGate></ErrorBoundary>
}
