import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import App from '../src/App'
import type { AssessmentCreate, CaseInput, Configuration, EvidenceDetail, FindingUpdate, Note } from '../src/types'
import { fixtures } from './fixtures'

type Fixture = ReturnType<typeof fixtures>
interface Call { path: string; method: string; body: unknown; headers: Headers }
type Handler = (call: Call, data: Fixture) => Response | undefined | Promise<Response | undefined>
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }) }
function mockApi(handler?: Handler) {
  const data = fixtures()
  const calls: Call[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input).replace(/^\/api/, '')
    const call: Call = { path, method: init?.method || 'GET', body: init?.body ? JSON.parse(String(init.body)) as unknown : undefined, headers: new Headers(init?.headers) }
    calls.push(call)
    const custom = await handler?.(call, data)
    if (custom) return custom
    if (call.method !== 'GET') return json({ detail: `Unhandled test write: ${call.method} ${path}` }, 400)
    if (path === '/health') return json({ status: 'ok' })
    if (path === '/session') return json({
      mode: 'local', temporary: true, session_active: true, network_enabled: true,
      expires_at: new Date(Date.now() + 86_400_000).toISOString(),
      retention_notice: 'Temporary workspace. Expires 24 hours after creation. Closing a tab does not delete server data.',
      max_upload_bytes: 2_000_000, max_storage_bytes: 20_000_000, max_assessments: 10,
      formats: ['webscope', 'har', 'openapi'],
    })
    if (path === '/settings') return json(data.config)
    if (path === '/rules') return json([data.rule])
    if (path === '/assessments') return json([data.assessment])
    if (path === '/assessments/a-1') return json(data.assessment)
    if (path === '/findings/f-1') return json(data.finding)
    if (path === '/evidence/e-1') return json(data.evidence)
    if (path === '/transactions/t-1') return json(data.transaction)
    if (path === '/cases/c-1') return json(data.caseDetail)
    if (path === '/cases') return json([data.caseDetail])
    if (path === '/assessments/a-1/findings') return json([data.finding])
    if (path === '/assessments/a-1/evidence') return json([data.evidence])
    if (path === '/assessments/a-1/transactions') return json([data.transaction])
    if (path === '/assessments/a-1/controls') return json({ headers: [], cookies: [], cors: [] })
    if (path === '/assessments/a-1/graph') return json({ nodes: [], edges: [] })
    if (path.startsWith('/assessments/a-1/')) return json([])
    return json({ detail: `No test record at ${path}` }, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { data, calls, fetchMock }
}
function renderApp(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></QueryClientProvider>)
}

describe('assessment workflows with mocked API integration', () => {
  it('creates an explicitly authorized passive assessment with complete scope and policy, without collection', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call, data) => {
      if (call.path === '/assessments' && call.method === 'POST') {
        Object.assign(data.assessment, call.body as AssessmentCreate, { status: 'DRAFT' })
        return json(data.assessment, 201)
      }
    })
    renderApp('/assessments/new')
    await user.type(await screen.findByLabelText('Assessment name'), 'Authorized portal review')
    await user.type(screen.getByLabelText(/Target URL/), 'https://portal.fixture.test')
    await user.type(screen.getByLabelText(/Allowed hosts/), 'portal.fixture.test\napi.fixture.test')
    await user.type(screen.getByLabelText(/Authorization note/), 'Written permission ENG-42; read-only scope.')
    expect(screen.getByLabelText(/Check HTTP\/HTTPS availability/)).not.toBeChecked()
    expect(screen.getByLabelText(/Observe advertised methods/)).not.toBeChecked()
    expect(screen.getByRole('button', { name: 'Create assessment' })).toBeDisabled()
    await user.click(screen.getByLabelText(/I am authorized to assess this target and scope/))
    await user.click(screen.getByRole('button', { name: 'Create assessment' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Authorized portal review' })).toBeVisible()
    const call = calls.find((c) => c.method === 'POST' && c.path === '/assessments')!
    expect(call.headers.get('X-WebScope-Request')).toBe('workstation')
    expect(call.headers.get('Content-Type')).toBe('application/json')
    expect(call.body).toMatchObject({ name: 'Authorized portal review', authorized: true, authorization_note: 'Written permission ENG-42; read-only scope.', config: { mode: 'PASSIVE', max_requests: 30, availability: false, methods: false }, scope: { allowed_hosts: ['portal.fixture.test', 'api.fixture.test'], excluded_paths: [] } })
    expect(calls.some((c) => /\/(discover|checks|analyze)$/.test(c.path))).toBe(false)
    expect(screen.getByRole('button', { name: 'Discover' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Safe checks' })).toBeDisabled()
    expect(document.querySelector('.page-header .badge')).toHaveTextContent('Draft')
  })

  it('requires confirmation for bounded safe checks and sends only the selected CORS origin', async () => {
    const user = userEvent.setup()
    const { data, calls } = mockApi((call, state) => call.path.endsWith('/checks') && call.method === 'POST' ? json(state.assessment) : undefined)
    data.assessment.config.mode = 'SAFE_HTTP'
    data.assessment.config.safe_paths = ['/health']
    renderApp('/assessments/a-1')
    await user.click(await screen.findByRole('button', { name: 'Safe checks' }))
    const dialog = screen.getByRole('dialog', { name: 'Run safe security checks?' })
    expect(within(dialog).getByText('/health')).toBeVisible()
    expect(calls.some((c) => c.path.endsWith('/checks'))).toBe(false)
    await user.click(within(dialog).getByLabelText(/Check CORS with a synthetic Origin header/))
    await user.click(within(dialog).getByRole('button', { name: 'Confirm safe checks' }))
    expect(await screen.findByText(/Safe checks completed/)).toBeVisible()
    expect(calls.find((c) => c.path.endsWith('/checks'))?.body).toEqual({ confirm: true, cors_origin: 'https://webscope.invalid' })
  })

  it('shows API failures with a retry, not a fabricated empty result', async () => {
    const user = userEvent.setup()
    let fail = true
    const { calls } = mockApi((call) => call.path === '/assessments' && fail ? json({ detail: 'Database is temporarily unavailable.' }, 503) : undefined)
    renderApp('/assessments')
    expect(await screen.findByRole('alert')).toHaveTextContent('Database is temporarily unavailable.')
    expect(screen.queryByText('Your investigation starts with scope')).not.toBeInTheDocument()
    fail = false
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('link', { name: 'Fixture assessment' })).toBeVisible()
    expect(calls.filter((c) => c.path === '/assessments')).toHaveLength(2)
  })

  it('shows honest empty state and zero counts from an empty API list', async () => {
    mockApi((call) => call.path === '/assessments' ? json([]) : undefined)
    renderApp('/')
    expect(await screen.findByText('Your investigation starts with scope')).toBeVisible()
    expect(screen.getByRole('link', { name: /Define your first assessment/ })).toHaveAttribute('href', '/assessments/new')
    expect(screen.getAllByText('0')).toHaveLength(4)
  })
})

describe('finding and evidence review', () => {
  it('links backend severity totals to matching effective-severity findings and preserves all-observation access', async () => {
    const user = userEvent.setup()
    const { data } = mockApi((call, state) => call.path === '/assessments/a-1/findings' ? json([
      state.finding,
      { ...state.finding, id: 'f-false', title: 'Excluded false-positive observation', status: 'FALSE_POSITIVE', severity: 'HIGH' },
      { ...state.finding, id: 'f-dismissed', title: 'Excluded dismissed observation', status: 'DISMISSED', severity: 'HIGH' },
    ]) : undefined)
    data.finding.analyst_severity = 'HIGH'
    data.finding.status = 'CONFIRMED'
    data.assessment.counts.findings = 3
    data.assessment.severity_counts = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0 }
    renderApp('/assessments/a-1')
    expect(await screen.findByText('Effective severity · analyst overrides applied · false positives and dismissed findings excluded')).toBeVisible()
    const high = screen.getByRole('link', { name: 'High: 1 prioritized finding' })
    expect(high).toHaveAttribute('href', '/assessments/a-1/findings?severity=HIGH&view=prioritized')
    await user.click(high)
    expect(await screen.findByRole('heading', { level: 1, name: 'Findings' })).toBeVisible()
    expect(screen.getByLabelText('Finding view')).toHaveValue('prioritized')
    expect(screen.getByLabelText('Severity')).toHaveValue('HIGH')
    expect(await screen.findByRole('columnheader', { name: 'Effective severity' })).toBeVisible()
    expect(screen.getByText('Analyst override · automated Medium')).toBeVisible()
    expect(screen.getByRole('link', { name: 'Missing fixture policy' })).toBeVisible()
    expect(screen.queryByText('Excluded false-positive observation')).not.toBeInTheDocument()
    expect(screen.queryByText('Excluded dismissed observation')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(await screen.findByText('Excluded false-positive observation')).toBeVisible()
    expect(screen.getByText('Excluded dismissed observation')).toBeVisible()
    expect(screen.getByLabelText('Finding view')).toHaveValue('')
    expect(data.finding.severity).toBe('MEDIUM')
  })

  it('updates review status, conclusions and explained risk override while retaining immutable automated facts', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call, data) => {
      if (call.path === '/findings/f-1' && call.method === 'PATCH') {
        const update = call.body as FindingUpdate
        Object.assign(data.finding, update)
        data.finding.risk.priority = update.priority_override || data.finding.risk.automated_priority
        data.finding.risk.override_reason = update.override_reason
        return json(data.finding)
      }
    })
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { name: 'Why WebScope flagged this' })).toBeVisible()
    expect(screen.getByText('The policy header was absent from response evidence e-1.')).toBeVisible()
    await waitFor(() => expect(screen.getByLabelText('Review status')).toBeEnabled())
    await user.selectOptions(screen.getByLabelText('Review status'), 'CONFIRMED')
    await user.type(screen.getByLabelText(/Analyst conclusion/), 'Verified against the authorized fixture response.')
    await user.selectOptions(screen.getByLabelText(/Analyst severity/), 'HIGH')
    await user.selectOptions(screen.getByLabelText(/Analyst confidence/), 'MEDIUM')
    await user.selectOptions(screen.getByLabelText(/Priority override/), 'HIGH')
    expect(screen.getByRole('button', { name: 'Save analyst review' })).toBeDisabled()
    await user.type(screen.getByLabelText(/Override reason/), 'Escalated for a production release review.')
    await user.click(screen.getByRole('button', { name: 'Save analyst review' }))
    expect(await screen.findByText(/Analyst review saved/)).toBeVisible()
    const sent = calls.find((c) => c.method === 'PATCH')!
    expect(sent.body).toEqual({ status: 'CONFIRMED', analyst_assessment: 'Verified against the authorized fixture response.', analyst_severity: 'HIGH', analyst_confidence: 'MEDIUM', priority_override: 'HIGH', override_reason: 'Escalated for a production release review.' })
    expect(sent.body).not.toHaveProperty('severity')
    expect(sent.body).not.toHaveProperty('confidence')
    const facts = document.querySelector('.finding-facts')!
    expect(facts).toHaveTextContent('Automated severityMedium')
    expect(facts).toHaveTextContent('Automated confidenceHigh')
    expect(screen.getByText('Medium severity, high confidence, and internal exposure determine this priority.')).toBeVisible()
    expect(screen.getByRole('link', { name: /Inspect triggering evidence/ })).toHaveAttribute('href', '/evidence/e-1')
  })

  it('persists an analyst note and its source evidence link', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call, data) => {
      if (call.path === '/findings/f-1/notes' && call.method === 'POST') {
        const input = call.body as { author: string; content: string }
        const note: Note = { id: 'n-1', assessment_id: 'a-1', finding_id: 'f-1', case_id: null, evidence_id: 'note-e-1', created_at: data.assessment.created_at, ...input }
        data.finding.notes.push(note)
        return json(note, 201)
      }
    })
    renderApp('/findings/f-1')
    await user.type(await screen.findByLabelText(/New analyst note/), 'Rechecked the response; policy remains absent.')
    await user.click(screen.getByRole('button', { name: 'Add note' }))
    expect(await screen.findByText('Note saved.')).toBeVisible()
    expect(screen.getByText('Rechecked the response; policy remains absent.')).toBeVisible()
    expect(screen.getByRole('link', { name: /Note evidence/ })).toHaveAttribute('href', '/evidence/note-e-1')
    expect(calls.find((c) => c.path.endsWith('/notes') && c.method === 'POST')?.body).toEqual({ author: 'Local analyst', content: 'Rechecked the response; policy remains absent.' })
  })

  it('retains analyst input and shows an actionable error when saving fails', async () => {
    const user = userEvent.setup()
    mockApi((call) => call.method === 'PATCH' ? json({ detail: 'A reason is required for this override.' }, 422) : undefined)
    renderApp('/findings/f-1')
    const input = await screen.findByLabelText(/Analyst conclusion/)
    await user.type(input, 'Unsaved verification notes.')
    await user.click(screen.getByRole('button', { name: 'Save analyst review' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('A reason is required for this override.')
    expect(input).toHaveValue('Unsaved verification notes.')
  })

  it('renders raw evidence as inert text and preserves redaction with keyboard-accessible tabs', async () => {
    const user = userEvent.setup()
    mockApi()
    renderApp('/evidence/e-1')
    expect(await screen.findByRole('heading', { level: 1, name: 'Captured fixture response' })).toBeVisible()
    expect(screen.getByLabelText('Structured evidence')).toHaveTextContent('[REDACTED]')
    const structuredTab = screen.getByRole('tab', { name: 'Structured' })
    structuredTab.focus()
    await user.keyboard('{ArrowRight}')
    const raw = screen.getByRole('tabpanel')
    expect(raw).toHaveTextContent('<script>window.untrustedTarget = true</script>')
    expect(raw).toHaveTextContent('Authorization: [REDACTED]')
    expect(raw.querySelector('script')).toBeNull()
    expect(screen.getByRole('tab', { name: 'Raw evidence' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('a'.repeat(64))).toBeVisible()
  })

  it('renders request/response captures as text and explicitly warns about truncation', async () => {
    const user = userEvent.setup()
    mockApi()
    renderApp('/transactions/t-1')
    expect(await screen.findByText(/Response body was truncated/)).toBeVisible()
    await user.click(screen.getByRole('tab', { name: 'Raw response' }))
    expect(screen.getByLabelText('Raw HTTP response')).toHaveTextContent('<script>window.untrustedTarget = true</script>')
    expect(screen.getByLabelText('Raw HTTP response').querySelector('script')).toBeNull()
    expect(screen.getByRole('link', { name: 'e-reques' })).toHaveAttribute('href', '/evidence/e-request')
  })
})

describe('inventory, cases, configuration, and exports', () => {
  it('adds a manual endpoint as inventory without sending target requests', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call) => call.method === 'POST' && call.path.endsWith('/endpoints') ? json({ id: 'endpoint-1' }, 201) : undefined)
    renderApp('/assessments/a-1/endpoints')
    await user.click(await screen.findByRole('button', { name: 'Add endpoint' }))
    await user.type(screen.getByLabelText('Endpoint URL'), 'https://fixture.test/api/profile')
    await user.selectOptions(screen.getByLabelText(/HTTP method/), 'POST')
    await user.click(screen.getByRole('button', { name: 'Save endpoint' }))
    expect(await screen.findByText(/Endpoint saved with source evidence/)).toBeVisible()
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ url: 'https://fixture.test/api/profile', method: 'POST', parameters: [] })
    expect(calls.every((c) => c.path.startsWith('/'))).toBe(true)
  })

  it('validates OpenAPI JSON locally and imports a parsed document explicitly', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call) => call.method === 'POST' && call.path.endsWith('/openapi') ? json({ imported: 1 }) : undefined)
    renderApp('/assessments/a-1/endpoints')
    await user.click(await screen.findByRole('button', { name: 'Import OpenAPI' }))
    const textarea = screen.getByLabelText('OpenAPI document')
    await user.type(textarea, 'not json')
    await user.click(screen.getByRole('button', { name: 'Import inventory' }))
    expect(await screen.findByRole('alert')).toBeVisible()
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    await user.clear(textarea)
    const document = { openapi: '3.0.3', info: { title: 'Test', version: '1' }, paths: {} }
    await user.click(textarea)
    await user.paste(JSON.stringify(document))
    await user.click(screen.getByRole('button', { name: 'Import inventory' }))
    expect(await screen.findByText(/OpenAPI inventory imported/)).toBeVisible()
    expect(calls.find((c) => c.path.endsWith('/openapi'))?.body).toEqual({ document })
  })

  it('enforces the exact 2,000,000-byte OpenAPI file boundary', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi()
    renderApp('/assessments/a-1/endpoints')
    const openImport = await screen.findByRole('button', { name: 'Import OpenAPI' })
    await waitFor(() => expect(openImport).toBeEnabled())
    await user.click(openImport)
    expect(screen.getByText('Maximum 2 MB. JSON only; convert YAML locally before importing.')).toBeVisible()
    const input = screen.getByLabelText(/OpenAPI JSON file/)
    const allowedText = '{}'.padEnd(2_000_000, ' ')
    const allowed = new File([allowedText], 'at-limit.json', { type: 'application/json' })
    const readAllowed = vi.fn().mockResolvedValue(allowedText)
    Object.defineProperty(allowed, 'text', { value: readAllowed })
    expect(allowed.size).toBe(2_000_000)
    await user.upload(input, allowed)
    await waitFor(() => expect(readAllowed).toHaveBeenCalledOnce())
    expect(screen.getByLabelText('OpenAPI document')).toHaveValue(allowedText)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    const oversized = new File([allowedText, ' '], 'over-limit.json', { type: 'application/json' })
    const readOversized = vi.fn()
    Object.defineProperty(oversized, 'text', { value: readOversized })
    expect(oversized.size).toBe(2_000_001)
    await user.upload(input, oversized)
    expect(screen.getByRole('alert')).toHaveTextContent('The document exceeds the 2 MB import limit.')
    expect(readOversized).not.toHaveBeenCalled()
    expect(calls.some((call) => call.method === 'POST')).toBe(false)
  })

  it('creates a case with selected finding/evidence links and updates its lifecycle', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call, data) => {
      if (call.path === '/assessments/a-1/cases' && call.method === 'POST') {
        const body = call.body as CaseInput
        Object.assign(data.caseDetail, { title: body.title, description: body.description, assigned_analyst: body.assigned_analyst, priority: body.priority })
        return json(data.caseDetail, 201)
      }
      if (call.path === '/cases/c-1' && call.method === 'PATCH') {
        Object.assign(data.caseDetail, call.body)
        return json(data.caseDetail)
      }
    })
    renderApp('/assessments/a-1/cases')
    await user.click(await screen.findByRole('button', { name: 'New case' }))
    await user.type(await screen.findByLabelText('Case title'), 'Browser policy review')
    await user.click(await screen.findByLabelText(/Missing fixture policy/))
    await user.click(screen.getByLabelText(/Captured fixture response/))
    await user.click(screen.getByRole('button', { name: 'Create case' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Browser policy review' })).toBeVisible()
    expect(calls.find((c) => c.path.endsWith('/cases') && c.method === 'POST')?.body).toMatchObject({ finding_ids: ['f-1'], evidence_ids: ['e-1'] })
    for (const next of ['INVESTIGATING', 'REMEDIATION', 'VERIFICATION', 'CLOSED', 'INVESTIGATING', 'OPEN']) {
      await user.click(screen.getByRole('button', { name: 'Edit case & links' }))
      const status = screen.getByRole('combobox', { name: /Case status/ })
      if (next === 'INVESTIGATING') expect(within(status).queryByRole('option', { name: 'Verification' })).not.toBeInTheDocument()
      await user.selectOptions(status, next)
      await user.click(screen.getByRole('button', { name: 'Save case' }))
      await screen.findByRole('button', { name: 'Edit case & links' })
      expect(document.querySelector('[aria-current="step"]')).toHaveTextContent(next[0] + next.slice(1).toLowerCase())
    }
    expect(calls.filter((c) => c.path === '/cases/c-1' && c.method === 'PATCH').map((c) => c.body)).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: 'VERIFICATION', finding_ids: ['f-1'], evidence_ids: ['e-1'] }),
      expect.objectContaining({ status: 'CLOSED' }),
    ]))
  })

  describe('enforced lifecycle and authorization contracts', () => {
    it('requires target validation before network collection and exposes the READY transition', async () => {
      const user = userEvent.setup()
      const { calls, data } = mockApi((call, state) => {
        if (call.path.endsWith('/validate') && call.method === 'POST') {
          state.assessment.status = 'READY'
          return json(state.assessment)
        }
      })
      data.assessment.status = 'DRAFT'
      data.assessment.config.mode = 'SAFE_HTTP'
      data.assessment.config.safe_paths = ['/health']
      renderApp('/assessments/a-1')
      const validate = await screen.findByRole('button', { name: 'Validate target' })
      expect(screen.getByRole('button', { name: 'Discover' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Safe checks' })).toBeDisabled()
      await user.click(validate)
      expect(await screen.findByText('Target and scope validated.')).toBeVisible()
      expect(screen.getByRole('button', { name: 'Discover' })).toBeEnabled()
      expect(screen.getByRole('button', { name: 'Safe checks' })).toBeEnabled()
      expect(calls.filter((call) => call.method === 'POST').map((call) => call.path)).toEqual(['/assessments/a-1/validate'])
    })

    it('allows PASSIVE analysis without authorization and never enables network actions', async () => {
      const user = userEvent.setup()
      const { calls, data } = mockApi((call, state) => call.path.endsWith('/analyze') && call.method === 'POST' ? json(state.assessment) : undefined)
      data.assessment.status = 'DRAFT'
      data.assessment.authorized = false
      data.assessment.authorization_note = ''
      renderApp('/assessments/a-1')
      const analyze = await screen.findByRole('button', { name: 'Analyze evidence' })
      expect(analyze).toBeEnabled()
      expect(screen.getByRole('button', { name: 'Validate target' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Discover' })).toBeDisabled()
      await user.click(analyze)
      expect(await screen.findByText(/Deterministic analysis completed/)).toBeVisible()
      expect(calls.filter((call) => call.method === 'POST').map((call) => call.path)).toEqual(['/assessments/a-1/analyze'])
    })

    it('sends a sparse metadata patch without unnecessarily invalidating validated scope', async () => {
      const user = userEvent.setup()
      const { calls } = mockApi((call, state) => {
        if (call.path === '/assessments/a-1' && call.method === 'PATCH') { Object.assign(state.assessment, call.body); return json(state.assessment) }
      })
      renderApp('/assessments/a-1/edit')
      await user.type(await screen.findByLabelText('Description'), ' Additional review context.')
      await user.click(screen.getByRole('button', { name: 'Save assessment policy' }))
      await screen.findByRole('heading', { level: 1, name: 'Fixture assessment' })
      expect(calls.find((call) => call.method === 'PATCH')?.body).toEqual({ description: 'Synthetic frontend integration fixture. Additional review context.' })
      expect(document.querySelector('.page-header .badge')).toHaveTextContent('Ready')
    })

    it.each(['scope', 'private network'])('requires explicit reauthorization for a changed %s boundary', async (boundary) => {
      const user = userEvent.setup()
      const { calls } = mockApi((call, state) => {
        if (call.path === '/assessments/a-1' && call.method === 'PATCH') {
          Object.assign(state.assessment, call.body, { status: 'DRAFT' })
          return json(state.assessment)
        }
      })
      renderApp('/assessments/a-1/edit')
      await screen.findByLabelText('Assessment name')
      if (boundary === 'scope') await user.type(screen.getByLabelText(/Allowed hosts/), '\napi.fixture.test')
      else await user.click(screen.getByLabelText(/Permit private \/ loopback networks/))
      expect(screen.getByRole('button', { name: 'Save assessment policy' })).toBeDisabled()
      await user.click(screen.getByLabelText('I explicitly reauthorize the updated scope and network policy'))
      await user.click(screen.getByRole('button', { name: 'Save assessment policy' }))
      await screen.findByRole('heading', { level: 1, name: 'Fixture assessment' })
      expect(calls.find((call) => call.method === 'PATCH')?.body).toMatchObject({ authorized: true, authorization_note: 'Test-only permission' })
      expect(document.querySelector('.page-header .badge')).toHaveTextContent('Draft')
      expect(screen.getByRole('button', { name: 'Discover' })).toBeDisabled()
    })

    it('requires archiving before deletion and locks mutations while archived', async () => {
      const user = userEvent.setup()
      const { calls } = mockApi((call, state) => {
        if (call.path === '/assessments/a-1' && call.method === 'PATCH') { Object.assign(state.assessment, call.body); return json(state.assessment) }
        if (call.path === '/assessments/a-1' && call.method === 'DELETE') return new Response(null, { status: 204 })
      })
      renderApp('/assessments/a-1')
      expect(await screen.findByRole('button', { name: 'Delete assessment' })).toBeDisabled()
      await user.click(screen.getByRole('button', { name: 'Archive assessment' }))
      await screen.findByRole('button', { name: 'Restore to draft' })
      expect(screen.getByRole('button', { name: 'Delete assessment' })).toBeEnabled()
      expect(screen.getByRole('button', { name: 'Analyze evidence' })).toBeDisabled()
      expect(screen.queryByRole('button', { name: 'Add note' })).not.toBeInTheDocument()
      expect(screen.queryByRole('link', { name: 'Edit policy' })).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Delete assessment' }))
      const dialog = screen.getByRole('dialog', { name: 'Delete this assessment?' })
      await user.click(within(dialog).getByRole('button', { name: 'Delete assessment' }))
      await screen.findByRole('heading', { level: 1, name: 'Assessments' })
      expect(calls.filter((call) => call.method !== 'GET').map((call) => call.method)).toEqual(['PATCH', 'DELETE'])
    })

    it.each([
      ['/assessments/a-1/endpoints', 'Add endpoint'],
      ['/findings/f-1', 'Save analyst review'],
      ['/cases/c-1', 'Edit case & links'],
      ['/assessments/a-1/reports', 'Generate report'],
      ['/assessments/a-1/cases', 'New case'],
      ['/evidence/e-1', 'Capture redacted evidence'],
    ])('keeps archived records read-only at %s', async (path, button) => {
      const { data, calls } = mockApi()
      data.assessment.status = 'ARCHIVED'
      renderApp(path)
      expect(await screen.findByText(/This assessment is archived and read-only/)).toBeVisible()
      expect(screen.getByRole('button', { name: button })).toBeDisabled()
      expect(screen.queryByRole('button', { name: 'Add note' })).not.toBeInTheDocument()
      expect(calls.some((call) => call.method !== 'GET')).toBe(false)
    })

    it.each(['CONFIRMED', 'FALSE_POSITIVE', 'DISMISSED'])('requires a conclusion for %s disposition', async (status) => {
      const user = userEvent.setup()
      mockApi()
      renderApp('/findings/f-1')
      const review = await screen.findByLabelText('Review status')
      await waitFor(() => expect(review).toBeEnabled())
      await user.selectOptions(review, status)
      expect(screen.getByRole('button', { name: 'Save analyst review' })).toBeDisabled()
      await user.type(screen.getByLabelText(/Analyst conclusion/), 'Disposition based on the recorded evidence.')
      expect(screen.getByRole('button', { name: 'Save analyst review' })).toBeEnabled()
    })

    it('requires a durable explanation for severity reclassification', async () => {
      const user = userEvent.setup()
      mockApi()
      renderApp('/findings/f-1')
      const severity = await screen.findByLabelText(/Analyst severity/)
      await waitFor(() => expect(severity).toBeEnabled())
      await user.selectOptions(severity, 'HIGH')
      expect(screen.getByRole('button', { name: 'Save analyst review' })).toBeDisabled()
      await user.type(screen.getByLabelText(/Analyst conclusion/), 'Higher impact for this production asset.')
      expect(screen.getByRole('button', { name: 'Save analyst review' })).toBeEnabled()
    })

    it('preserves the CORS allow_credentials observation and links its source response', async () => {
      const user = userEvent.setup()
      mockApi((call, state) => call.path.endsWith('/controls') ? json({
        headers: [], cookies: [], cors: [{
          ...state.evidence,
          id: 'cors-1',
          data: { origin: 'https://webscope.invalid', allow_credentials: true, methods: 'GET', headers: 'Content-Type', request_origin: 'https://webscope.invalid', vary: 'Origin', source_evidence_id: 'e-1' },
        }],
      }) : undefined)
      renderApp('/assessments/a-1/controls')
      await user.click(await screen.findByRole('tab', { name: 'CORS' }))
      expect(await screen.findByRole('cell', { name: 'true' })).toBeVisible()
      expect(screen.getByRole('link', { name: 'Source response' })).toHaveAttribute('href', '/evidence/e-1')
      expect(screen.getByRole('link', { name: 'CORS observation' })).toHaveAttribute('href', '/evidence/cors-1')
    })
  })

  it('persists settings while keeping existing assessment policy separate', async () => {
    const user = userEvent.setup()
    const { calls } = mockApi((call, data) => {
      if (call.path === '/settings' && call.method === 'PATCH') { data.config = call.body as Configuration; return json(data.config) }
    })
    renderApp('/settings')
    const budget = await screen.findByLabelText('Request budget')
    await user.clear(budget)
    await user.type(budget, '12')
    await user.click(screen.getByLabelText(/DNS collection/))
    await user.click(screen.getByLabelText(/Check HTTP\/HTTPS availability/))
    await user.click(screen.getByLabelText(/Observe advertised methods/))
    await user.click(screen.getByRole('button', { name: 'Save defaults' }))
    expect(await screen.findByText(/Workstation defaults saved/)).toBeVisible()
    expect(calls.find((c) => c.method === 'PATCH')?.body).toMatchObject({ max_requests: 12, dns: true, mode: 'PASSIVE', availability: true, methods: true })
    expect(calls.some((c) => c.path.startsWith('/assessments/') && c.method === 'PATCH')).toBe(false)
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
  })

  it('generates a report and downloads actual API response bytes', async () => {
    const user = userEvent.setup()
    const reports: object[] = []
    const { calls } = mockApi((call) => {
      if (call.path === '/assessments/a-1/reports' && call.method === 'POST') {
        const report = { id: 'r-1', assessment_id: 'a-1', created_at: '2026-10-07T12:00:00Z', filename: 'assessment.md', format: 'markdown', dataset: 'assessment', sha256: 'c'.repeat(64) }
        reports.push(report)
        return json(report, 201)
      }
      if (call.path === '/assessments/a-1/reports') return json(reports)
      if (call.path === '/reports/r-1/download') return new Response('# Test report\nVerified byte content.', { headers: { 'Content-Type': 'text/markdown' } })
    })
    const createObjectURL = vi.fn((_blob: Blob) => 'blob:webscope-test')
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    renderApp('/assessments/a-1/reports')
    await user.click(await screen.findByRole('button', { name: 'Generate report' }))
    await user.click(await screen.findByRole('button', { name: 'Download assessment.md' }))
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled())
    expect(await (createObjectURL.mock.calls[0][0] as Blob).text()).toContain('Verified byte content.')
    expect(click).toHaveBeenCalledOnce()
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ format: 'markdown', dataset: 'assessment' })
    expect(calls.some((c) => c.path === '/reports/r-1/download')).toBe(true)
  })
})

describe('redacted persisted evidence captures', () => {
  function screenshot(data: Fixture): EvidenceDetail {
    return {
      ...data.evidence,
      id: 's-1',
      type: 'SCREENSHOT',
      source: 'webscope:evidence:e-1',
      summary: 'Rendered redacted evidence capture',
      raw: '',
      data: { source_evidence_id: 'e-1', media_type: 'image/png', width: 1100, height: 650, image_base64: 'BASE64_IMAGE_BYTES_MUST_NOT_APPEAR_IN_THE_PANEL', rendering: 'Redacted persisted text only' },
      lineage: [{ parent_id: 'e-1', child_id: 's-1', assessment_id: 'a-1', relation: 'DERIVED_FROM' }],
    }
  }

  it('captures redacted text through the API, displays PNG metadata safely, and navigates lineage', async () => {
    const user = userEvent.setup()
    let captured: EvidenceDetail | undefined
    const { calls } = mockApi((call, data) => {
      if (call.path === '/evidence/e-1/capture' && call.method === 'POST') {
        captured = screenshot(data)
        data.evidence.lineage = captured.lineage
        return json(captured, 201)
      }
      if (call.path === '/evidence/s-1') return json(captured)
    })
    renderApp('/evidence/e-1')
    const capture = await screen.findByRole('button', { name: 'Capture redacted evidence' })
    await waitFor(() => expect(capture).toBeEnabled())
    await user.click(capture)
    expect(await screen.findByText('Redacted evidence capture · not a target-browser screenshot')).toBeVisible()
    const image = screen.getByRole('img', { name: 'Redacted persisted evidence text capture' })
    expect(image).toHaveAttribute('src', '/api/evidence/s-1/image')
    fireEvent.load(image)
    expect(screen.queryByText('Loading redacted capture…')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Structured evidence')).toHaveTextContent('"media_type": "image/png"')
    expect(screen.getByLabelText('Structured evidence')).not.toHaveTextContent('image_base64')
    expect(document.body).not.toHaveTextContent('BASE64_IMAGE_BYTES_MUST_NOT_APPEAR_IN_THE_PANEL')
    expect(screen.queryByRole('button', { name: 'Capture redacted evidence' })).not.toBeInTheDocument()
    const write = calls.find((call) => call.path === '/evidence/e-1/capture')!
    expect(write.body).toEqual({})
    expect(write.headers.get('X-WebScope-Request')).toBe('workstation')
    expect(write.headers.get('Content-Type')).toBe('application/json')
    expect(screen.getByRole('link', { name: 'e-1' })).toHaveAttribute('href', '/evidence/e-1')
    expect(screen.getByRole('link', { name: 's-1' })).toHaveAttribute('href', '/evidence/s-1')
    await user.click(screen.getByRole('link', { name: 'e-1' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Captured fixture response' })).toBeVisible()
    expect(screen.getByRole('link', { name: 's-1' })).toHaveAttribute('href', '/evidence/s-1')
    expect(calls.filter((call) => call.method === 'POST')).toHaveLength(1)
  })

  it('reports capture failure without hiding or changing the source evidence', async () => {
    const user = userEvent.setup()
    mockApi((call) => call.path.endsWith('/capture') ? json({ detail: 'Capture renderer is unavailable. Please retry.' }, 503) : undefined)
    renderApp('/evidence/e-1')
    const capture = await screen.findByRole('button', { name: 'Capture redacted evidence' })
    await waitFor(() => expect(capture).toBeEnabled())
    await user.click(capture)
    expect(await screen.findByRole('alert')).toHaveTextContent('Capture renderer is unavailable. Please retry.')
    expect(screen.getByRole('heading', { level: 1, name: 'Captured fixture response' })).toBeVisible()
    expect(screen.getByLabelText('Structured evidence')).toHaveTextContent('[REDACTED]')
    expect(capture).toBeEnabled()
  })

  it('provides retry for PNG loading failures without embedding base64 or target HTML', async () => {
    const user = userEvent.setup()
    mockApi((call, data) => call.path === '/evidence/s-1' ? json(screenshot(data)) : undefined)
    renderApp('/evidence/s-1')
    const image = await screen.findByRole('img', { name: 'Redacted persisted evidence text capture' })
    fireEvent.error(image)
    expect(screen.getByRole('alert')).toHaveTextContent('The redacted evidence image could not be loaded.')
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    const retryImage = screen.getByRole('img', { name: 'Redacted persisted evidence text capture' })
    expect(retryImage).toHaveAttribute('src', '/api/evidence/s-1/image')
    fireEvent.load(retryImage)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Raw evidence' })).not.toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })
})
