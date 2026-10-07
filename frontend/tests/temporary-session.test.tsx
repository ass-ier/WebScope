import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import App from '../src/App'

const status = {
  mode: 'hosted', temporary: true, session_active: true, network_enabled: false,
  expires_at: new Date(Date.now() + 86_400_000).toISOString(), retention_notice:
    'Temporary for 24 hours. Closing a tab does not guarantee deletion. Restart clears earlier.',
  max_upload_bytes: 2_000_000, max_storage_bytes: 20_000_000, max_assessments: 10,
  formats: ['webscope', 'har', 'openapi'],
}
const json = (data: unknown, code = 200) => new Response(JSON.stringify(data), { status: code })
function setup(path = '/', active = true) {
  const calls: { path: string; method: string; body?: unknown }[] = []
  let isActive = active
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method || 'GET'
    calls.push({ path: url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (url === '/api/session') {
      if (method === 'DELETE') { isActive = false; return new Response(null, { status: 204 }) }
      if (method === 'POST') isActive = true
      return json({ ...status, session_active: isActive, temporary: isActive })
    }
    if (url === '/api/imports') return json({ detail: 'Invalid upload fixture; nothing was imported.' }, 400)
    if (url === '/api/health') return json({ status: 'ok' })
    if (url === '/api/assessments' || url === '/api/cases') return json([])
    return json({ detail: 'Record not found' }, 404)
  }))
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></QueryClientProvider>)
  return { calls, expire: () => { isActive = false } }
}

test('entry has no sign-in and explains expiry, early deletion, browser tabs and exports', async () => {
  const user = userEvent.setup()
  const { calls } = setup('/', false)
  expect(await screen.findByRole('heading', { name: 'Investigate the evidence. No sign-in.' })).toBeVisible()
  expect(screen.getByText(/24 hours after creation/)).toBeVisible()
  expect(screen.getByText(/A hosted restart or redeploy can clear it earlier/)).toBeVisible()
  expect(screen.getByText(/Tabs in the same browser profile share this session/)).toBeVisible()
  expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Start temporary workspace' }))
  expect(await screen.findByLabelText('Temporary workspace notice')).toHaveTextContent('export to keep your work')
  expect(calls.some(c => c.path === '/api/session' && c.method === 'POST')).toBe(true)
})

test('ending a session requires deletion confirmation and clears the workspace', async () => {
  const user = userEvent.setup()
  const { calls } = setup()
  await user.click(await screen.findByRole('button', { name: 'End session' }))
  expect(screen.getByRole('dialog')).toHaveTextContent('Download reports first')
  expect(calls.some(c => c.method === 'DELETE')).toBe(false)
  await user.click(screen.getByRole('button', { name: 'Delete session data' }))
  expect(await screen.findByRole('button', { name: 'Start temporary workspace' })).toBeVisible()
  expect(calls.some(c => c.path === '/api/session' && c.method === 'DELETE')).toBe(true)
})

test('expiry removes cached data and returns to the explicit temporary-session notice', async () => {
  const { expire } = setup()
  await screen.findByLabelText('Temporary workspace notice')
  expire()
  act(() => window.dispatchEvent(new Event('webscope-session-expired')))
  expect(await screen.findByRole('button', { name: 'Start temporary workspace' })).toBeVisible()
  expect(screen.queryByRole('heading', { name: 'Investigation workspace' })).not.toBeInTheDocument()
})

test('upload requires consent, explains privacy, and surfaces API validation errors', async () => {
  const user = userEvent.setup()
  const { calls } = setup('/uploads')
  await screen.findByRole('heading', { name: 'Upload your own data' })
  expect(screen.getByText('Temporary upload — export before your session ends.', { exact: true })).toBeVisible()
  expect(screen.getByText(/Redaction cannot identify every opaque secret/)).toBeVisible()
  const file = new File(['{}'], 'capture.har', { type: 'application/json' })
  Object.defineProperty(file, 'text', { value: async () => '{"log":{"version":"1.2","entries":[]}}' })
  await user.upload(screen.getByLabelText(/^Data file/), file)
  await screen.findByText(/Selected: capture.har/)
  const button = screen.getByRole('button', { name: 'Upload to temporary workspace' })
  expect(button).toBeDisabled()
  await user.click(screen.getByLabelText(/^I am allowed to upload/))
  await user.click(button)
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid upload fixture; nothing was imported.')
  expect(calls.find(c => c.path === '/api/imports')?.body).toMatchObject({ format: 'har', consent: true, name: 'capture' })
})

test('oversized files and malformed JSON are rejected before upload', async () => {
  const user = userEvent.setup()
  const { calls } = setup('/uploads')
  const input = await screen.findByLabelText(/^Data file/)
  const tooLarge = new File(['a'], 'large.json', { type: 'application/json' })
  Object.defineProperty(tooLarge, 'size', { value: 2_000_001 })
  await user.upload(input, tooLarge)
  expect(await screen.findByRole('alert')).toHaveTextContent('exceeds 2 MB')
  const malformed = new File(['not-json'], 'bad.json', { type: 'application/json' })
  Object.defineProperty(malformed, 'text', { value: async () => 'not-json' })
  await user.upload(input, malformed)
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Cannot read this file'))
  expect(calls.some(c => c.path === '/api/imports')).toBe(false)
})
