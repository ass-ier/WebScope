import { expect, test } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

test('anonymous hosted sessions, synthetic data, uploads, privacy and immediate deletion', async ({ page, browser, baseURL }) => {
  test.setTimeout(120_000)
  const pageErrors: string[] = []
  page.on('pageerror', error => pageErrors.push(error.message))
  const outgoing: string[] = []
  page.on('request', request => outgoing.push(request.url()))
  const proof = path.resolve('../docs/verification-logs/hosted')
  mkdirSync(proof, { recursive: true })
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Investigate the evidence. No sign-in.' })).toBeVisible()
  await expect(page.getByText(/24 hours after creation/)).toBeVisible()
  await expect(page.getByText(/A hosted restart or redeploy can clear it earlier/)).toBeVisible()
  await expect(page.locator('input[type=password]')).toHaveCount(0)
  await page.getByRole('button', { name: 'Start temporary workspace', exact: true }).click()
  await expect(page.getByLabel('Temporary workspace notice')).toContainText('export to keep your work')
  await expect(page.getByLabel('Temporary workspace notice')).toContainText('Hosted import-only')
  const synthetic = await (await page.request.get('/api/assessments')).json()
  expect(synthetic).toHaveLength(2)
  const example = synthetic.find((a: { counts: { endpoints: number } }) => a.counts.endpoints > 0)
  expect(example.counts).toMatchObject({ endpoints: 22, findings: 44, cases: 1, evidence: 139 })
  await page.getByRole('link', { name: 'Synthetic web application investigation', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Discover', exact: true })).toBeDisabled()
  await expect(page.getByText('Synthetic example', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'Upload data', exact: true }).first().click()
  await expect(page.getByRole('heading', { name: 'Upload your own data', exact: true })).toBeVisible()
  await expect(page.getByText('Temporary upload — export before your session ends.', { exact: true })).toBeVisible()
  await page.getByLabel('Assessment name', { exact: true }).fill('My temporary HAR')
  await page.getByLabel(/^Data file/).setInputFiles(path.resolve('../fixtures/http/upload.har'))
  await expect(page.getByRole('button', { name: 'Upload to temporary workspace', exact: true })).toBeDisabled()
  await page.getByLabel(/^I am allowed to upload/).check()
  const [importResponse] = await Promise.all([
    page.waitForResponse(r => r.url().endsWith('/api/imports') && r.request().method() === 'POST'),
    page.getByRole('button', { name: 'Upload to temporary workspace', exact: true }).click(),
  ])
  expect(importResponse.status()).toBe(201)
  const imported = await importResponse.json()
  await page.waitForURL(`/assessments/${imported.id}`)
  await expect(page.getByText('Uploaded data · unverified source', { exact: true })).toBeVisible()
  const evidence = await (await page.request.get(`/api/assessments/${imported.id}/evidence`)).json()
  expect(JSON.stringify(evidence)).not.toContain('HAR_SYNTHETIC_SECRET')
  const fid = (await (await page.request.get(`/api/assessments/${imported.id}/findings`)).json())[0].id
  const headers = { 'X-WebScope-Request': 'workstation' }
  const report = await page.request.post(`/api/assessments/${imported.id}/reports`, { headers, data: { format: 'json' } })
  expect(report.status()).toBe(201)
  const reportId = (await report.json()).id
  const exported = await page.request.get(`/api/reports/${reportId}/download`)
  expect((await exported.json()).assessment.id).toBe(imported.id)

  const other = await browser.newContext({ baseURL, ignoreHTTPSErrors: true })
  try {
    expect((await other.request.get(`/api/findings/${fid}`)).status()).toBe(401)
    expect((await other.request.post('/api/session', { headers, data: {} })).status()).toBe(200)
    expect((await other.request.get(`/api/assessments/${imported.id}`)).status()).toBe(404)
    expect((await other.request.get(`/api/findings/${fid}`)).status()).toBe(404)
    expect((await other.request.get(`/api/reports/${reportId}/download`)).status()).toBe(404)
    await other.request.delete('/api/session', { headers: { ...headers, 'Content-Type': 'application/json' } })
  } finally { await other.close() }

  await page.goto('/uploads')
  await page.setViewportSize({ width: 1440, height: 1000 })
  await expect(page.getByRole('heading', { name: 'Upload your own data', exact: true })).toBeVisible()
  await page.screenshot({ path: path.join(proof, 'uploads-desktop.png'), fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: path.join(proof, 'uploads-mobile.png'), fullPage: true })
  const firstToken = (await page.context().cookies()).find(cookie => cookie.name === 'webscope_workspace')!
  expect(firstToken.httpOnly).toBe(true)
  expect(firstToken.secure).toBe(true)
  expect(firstToken.expires).toBe(-1)
  await page.getByRole('button', { name: 'End session', exact: true }).click()
  await expect(page.getByRole('dialog')).toContainText('Download reports first')
  await page.getByRole('button', { name: 'Delete session data', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Start temporary workspace', exact: true })).toBeVisible()
  await page.screenshot({ path: path.join(proof, 'session-notice-mobile.png'), fullPage: true })
  await page.context().addCookies([firstToken])
  expect((await page.request.get(`/api/assessments/${imported.id}`)).status()).toBe(401)
  expect(pageErrors).toEqual([])
  expect(outgoing.every(url => new URL(url).origin === baseURL)).toBeTruthy()
  writeFileSync(path.join(proof, 'browser-proof.json'), JSON.stringify({
    result: 'PASS', observed_at: new Date().toISOString(), no_signin: true,
    synthetic_assessments: synthetic.map((a: { data_origin: string; counts: object }) => ({ origin: a.data_origin, counts: a.counts })),
    imported_counts: imported.counts, redaction: 'PASS', session_isolation: 'PASS',
    immediate_deletion_and_cookie_revocation: 'PASS', http_only_secure_session_cookie: true,
    page_errors: pageErrors, all_browser_requests_same_origin: true,
    environment: 'Owned loopback HTTPS hosted-mode fixture; not a deployed Vercel/Render service',
  }, null, 2))
})
