import { test, expect, type Page } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const proof = path.resolve(process.env.WEBSCOPE_PROOF_DIR || 'test-results/example')
const screenshots = path.resolve(process.env.WEBSCOPE_SCREENSHOT_DIR || 'test-results/screenshots')

test.beforeEach(async ({ page }) => {
  const response = await page.request.post('/api/session', {
    headers: { 'X-WebScope-Request': 'workstation' }, data: {},
  })
  expect(response.ok()).toBeTruthy()
})

test.afterEach(async ({ page }) => {
  await page.request.delete('/api/session', {
    headers: { 'X-WebScope-Request': 'workstation', 'Content-Type': 'application/json' },
  })
})

async function submit(page: Page, button: string, suffix: string, method = 'POST') {
  const [response] = await Promise.all([
    page.waitForResponse(r => r.url().endsWith(suffix) && r.request().method() === method),
    page.getByRole('button', { name: button, exact: true }).click(),
  ])
  expect(response.ok(), await response.text()).toBeTruthy()
  return response.json()
}

test('complete real local assessment, analyst investigation and all export formats', async ({ page }) => {
  const request = page.request
  test.setTimeout(180_000)
  mkdirSync(proof, { recursive: true })
  mkdirSync(screenshots, { recursive: true })
  const pageErrors: string[] = []
  page.on('pageerror', error => pageErrors.push(error.message))
  const fixtureBefore = await (await request.get('http://127.0.0.1:9998/fixture-requests')).json() as string[]
  await page.goto('/assessments/new')
  await page.getByLabel('Assessment name', { exact: true }).fill('WebScope local fixture assessment')
  await page.getByLabel(/^Target URL/).fill('http://127.0.0.1:9998')
  await page.getByLabel('Description', { exact: true }).fill('Deterministic owned loopback fixture. No external scanning.')
  await page.getByLabel(/^Allowed hosts/).fill('127.0.0.1')
  await page.getByLabel(/^Excluded paths/).fill('/admin\n/payments')
  await page.getByRole('combobox', { name: 'Collection mode' }).selectOption('SAFE_HTTP')
  await page.getByLabel('Requests per second', { exact: true }).fill('10')
  await page.getByLabel(/^Safe check paths/).fill('/.env\n/.git/\n/debug\n/cors')
  await page.getByLabel(/^Permit private/).check()
  await page.getByLabel(/^I am authorized/).check()
  await page.getByLabel(/^Authorization note/).fill('I own the loopback WebScope fixture and authorize bounded read-only collection.')
  const assessment = await submit(page, 'Create assessment', '/api/assessments')
  const aid = assessment.id as string
  await page.waitForURL(`/assessments/${aid}`)
  await submit(page, 'Validate target', `/assessments/${aid}/validate`)
  await page.getByRole('button', { name: 'Discover', exact: true }).click()
  const discovered = await submit(page, 'Start discovery', `/assessments/${aid}/discover`)
  expect(discovered.status).toBe('COMPLETED')
  expect(discovered.counts.endpoints).toBeGreaterThan(10)
  expect(discovered.counts.evidence).toBeGreaterThan(20)
  await page.getByRole('button', { name: 'Safe checks', exact: true }).click()
  await page.getByLabel(/^Check CORS/).check()
  await submit(page, 'Confirm safe checks', `/assessments/${aid}/checks`)

  await page.getByRole('link', { name: 'Review findings', exact: true }).click()
  await page.getByRole('link', { name: 'Potential unsafe credentialed origin reflection', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Why WebScope flagged this', exact: true })).toBeVisible()
  const fid = page.url().split('/').at(-1)!
  const original = await (await request.get(`/api/findings/${fid}`)).json()
  const eid = original.evidence_id as string
  await page.getByRole('combobox', { name: 'Review status' }).selectOption('CONFIRMED')
  const conclusion = 'Confirmed the unsafe origin configuration in the owned fixture; authenticated data impact was not tested.'
  await page.getByLabel(/^Analyst conclusion/).fill(conclusion)
  await page.getByRole('combobox', { name: 'Priority override' }).selectOption('HIGH')
  await page.getByLabel(/^Override reason/).fill('Prioritize configuration correction before production deployment.')
  const reviewed = await submit(page, 'Save analyst review', `/api/findings/${fid}`, 'PATCH')
  expect(reviewed.automated).toEqual(original.automated)
  expect(reviewed.risk.priority).toBe('HIGH')
  await page.getByLabel(/^New analyst note/).fill('Verified with the configured synthetic Origin probe. Source evidence retained.')
  await submit(page, 'Add note', `/api/findings/${fid}/notes`)

  await page.getByRole('link', { name: 'Inspect triggering evidence', exact: true }).click()
  await page.getByRole('tab', { name: 'Raw evidence', exact: true }).click()
  await expect(page.locator('pre').first()).toContainText('access-control-allow-credentials: true')
  const capture = await submit(page, 'Capture redacted evidence', `/api/evidence/${eid}/capture`)
  await page.waitForURL(`/evidence/${capture.id}`)
  const image = page.getByRole('img', { name: 'Redacted persisted evidence text capture', exact: true })
  await expect(image).toBeVisible()
  await expect.poll(() => image.evaluate((el: HTMLImageElement) => el.naturalWidth)).toBe(1100)
  await expect(page.getByText('Redacted evidence capture · not a target-browser screenshot', { exact: true })).toBeVisible()

  await page.getByRole('link', { name: 'Endpoints', exact: true }).click()
  await page.getByRole('button', { name: 'Add endpoint', exact: true }).click()
  await page.getByLabel('Endpoint URL', { exact: true }).fill('http://127.0.0.1:9998/manual-inventory')
  await page.getByRole('combobox', { name: /HTTP method/ }).selectOption('POST')
  await page.getByLabel(/^Parameters \(JSON\)/).fill('[{"name":"filter","in":"body","type":"string"}]')
  await submit(page, 'Save endpoint', `/assessments/${aid}/endpoints`)
  await page.getByRole('button', { name: 'Import OpenAPI', exact: true }).click()
  await page.getByLabel(/^OpenAPI JSON file/).setInputFiles(path.resolve('../fixtures/api/openapi.json'))
  const imported = await submit(page, 'Import inventory', `/assessments/${aid}/openapi`)
  expect(imported.imported).toBe(2)

  await page.getByRole('link', { name: 'Cases', exact: true }).click()
  await page.getByRole('button', { name: 'New case', exact: true }).click()
  await page.getByLabel('Case title', { exact: true }).fill('Fixture CORS remediation case')
  await page.getByLabel('Assigned analyst', { exact: true }).fill('Local fixture analyst')
  await page.getByLabel('Case description', { exact: true }).fill('Evidence-led configuration remediation and verification.')
  await page.getByRole('combobox', { name: 'Case priority' }).selectOption('HIGH')
  await page.getByRole('checkbox', { name: /Potential unsafe credentialed origin reflection/ }).check()
  await page.getByRole('checkbox', { name: new RegExp(eid.slice(0, 8)) }).check()
  const investigation = await submit(page, 'Create case', `/assessments/${aid}/cases`)
  const cid = investigation.id as string
  await page.waitForURL(`/cases/${cid}`)
  await page.getByLabel(/^New analyst note/).fill('Test case lifecycle completed; no target data was changed.')
  await submit(page, 'Add note', `/api/cases/${cid}/notes`)
  for (const stage of ['INVESTIGATING', 'REMEDIATION', 'VERIFICATION', 'CLOSED']) {
    if (!await page.getByRole('button', { name: 'Save case', exact: true }).isVisible()) {
      await page.getByRole('button', { name: 'Edit case & links', exact: true }).click()
    }
    await page.getByRole('combobox', { name: /^Case status/ }).selectOption(stage)
    const changed = await submit(page, 'Save case', `/api/cases/${cid}`, 'PATCH')
    expect(changed.status).toBe(stage)
  }

  for (const [route, heading] of [
    ['technologies', 'Technolog'], ['transactions', 'HTTP transaction'],
    ['controls', 'Security controls'], ['timeline', 'Timeline'],
  ]) {
    await page.goto(`/assessments/${aid}/${route}`)
    await expect(page.locator('main h1')).toContainText(new RegExp(heading, 'i'))
    await page.waitForLoadState('networkidle')
    await expect(page.locator('main')).not.toContainText('Unable to')
  }

  const tx = (await (await request.get(`/api/assessments/${aid}/transactions`)).json())[0]
  await page.goto(`/transactions/${tx.id}`)
  await expect(page.getByRole('heading', { name: 'HTTP request', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'HTTP response', exact: true })).toBeVisible()
  const priorCount = (await (await request.get('http://127.0.0.1:9998/fixture-requests')).json() as string[]).length
  await page.goto(`/assessments/${aid}`)
  await submit(page, 'Analyze evidence', `/assessments/${aid}/analyze`)
  const afterCount = (await (await request.get('http://127.0.0.1:9998/fixture-requests')).json() as string[]).length
  expect(afterCount).toBe(priorCount + 1) // Only the fixture's audit-read request itself.

  await page.getByRole('link', { name: 'Reports', exact: true }).click()
  const exported: { format: string; dataset: string; id: string; filename: string; artifact: string }[] = []
  for (const [format, dataset] of [
    ['markdown', 'assessment'], ['json', 'assessment'], ['pdf', 'assessment'],
    ['csv', 'endpoints'], ['csv', 'findings'], ['csv', 'technologies'], ['csv', 'evidence'],
  ]) {
    await page.getByRole('combobox', { name: 'Report format' }).selectOption(format)
    await page.getByRole('combobox', { name: 'Report dataset' }).selectOption(dataset)
    const report = await submit(page, 'Generate report', `/assessments/${aid}/reports`)
    const extension = format === 'markdown' ? 'md' : format
    const artifact = `${dataset}.${extension}`
    exported.push({ format, dataset, id: report.id, filename: report.filename, artifact })
    const download = await request.get(`/api/reports/${report.id}/download`)
    expect(download.ok()).toBeTruthy()
    writeFileSync(path.join(proof, artifact), await download.body())
  }
  const artifactLink = page.getByRole('button', { name: /Download/ }).first()
  await expect(artifactLink).toBeVisible()
  const [download] = await Promise.all([page.waitForEvent('download'), artifactLink.click()])
  expect(await download.failure()).toBeNull()

  const final = await (await request.get(`/api/assessments/${aid}`)).json()
  const evidence = await (await request.get(`/api/assessments/${aid}/evidence`)).json()
  const graph = await (await request.get(`/api/assessments/${aid}/graph`)).json()
  const timeline = await (await request.get(`/api/assessments/${aid}/timeline`)).json()
  const actualRequests = (await (await request.get('http://127.0.0.1:9998/fixture-requests')).json() as string[]).slice(fixtureBefore.length)
  for (const forbidden of ['/admin/private', '/session', '/manual-inventory', '/api/orders', '/never-requested']) {
    expect(actualRequests).not.toContain(forbidden)
  }
  expect(evidence.some((e: { type: string }) => e.type === 'REDIRECT_BLOCKED')).toBeTruthy()
  const persisted = JSON.stringify({ final, evidence, graph, timeline })
  for (const secret of ['COOKIE_DUMMY_SECRET', 'PREFERENCE_DUMMY_SECRET', 'FORM_DUMMY_SECRET', 'API_DUMMY_SECRET', 'ENV_DUMMY_SECRET']) {
    expect(persisted).not.toContain(secret)
  }
  writeFileSync(path.join(proof, 'workflow-proof.json'), JSON.stringify({
    observed_at: new Date().toISOString(), assessment_id: aid, finding_id: fid, evidence_id: eid,
    capture_id: capture.id, case_id: cid, counts: final.counts, severity_counts: final.severity_counts,
    graph_nodes: graph.nodes.length, graph_edges: graph.edges.length, actual_fixture_requests: actualRequests,
    network_attempts: timeline.filter((e: { event: string }) => e.event === 'NETWORK_ATTEMPT'),
    exports: exported, page_errors: pageErrors, fixture_only: true,
  }, null, 2))

  // One batched desktop/mobile proof pass; no target content is executed.
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(`/findings/${fid}`)
  await expect(page.getByRole('heading', { name: 'Why WebScope flagged this', exact: true })).toBeVisible()
  await page.screenshot({ path: path.join(screenshots, 'finding-desktop.png') })
  await page.goto(`/evidence/${eid}`)
  await page.getByRole('tab', { name: 'Raw evidence', exact: true }).click()
  await page.screenshot({ path: path.join(screenshots, 'evidence-desktop.png') })
  await page.goto(`/assessments/${aid}/graph`)
  await expect(page.locator('.react-flow__node').first()).toBeVisible()
  await page.screenshot({ path: path.join(screenshots, 'graph-desktop.png') })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/findings/${fid}`)
  await expect(page.getByRole('heading', { name: 'Why WebScope flagged this', exact: true })).toBeVisible()
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy()
  await page.screenshot({ path: path.join(screenshots, 'finding-mobile.png') })
  await page.goto(`/evidence/${eid}`)
  await page.getByRole('tab', { name: 'Raw evidence', exact: true }).click()
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy()
  await page.screenshot({ path: path.join(screenshots, 'evidence-mobile.png') })
  expect(pageErrors).toEqual([])
})

test('passive creation never sends traffic and archive guards remain usable', async ({ page }) => {
  const request = page.request
  await page.goto('/assessments/new')
  await page.getByLabel('Assessment name', { exact: true }).fill('Passive workflow boundary')
  await page.getByLabel(/^Target URL/).fill('http://127.0.0.1:9998')
  await page.getByLabel(/^Allowed hosts/).fill('127.0.0.1')
  await page.getByLabel(/^I am authorized/).check()
  await page.getByLabel(/^Authorization note/).fill('Owned local fixture; passive inventory only.')
  const assessment = await submit(page, 'Create assessment', '/api/assessments')
  await page.waitForURL(`/assessments/${assessment.id}`)
  await expect(page.getByRole('button', { name: 'Discover', exact: true })).toBeDisabled()
  await submit(page, 'Analyze evidence', `/assessments/${assessment.id}/analyze`)
  const result = await (await request.get(`/api/assessments/${assessment.id}/transactions`)).json()
  expect(result).toEqual([])
  await expect(page.getByRole('button', { name: 'Delete assessment', exact: true })).toBeDisabled()
})
