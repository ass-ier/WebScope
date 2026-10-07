import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(new URL('../frontend/package.json', import.meta.url))
const { chromium } = require('@playwright/test')
const root = new URL('../', import.meta.url)
const base = 'http://127.0.0.1:8765'
const browser = await chromium.launch({ headless: true })
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
  const errors = []
  const requests = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => requests.push(request.url()))
  const headers = { 'X-WebScope-Request': 'workstation' }
  assert.equal((await page.request.post(`${base}/api/session`, { headers, data: {} })).status(), 200)
  const assessments = await (await page.request.get(`${base}/api/assessments`)).json()
  const assessment = assessments.find(item => item.data_origin === 'SYNTHETIC' && item.counts.endpoints > 0)
  const findings = await (await page.request.get(`${base}/api/assessments/${assessment.id}/findings`)).json()
  const selected = findings.find(item => item.title === 'Potential unsafe credentialed origin reflection')
  const cases = await (await page.request.get(`${base}/api/assessments/${assessment.id}/cases`)).json()
  const proof = { assessment_id: assessment.id, finding_id: selected.id, evidence_id: selected.evidence_id, case_id: cases[0].id }
  const response = await page.goto(`${base}/findings/${proof.finding_id}`)
  assert.equal(response.status(), 200)
  assert.match(response.headers()['content-security-policy'], /script-src 'self'/)
  await page.getByRole('heading', { name: 'Why WebScope flagged this', exact: true }).waitFor()
  const finding = await (await page.request.get(`${base}/api/findings/${proof.finding_id}`)).json()
  assert.equal(finding.status, 'CONFIRMED')
  assert.equal(finding.risk.priority, 'HIGH')
  assert.ok(finding.notes.length)
  const investigation = await (await page.request.get(`${base}/api/cases/${proof.case_id}`)).json()
  assert.equal(investigation.status, 'CLOSED')
  assert.equal(investigation.findings[0].id, proof.finding_id)
  assert.equal(investigation.evidence[0].id, proof.evidence_id)
  assert.ok(investigation.notes.length)
  await page.goto(`${base}/evidence/${proof.evidence_id}`)
  await page.getByRole('tab', { name: 'Raw evidence', exact: true }).click()
  assert.match(await page.locator('pre').first().innerText(), /access-control-allow-credentials: true/)
  await page.goto(`${base}/assessments/${proof.assessment_id}/graph`)
  await page.locator('.react-flow__node').first().waitFor()
  assert.match(await page.locator('main').innerText(), /28 of 72 nodes/)
  const created = await page.request.post(`${base}/api/assessments/${assessment.id}/reports`, { headers, data: { format: 'pdf' } })
  assert.equal(created.status(), 201)
  const pdf = await created.json()
  const downloaded = await page.request.get(`${base}/api/reports/${pdf.id}/download`)
  assert.equal(downloaded.status(), 200)
  const bytes = await downloaded.body()
  assert.equal(createHash('sha256').update(bytes).digest('hex'), pdf.sha256)
  const schema = await page.request.get(`${base}/openapi.json`)
  assert.equal(schema.status(), 200)
  assert.ok((await schema.json()).paths['/api/assessments'])
  assert.deepEqual(errors, [])
  assert.ok(requests.every(url => new URL(url).origin === base))
  const result = {
    result: 'PASS', observed_at: new Date().toISOString(), base_url: base,
    assessment_id: proof.assessment_id, production_spa_deep_links: true,
    synthetic_finding_notes_case_and_report: true, compiled_graph_visible: true,
    restrictive_csp: true, all_browser_requests_local: true, page_errors: errors,
    requests_observed: requests.length, vite_required: false, target_fixture_required_for_inspection: false,
  }
  await page.request.delete(`${base}/api/session`, { headers: { ...headers, 'Content-Type': 'application/json' } })
  mkdirSync(fileURLToPath(new URL('docs/verification-logs/hosted/', root)), { recursive: true })
  writeFileSync(fileURLToPath(new URL('docs/verification-logs/hosted/local-production-smoke.json', root)),
    JSON.stringify(result, null, 2) + '\n')
  console.log(JSON.stringify(result, null, 2))
} finally {
  await browser.close()
}
