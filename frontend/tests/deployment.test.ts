import { execFileSync, spawnSync } from 'node:child_process'
import { expect, test } from 'vitest'

test('Vercel config creates a same-origin API proxy and SPA fallback', () => {
  const output = execFileSync(process.execPath, ['--input-type=module', '-e',
    "import('./vercel.mjs').then(({config}) => console.log(JSON.stringify(config)))"],
  { cwd: process.cwd(), env: { ...process.env, WEBSCOPE_API_ORIGIN: 'https://webscope-api.onrender.com' } }).toString()
  const config = JSON.parse(output)
  expect(config.rewrites[0]).toEqual({ source: '/api/:path*', destination: 'https://webscope-api.onrender.com/api/:path*' })
  expect(config.rewrites.at(-1).destination).toBe('/index.html')
  expect(config.headers[1].headers[0].value).toContain('no-store')
})

test.each(['', 'http://api.example', 'https://api.example/path', 'https://name:pass@api.example', 'https://api.example?query=1'])(
  'Vercel configuration fails closed for invalid API origin %s', value => {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./vercel.mjs')"],
      { env: { ...process.env, WEBSCOPE_API_ORIGIN: value } })
    expect(result.status).not.toBe(0)
  },
)
