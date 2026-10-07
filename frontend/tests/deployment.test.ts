import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, existsSync } from 'node:fs'
import { expect, test } from 'vitest'

function generatedConfig(value: string) {
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e',
    "import('./scripts/build-vercel.mjs').then(({buildOutputConfig}) => console.log(JSON.stringify(buildOutputConfig(process.env.WEBSCOPE_API_ORIGIN))))"],
  { env: { ...process.env, WEBSCOPE_API_ORIGIN: value } }).toString())
}

test('project import uses static configuration with no unresolved rewrite destinations or environment', () => {
  const config = JSON.parse(readFileSync('vercel.json', 'utf8'))
  expect(config.framework).toBeNull()
  expect(config.buildCommand).toBe('npm run build:vercel')
  expect(config.outputDirectory).toBeNull()
  expect(config).not.toHaveProperty('rewrites')
  expect(JSON.stringify(config)).not.toContain('WEBSCOPE_API_ORIGIN')
  expect(existsSync('vercel.mjs')).toBe(false)
})

test('build output resolves the API origin only during the build and preserves route ordering', () => {
  const config = generatedConfig('https://webscope-api.onrender.com/')
  expect(config.version).toBe(3)
  expect(config.routes[0]).toMatchObject({ continue: true, headers: { 'X-Content-Type-Options': 'nosniff' } })
  expect(config.routes[1]).toMatchObject({ src: '/api/(.*)', dest: 'https://webscope-api.onrender.com/api/$1' })
  expect(config.routes[1].headers['Cache-Control']).toContain('no-store')
  expect(config.routes[2].dest).toBe('https://webscope-api.onrender.com/openapi.json')
  expect(config.routes[3]).toEqual({ handle: 'filesystem' })
  expect(config.routes[4]).toEqual({ src: '/assets/(.*)', status: 404 })
  expect(config.routes.at(-1).dest).toBe('/index.html')
})

test('different deployment origins generate different concrete routes without placeholders', () => {
  const config = generatedConfig('https://other-api.example')
  expect(config.routes[1].dest).toBe('https://other-api.example/api/$1')
  expect(JSON.stringify(config)).not.toContain('undefined')
})

test.each(['', 'http://api.example', 'https://api.example/path', 'https://user:pass@api.example',
  'https://api.example?query=1', 'https://api.example#fragment', 'https://api.example:8443',
  ' https://api.example', 'not a URL'])(
  'deployment build fails before emitting routes for invalid API origin %s', value => {
    const result = spawnSync(process.execPath, ['scripts/build-vercel.mjs'],
      { env: { ...process.env, WEBSCOPE_API_ORIGIN: value } })
    expect(result.status).not.toBe(0)
    expect(result.stderr.toString()).toContain('WEBSCOPE_API_ORIGIN')
    expect(result.stdout.toString()).not.toContain('vite')
  },
)
