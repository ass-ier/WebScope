import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export function buildOutputConfig(value) {
  if (!value) throw new Error('Set WEBSCOPE_API_ORIGIN in Vercel Environment Variables to your HTTPS Render API origin, then redeploy.')
  let upstream
  try { upstream = new URL(value) }
  catch { throw new Error('WEBSCOPE_API_ORIGIN must be a valid HTTPS origin.') }
  if (upstream.protocol !== 'https:' || upstream.username || upstream.password || upstream.search ||
      upstream.hash || upstream.pathname !== '/' || upstream.port || value !== value.trim()) {
    throw new Error('WEBSCOPE_API_ORIGIN must be an HTTPS origin without a path, port, query, credentials or whitespace.')
  }
  return {
    version: 3,
    routes: [
      {
        src: '/(.*)',
        headers: {
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'X-Frame-Options': 'DENY',
          'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        },
        continue: true,
      },
      { src: '/api/(.*)', dest: `${upstream.origin}/api/$1`, headers: { 'Cache-Control': 'private, no-store, max-age=0' } },
      { src: '/openapi\\.json', dest: `${upstream.origin}/openapi.json`, headers: { 'Cache-Control': 'private, no-store, max-age=0' } },
      { handle: 'filesystem' },
      { src: '/assets/(.*)', status: 404 },
      { src: '/(.*)', dest: '/index.html' },
    ],
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = buildOutputConfig(process.env.WEBSCOPE_API_ORIGIN)
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build'], { cwd: root, stdio: 'inherit' })
  const output = resolve(root, '.vercel', 'output')
  rmSync(output, { recursive: true, force: true })
  mkdirSync(output, { recursive: true })
  cpSync(resolve(root, 'dist'), resolve(output, 'static'), { recursive: true })
  writeFileSync(resolve(output, 'config.json'), JSON.stringify(config, null, 2) + '\n')
  console.log('Vercel Build Output API v3 emitted with validated API rewrites.')
}
