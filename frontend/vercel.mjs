const value = process.env.WEBSCOPE_API_ORIGIN
if (!value) throw new Error('Set WEBSCOPE_API_ORIGIN to the HTTPS Render API origin before deploying.')
const upstream = new URL(value)
if (upstream.protocol !== 'https:' || upstream.username || upstream.password || upstream.search ||
    upstream.hash || upstream.pathname !== '/' || upstream.port) {
  throw new Error('WEBSCOPE_API_ORIGIN must be an HTTPS origin without a path, port, query or credentials.')
}

export const config = {
  framework: 'vite',
  installCommand: 'npm ci',
  buildCommand: 'npm run build',
  outputDirectory: 'dist',
  rewrites: [
    { source: '/api/:path*', destination: `${upstream.origin}/api/:path*` },
    { source: '/openapi.json', destination: `${upstream.origin}/openapi.json` },
    { source: '/:path*', destination: '/index.html' },
  ],
  headers: [
    {
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" },
      ],
    },
    { source: '/api/:path*', headers: [{ key: 'Cache-Control', value: 'private, no-store, max-age=0' }] },
  ],
}
