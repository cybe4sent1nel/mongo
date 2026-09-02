# Next.js 16.3.4 — Flight argument decoder (`decodeReply`) deep dive

Scope: the Server Action **argument** deserializer — the part of the RSC Flight protocol that
React2Shell (CVE-2025-55182) actually abused. Target `next@16.3.4`, vendored
`react-server-dom-webpack-server.node.production.js`.

**Outcome: no RCE, and no prototype pollution. I did not find an exploitable bug here.** One
genuine code defect was found (a security guard testing the wrong variable) but it is provably
unreachable, so it is a hardening report to React, not a vulnerability. Details below, including
the two places my own testing produced misleading results.

## What the decoder actually exposes

`parseModelString` (`:3218-3460`) is the token dispatch for every `$`-prefixed value. I read
every case. The security-relevant conclusions:

* **No `eval` anywhere on the server decode path**, and no `Symbol.for` case. (`$S` here is
  `Int16Array`, not a symbol constructor — worth stating because the *client* Flight decoder does
  have symbol handling, and conflating the two is an easy mistake.)
* The only cases that reach code loading are `$h` → `loadServerReference$1` (`:2538`) and
  `$F`/`decodeBoundActionMetaData`. Both resolve through `response._bundlerConfig`, which in
  Next.js is the hardened module-map Proxy — so the argument path is gated exactly like the
  action-ID path.
* Everything else is data construction: typed arrays from Blobs, `Map`/`Set`/`FormData`/`Date`/
  `BigInt` (length-capped at 300 digits), readable streams, async iterables.

## Why `resolveServerReference`'s `#` fallback is unreachable

React's `resolveServerReference` (`:2303`) has two latent hazards — a raw `bundlerConfig[id]`
lookup with no `hasOwnProperty` guard, and a `#`-suffix fallback that makes the **export name**
attacker-controlled, feeding `requireModule`'s `moduleExports[metadata[2]]`.

Next.js's `createServerModuleMap()` (`server/app-render/manifests-singleton.ts`) closes it:

```ts
return new Proxy(Object.create(null) as ServerModuleMap, {
  get: (target, id, receiver) => {
    if (typeof id !== 'string') return Reflect.get(target, id, receiver)
    if (wellKnownProperties.has(id)) return Reflect.get(target, id, receiver)
    if (!mightBeServerReferenceId(id)) throw getInvalidServerReferenceIdError(id)
    const workers = getServerActionsManifest()[…]?.[id]?.workers
    if (!workers) throw getActionNotFoundError(id)
    …
    if (!workerEntry) throw getActionNotFoundError(id)
    return { id: moduleId, name: id, chunks: [], async }
  },
})
```

The decisive property is that **every miss throws** — the map can never return a falsy value for
a string id. React only reaches the `#` branch when `bundlerConfig[id]` is falsy, so that branch
is dead in Next.js.

I also checked the obvious way to force a falsy return: a *valid* action ID belonging to a
different page. `if (!workerEntry) throw` covers it. And the `#` split cannot help, because
`mightBeServerReferenceId` is an **exact length** test — the pre-`#` prefix is always shorter
than the full id, so the second lookup throws even if the first somehow did not.

The returned `name` is the attacker's id string, but it must equal a manifest key to have gotten
that far, and Next.js compiles actions so the module export name *is* the action id. `"*"` and
`""` (the two special `requireModule` names that would return the whole module namespace) both
fail the length gate.

## Prototype pollution — 14 payloads, all clean

`poc/t_flight_pollute.mjs`, driving the real `decodeReply` with `--conditions=react-server` and
`NODE_ENV=production` (the production bundle is what ships; the dev bundle refuses to load
without the condition and is not the shipped artifact).

`__proto__` targeted at every value-token shape (`$o` Uint8Array, `$A` ArrayBuffer, `$V` DataView,
`$Q` Map, `$W` Set, `$D` Date, outlined model, plain object), nested one and two levels deep,
inside an array element, plus `constructor` / `constructor.prototype` variants and an outlined
model whose own root carries `__proto__`. Every `Object.prototype` sentinel stayed clean.

The effective guard is in `reviveModel` (`:2666-2670`), which **deletes** the key before any
value handler runs:

```js
for (childContext in value)
  hasOwnProperty.call(value, childContext) &&
    ("__proto__" === childContext
      ? delete value[childContext]
      : (… reviveModel(response, value, childContext, …)))
```

## The real defect: a guard testing the wrong variable (unreachable)

`parseTypedArray` (`:2969`) is declared
`(response, reference, constructor, bytesPerElement, parentObject, parentKey, referenceArrayRoot)`
and then does:

```js
var key = response._prefix + reference;   // local `key` = the FormData field name, e.g. "1_5"
…
"__proto__" !== key && (parentObject[parentKey] = resolvedValue);   // :3020
```

The guard tests `key`, but the assignment writes `parentKey`. `key` is always
`<prefix><hex>` and can never be `"__proto__"`, so the guard is inert. Compare the same guard
written correctly in `resolveReference` (`:2823`) and in `loadServerReference$1` (`:2555`):

```js
"__proto__" !== key && (parentObject[key] = resolvedValue);
```

**This is not exploitable**, because `reviveModel` deletes `__proto__` keys before
`parseTypedArray` can ever be called with `parentKey === "__proto__"`. It is dead
defence-in-depth — the kind of thing that becomes live the moment the upstream `delete` is
refactored. Worth an upstream fix in React; not a vulnerability report, and I am not filing it
as one.

## Two places my own testing misled me — recorded so the negatives are trustworthy

1. **A false positive I nearly reported.** My battery flagged
   `[[{"__proto__":"$o1"}]]` as `*** PROTOTYPE REPLACED ***`. It was my check, not the decoder:
   the root of that payload is an **array**, and `Object.getPrototypeOf([]) === Array.prototype`,
   which is trivially `!== Object.prototype`. Re-tested directly: the inner object's own keys are
   `[]` and its prototype is `Object.prototype`. Nothing was replaced.
2. **A false negative shape.** The first `__proto__` run showed "no effect", which on its own
   proves nothing — it could equally mean the payload never reached the typed-array path. The
   `benign` control (`[{"benign":"$o1"}]` → own keys `["benign"]`) is what makes the negative
   mean something: the path was live and the `__proto__` variant specifically was stripped.

## Still not covered

* **Server Action CSRF** — `Origin`/`Host` comparison and `allowedOrigins` matching. Not touched
  in this pass; a bypass there is High on its own and is the most promising remaining lead.
* `decodeFormState` / `$K` FormData reconstruction under adversarial field-prefix collisions.
* `parseReadableStream` / `parseAsyncIterable` resource-exhaustion behaviour (the `arraySizeLimit`
  is `1e6` by default — a DoS question, not RCE, and out of the requested scope).
* Windows-only path semantics, which cannot be tested from this container.
