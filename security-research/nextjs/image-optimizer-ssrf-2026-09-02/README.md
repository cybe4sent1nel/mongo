# Next.js 16.3.4 — image optimizer SSRF audit

Audit started from the two recent advisories the engagement pointed at, hunting siblings:

* **GHSA-p293-qw3h-jr36 / CVE-2026-75604** — unauthenticated RCE on Windows hosts, path
  traversal. Root cause per the `v16.3.2..v16.3.3` patch: `escape-path-delimiters.ts` escaped
  `/ # ?` but not `\`, and `FileSystemCache.getFilePath()` did `path.join(root, key)` with no
  containment check.
* **GHSA-p9j2-gv94-2wf4 / CVE-2026-64645** — SSRF via `rewrites()` destination hostname. Root
  cause per `v16.2.10..v16.2.11`: `safeCompile(destHostname, { validate: false })` interpolated
  a raw request param into a hostname template; fixed with `encode: encodeURIComponent`.

## Findings

`REPORT.md` — **image optimizer SSRF**, two defects, both reproduced by execution on 16.3.4:

1. The private-IP guard in `fetchExternalImage()` is **TOCTOU**: `dns.lookup()` validates
   addresses, then `fetch()` resolves the hostname independently. A rebinding host passes the
   check and is fetched at `127.0.0.1`.
2. `hasRemoteMatch()` is called **once** (`image-optimizer.ts:442`, on the original URL). The
   redirect loop (`:913-921`) re-applies only the IP guard, so an allowlisted host can redirect
   the fetch to any hostname.

Defect 2 removes Defect 1's precondition. Claimed **High for the chain, Medium for either
alone** — deliberately not rated at parity with CVE-2026-64645, which returns the upstream
response body while this is largely blind.

Also recorded there as an explicit **non-finding**: `getSharp()` re-enabled AVIF decoding in
16.3.4 with the compensating control expressed only as an `optionalDependencies` range, not
enforced at runtime.

## Lab

`next@16.3.4` app (`next build` + `next start` on :3000), Node v22.22.2, all traffic on
loopback:

| piece | file | role |
|---|---|---|
| rebinding resolver | `poc/rebind_dns.py` | first `A` answer public, then `127.0.0.1`; forwards everything else upstream so the container keeps working |
| internal service | `poc/canary.py` | stands in for an internal-only endpoint on `127.0.0.1:80` |
| redirect host | `poc/redir_server.py` | routes by `Host`: `allowed.test` 302s to `notallowed.test` |

Run `poc/poc_image_rebind.sh` and `poc/poc_image_redirect.sh`; their captured output is in the
matching `.txt` files and is quoted verbatim in the report.

Both scripts rewrite `/etc/resolv.conf` and `/etc/hosts` for the duration of the run. The
rebinding script restores `resolv.conf` on exit. Note this sandbox periodically restores
`/etc/resolv.conf` on its own, which produced one confusing intermediate result during the
audit — the responder and the resolver must both be live for the PoC to mean anything, which
is why the script sets both up in a single invocation.

## Negative results

Recorded so the work is not repeated.

* **The Windows-RCE traversal primitive is genuinely fixed.** A dynamic App Router slug still
  becomes an on-disk filename (`.next/server/app/blog/<slug>.html`) — the primitive behind
  CVE-2026-75604 is unchanged — but 33 traversal encodings fired at it
  (`poc/probe_traversal.py`: raw/encoded/double-encoded `../`, `..\`, `%2e%2e`, `%5c`, `%255c`,
  mixed separators, `....//`, `..;/`, overlong UTF-8, `%00`, `C:`, UNC) produced **zero** files
  outside the confined directory. The `startsWith(rootDir + path.sep)` check holds. Payloads do
  survive into filenames (`..%5Cpwned.html`, `C:pwned.html`, and a filename containing a raw
  newline), but none escapes.
* **`isPrivateIp()` is sound.** `ipaddr.js` `range() !== 'unicast'` covers loopback, link-local,
  private, unique-local, CGNAT, reserved and broadcast; IPv4-mapped IPv6 is normalised and IPv6
  brackets stripped (`is-private-ip.ts:3-20`). The bypass is the TOCTOU, not the predicate.
* **Redirects are not blindly followed.** `redirect: 'manual'` plus a bounded `count = 3` and
  re-entry through the IP guard — the redirect handling is deliberate. Its only gap is the
  missing allowlist re-check.

## Not covered

Four parallel static-analysis sweeps (path-traversal sinks, URL/SSRF surface, Server
Actions/RSC, cache poisoning + middleware bypass) were launched and all four died on an API
rate limit before returning anything. Those surfaces remain **unaudited** — in particular
`action-handler.ts` and `manifests-singleton.ts`, which received large changes in the same
16.2.11 release that carried the SSRF fix and are therefore a strong lead.
