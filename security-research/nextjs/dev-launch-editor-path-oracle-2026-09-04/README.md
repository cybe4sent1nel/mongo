# Next.js `next dev` — `/__nextjs_launch-editor` has no path containment: cross-site arbitrary-file-existence oracle and forced editor-open on any absolute path

**Component** `packages/next/src/next-devtools/server/launch-editor.ts` (`openFileInEditor`), reached from
`packages/next/src/server/dev/middleware-turbopack.ts` and `packages/next/src/server/dev/middleware-webpack.ts` (`/__nextjs_launch-editor`)
**Target** `next@16.3.4` (`299180d331`), `next dev` — **both** the Turbopack and Webpack dev servers
**Class** CWE-22 (path traversal / improper limitation of a pathname to a restricted directory) + CWE-352 (CSRF), yielding CWE-203 (observable discrepancy) as a cross-origin filesystem oracle
**Status** Reproduced end to end against real headless Chromium from a genuinely cross-site origin. 9/9 probed paths correctly resolved against ground truth; a 63-probe zero-knowledge recon chain recovered the developer's username, project root, and secret-file inventory.

## Summary

`/__nextjs_launch-editor` exists so the dev-overlay's "open in editor" button can hand a file path to the developer's editor. Its path handling is:

```ts
export async function openFileInEditor(file, line1, column1, nextRootDirectory) {
  let filePath: string
  if (file.startsWith('file://')) {
    filePath = fileURLToPath(file)          // any absolute path
  } else if (path.isAbsolute(file)) {
    filePath = file                          // any absolute path
  } else {
    filePath = path.join(nextRootDirectory, file)   // `../` escapes the root
  }
  // <- no check that filePath is inside nextRootDirectory
  const existed = await fsp.access(filePath, fs.constants.F_OK) ...
  if (existed) { launchEditor(filePath, line1, column1) }
}
```

There is **no containment check of any kind**. `file` comes straight from the query string, and all three branches are attacker-reachable. The handler's own "safer" branch is not safer either: `isAppRelativePath=1` builds `path.join(isSrcDir ? 'src' : '', 'app', relativeFilePath)`, which `../../../..` walks straight out of.

Two consequences follow, and both are reachable **cross-site, with no interaction beyond loading a page**:

1. The endpoint answers **204 when the path exists on the developer's disk and 404 when it does not** — an arbitrary-filesystem existence oracle for absolute paths anywhere on the machine.
2. When the path exists, it **spawns the developer's configured editor on it**.

### Why the Same-Origin Policy does not contain the oracle

The attacker never needs to read the response. A browser does **not** navigate a frame on a `204 No Content`, but does on a `404`. So point an iframe at an attacker-origin document, then set `src` to the probe URL:

* path **exists** → 204 → no navigation → the frame still holds the attacker's *own same-origin* document → `iframe.contentWindow.document` reads fine;
* path **missing** → 404 → the frame navigates to the victim origin → the same read throws `SecurityError`.

That is a deterministic, timing-free binary read of the victim's filesystem. `poc/oracle.html` is 40 lines and does exactly this.

### Reachability: the CSRF gate does not stop it

`/__nextjs_launch-editor` is gated by `blockCrossSiteDEV()`, the same control covered in `../dev-csrf-inspector-rce-2026-09-04`. A cross-site **navigation** (an `<iframe src>`) carries no `Origin` header, and `blockCrossSiteDEV` returns "not blocked" for an absent `Origin` — so every probe here sails through. The two findings are independent (this one is a missing containment check in file handling; that one is the CSRF gap) but they compose: the CSRF gap is what makes this endpoint reachable from `attacker.test` at all.

## Reproduction

```
# victim: a developer running `next dev` on victimdev.test:3020
# attacker: an ordinary web page on attacker.test:8899

node poc/drive_oracle.js   # existence oracle, checked against fs.existsSync ground truth
node poc/drive_recon.js    # zero-knowledge walk: OS -> username -> project root -> secrets
```

Direct HTTP behaviour, showing the endpoint accepts anything (`poc/evidence_run.txt` §1):

```
absolute path, EXISTS      /etc/passwd                     -> 204
absolute path, MISSING     /etc/nope-xyz                   -> 404
file:// URL,  EXISTS       /etc/hostname                   -> 204
isAppRelativePath=1 traversal out of app/ EXISTS           -> 204
isAppRelativePath=1 traversal out of app/ MISSING          -> 404
```

Cross-site oracle from real Chromium (§3) — every answer checked against `fs.existsSync` on the victim host:

```
  /etc/passwd                       EXISTS   MATCH
  /home/user/nextlab/package.json   EXISTS   MATCH
  /home/user/nextlab/.env.secret    EXISTS   MATCH
  /home/user/nextlab/.env.production  missing  MATCH
  /root/.ssh/id_ed25519               missing  MATCH
  ... 9/9 paths correctly determined cross-site.
```

Forced editor spawn (§4) — the dev server was started with `REACT_EDITOR` pointing at a recorder script standing in for the developer's real editor. After **one hidden cross-site iframe** and nothing else:

```
01:38:51 spawned with argv: [/home/user/nextlab/.env.secret]
```

Zero-knowledge recon chain (§5), 63 cross-site probes, no response body ever read:

```
STEP 1  platform fingerprint     /etc/passwd  /home  /proc/version  /etc/debian_version
STEP 2  home directories         /home/user  /home/ubuntu
STEP 3  project checkout         /home/user/nextlab
STEP 4  secrets in the project   .env.local  .env.secret  next.config.js  middleware.js
STEP 5  credentials in $HOME     (none on this host)
```

## Impact

An attacker-controlled webpage, loaded in any browser on a machine currently running `next dev`, can:

* **Determine the existence of any absolute path on the developer's filesystem**, reliably and at will — enumerating home directories and usernames, locating the project checkout, and inventorying which secret files are present (`.env.local`, `.env.secret`, `.git/config`, `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.kube/config`). File *presence* is itself sensitive: it fingerprints the host, names the developer, maps the source tree, and tells an attacker precisely which follow-up primitive is worth spending.
* **Force the developer's editor to open an arbitrary file** on their machine. At minimum this is disruptive and a convincing phishing/social-engineering surface; the security weight depends on which editor is configured and what that editor does on open, which I did not attempt to enumerate and do not claim.

This is squarely the threat model `blockCrossSiteDEV` and `allowedDevOrigins` were built for: developers run `next dev` for hours while browsing the web in the same browser.

## What I checked and could *not* turn into more, stated plainly

I would rather bound this precisely than round it up.

* **No command injection.** On Linux the chain ends in `child_process.spawn(editor, args)` with **no shell**, so the filename is an inert argv element. The macOS terminal-editor branch does build a shell string for `osascript ... do script`, but it is correctly layered — `shellQuote.quote([...])` then `escapeApplescriptStringFragment` escaping `\` and `"` — and I found no way through it. Windows spawns via `cmd.exe` but is guarded by `WINDOWS_FILE_NAME_ACCESS_LIST`, whose own comment cites exactly this risk. **That Windows guard is the only path-content validation in the function, and there is no Linux/macOS equivalent** — which is what leaves the traversal itself unaddressed even though injection is not reachable.
* **No argument injection.** `file=--goto`, `--wait`, `-c:!id` all 404: a leading-dash name is not absolute, so `path.join(projectPath, name)` turns it into `/home/user/nextlab/--goto`, which does not exist (`poc/evidence_run.txt` §2). Nothing attacker-controlled reaches argv as a flag.
* **No file-content read.** The response is 204/404 with no body. I checked the two neighbouring endpoints that *do* return source text — `/__nextjs_source-map` returned 204 for arbitrary absolute paths and `file://` URLs (no source map to serve), and `/__nextjs_original-stack-frames` is POST-with-JSON-body, which a cross-site page cannot forge (cross-site POST navigations *do* carry `Origin` and are correctly rejected — verified in the companion report). So this is an existence oracle, not an arbitrary file read.

## Scope

* **`next dev` only**, but **both bundlers**: `getOverlayMiddleware` is registered from `hot-reloader-turbopack.ts:1148` and `hot-reloader-webpack.ts:1650`, and both `middleware-turbopack.ts` and `middleware-webpack.ts` pass `searchParams.get('file')` through unvalidated. Production (`next start`, `output: standalone`) does not register the endpoint.
* Fixing this is a containment check: resolve `filePath` and require it to stay within `nextRootDirectory` before the `fs.access` probe — which also removes the oracle, since the 204/404 discrepancy would then only ever describe files inside the project the overlay is already allowed to open.

## Files

| file | what it is |
|---|---|
| `poc/oracle.html` | the attacker page: deterministic 204-vs-404 existence oracle built on the SOP boundary itself |
| `poc/blank.html` | attacker-origin document the probe frame starts on |
| `poc/drive_oracle.js` | drives the oracle in real headless Chromium and checks every answer against `fs.existsSync` ground truth |
| `poc/drive_recon.js` | the 63-probe zero-knowledge chain: OS → username → project root → secret inventory |
| `poc/fake_editor.sh` | recorder standing in for the developer's editor, logging exactly what Next.js spawned it with |
| `poc/evidence_run.txt` | full annotated run: direct HTTP behaviour, the argv-injection negative, the cross-site oracle, the forced spawn, the recon chain |

## Lab

`next@16.3.4`, Node v22.22.2, `next dev` on port 3020. Chromium 1194 (Playwright), headless. `/etc/hosts` maps `attacker.test` and `victimdev.test` to `127.0.0.1` so Chromium treats them as genuinely cross-site — same-IP-different-port is *not* sufficient, since the browser's site boundary is host-based and `blockCrossSiteDEV` always-allows `127.0.0.1`/`localhost`. `REACT_EDITOR` pointed at `poc/fake_editor.sh` for the spawn evidence; the oracle half needs no editor configured at all.
