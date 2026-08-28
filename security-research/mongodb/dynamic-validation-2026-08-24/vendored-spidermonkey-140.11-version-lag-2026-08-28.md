# MongoDB 8.3.8 — vendored SpiderMonkey/MozJS version: corrected assessment and version-lag check

**Status: version confirmed precisely; lags two Firefox ESR security point-releases; JS-engine
reachability of the specific fixed CVEs could not be confirmed from public sources (Mozilla's
detailed bug-tracker pages are blocked by this environment's egress policy).** Recorded honestly —
this is weaker evidence than the ICU finding, not oversold.

## Correcting an initial assumption

A source comment in `src/mongo/scripting/mozjs/shell/mongohelpers.js` reads "Starting in MozJS
ESR128, the column numbers returned by the engine are..." — read in isolation, this looked like it
might mark the *currently vendored* version. It doesn't; it's just noting when a behavior changed.
The actual vendored version, confirmed from real commit history reachable from the exact `r8.3.8`
commit under test (`d100bf19961251f273e1d0bd8ce66fc60634f53c`, fetched to depth 3000):

```
7cb8c053d SERVER-126162 [v8.3] MozJS ESR 140.11.0 upgrade (#55309)
ccc647816 SERVER-126049: Use thread-local counter for mozjs mmap allocations (8.3) (#53544)
d82eb1aae SERVER-124958 Surface OOM during JavaScript scope creation as a clean error (#52597)
97d228f70 SERVER-120450 [v8.3] Upgrade MozJS to 140.9 (#50703) (#51098)
28d4e3cc1 SERVER-117317 Upgrade MozJS to esr 140.7 (#46920)
```

`7cb8c053d` (140.11.0) is the most recent mozjs-touching commit in this history — i.e. **ESR
140.11.0** is what `r8.3.8` actually ships, a comparatively current version (Firefox ESR 140 shipped
in mid-2025), not the decade-old situation found with ICU.

## Version-lag check against Mozilla's own security advisories

Two Firefox ESR releases after 140.11 carry their own security advisories:
- **Firefox ESR 140.12** (MFSA 2026-58): fixes bugs "present in Firefox ESR 140.11" — i.e. present
  in MongoDB's exact vendored version.
- **Firefox ESR 140.13** (MFSA 2026-70): fixes bugs "present in Firefox ESR 140.12" (including
  CVE-2026-16412, CVSS 9.8 critical, a generic "memory safety bugs...presumed exploitable" entry).

So MongoDB's vendored SpiderMonkey is at minimum two security-point-releases behind as of this
session. The four **individually named** CVEs in the 140.12 advisory (MFSA 2026-58) were confirmed
via public advisory summaries:
- CVE-2026-12291: use-after-free, **Networking: HTTP**
- CVE-2026-12292: incorrect boundary conditions, **Web Audio**
- CVE-2026-12295: sandbox escape, **DOM: Navigation**
- CVE-2026-12296: sandbox escape, **Security: Process Sandboxing**

**All four are browser-subsystem bugs — none are in the JS engine (`js/src`) that MongoDB actually
vendors.** MongoDB's `third_party/mozjs` embedding is JS-engine-only (extracted via its own
`extract.sh`/`get-sources.sh` pipeline); it does not compile Firefox's networking stack, Web Audio,
DOM, or OS-level process-sandboxing code at all, so these four are confirmed **not applicable**
regardless of version lag.

The remaining catch-all "memory safety bugs" CVE in the same advisory (and the CVE-2026-16412 entry
in 140.13's advisory) is Mozilla's standard generic bucket, which routinely *does* include `js/src`
fixes across Firefox's history in general — but Mozilla deliberately does not publish per-bug
component detail for these entries until long after the advisory (specifically to prevent exactly
this kind of "match a public disclosure to exploit code" analysis). Both `mozilla.org` and
`bugzilla.mozilla.org` are blocked by this session's egress policy (`EGRESS_BLOCKED`), and no
secondary source found via web search breaks the generic bucket down by component. **Whether any of
the underlying bugs touch the JS-engine subset MongoDB vendors is therefore unconfirmed — neither
ruled in nor ruled out.**

## Assessment

This is real, verifiable version-lag information (MongoDB is 2 ESR security releases behind), but
weaker than the ICU 57.1 finding in every way that matters for a report: the four specifically-named
CVEs in the immediately-following release are confirmed not applicable (wrong subsystem entirely,
not just "probably safe"), and the one remaining possibly-relevant bucket can't be pinned to the
vendored component without access this environment doesn't have. Recording this honestly as
"version gap confirmed, exploitability unconfirmed" rather than extrapolating a "critical JS engine
CVE" claim from a CVSS score that belongs to a bucket covering dozens of unrelated bugs across the
whole browser codebase.

## Reachability, for context if a specific bug were ever confirmed

MongoDB's SpiderMonkey embedding is reachable via server-side JS: `$where`, `mapReduce`, and stored
`db.system.js` functions (a legacy, generally-discouraged-by-MongoDB's-own-docs feature set, but not
disabled by default in `mongod` itself). Any confirmed JS-engine memory-safety bug in the vendored
version would be reachable by any user able to issue an aggregation/query using these operators —
worth revisiting if a future pass can get authoritative bug-component data.
