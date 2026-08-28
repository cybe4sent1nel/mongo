# MongoDB 8.3.8 — Ghidra-MCP binary analysis pass (2026-08-28)

**Status: infrastructure stood up and confirmed working; two candidate leads found via
binary-level dangerous-import analysis, both triaged closed (intentional, documented, already
out of MongoDB's own threat model).**

## Infrastructure

Cloned `bethington/ghidra-mcp` and built it natively (no Docker — faster given Java 21/Maven were
already present): downloaded Ghidra 12.1.2 (official NSA release, 573MB, reachable through this
session's egress policy unlike fastdl.mongodb.org/Docker Hub's CDN), installed its JARs into the
local Maven repo per the project's own Dockerfile recipe, built the `headless` Maven profile
(`GhidraMCP-7.0.0.jar`), and ran the resulting headless REST server natively against the real
8.3.8 `mongod` binary (`gitVersion 35e8c8a57f78157ed9fac1a9e90ee6c1818adab6`, the same binary used
throughout this program). Confirmed working end-to-end: `/check_connection`,
`/get_current_program_info` (190,359 functions, 353,884 symbols resolved straight from the ELF
`.symtab` — the binary ships **not stripped**), `/decompile_function`, `/list_imports`,
`/search_functions`, `/get_xrefs_to` all verified functional against the live program.

## Method: dangerous-import call-site sweep

Rather than waiting on Ghidra's full heuristic auto-analysis pass (which, kicked off via
`/run_analysis`, is still running in the background against a 190k-function/168MB binary — xref
data depends on it, decompilation of individually-named functions does not), used the binary's own
retained symbol table directly: `nm`/`objdump` to enumerate every `call` site to classically
dangerous libc functions (`strcpy`, `sprintf`, `strcat`, `memcpy`, `popen`, `execl`), then mapped
each call site to its enclosing function name to separate MongoDB's own code from vendored
third-party libraries compiled into the same binary.

**Result:** all `strcpy`/`sprintf`/`strcat` call sites resolve to vendored third-party libraries
(ICU, SpiderMonkey/mozilla JS engine, libunwind, protobuf/upb) — out of scope for a MongoDB-specific
finding and not something a quick binary sweep can responsibly flag without deep expertise in those
libraries' own (separately-maintained, separately-audited) codebases. `memcpy` (33,772 call sites)
is too common to be a meaningful signal on its own. Two call sites, however, are MongoDB's own code:

### 1. `mongo::shellExec` → `popen` — closed, not network-reachable

All three call sites are config-file/CLI-tool-only: `options_parser.cpp`'s `__exec`-style config
expansion (reachable only by whoever already controls the config file on disk — a local,
already-privileged actor, not a network attacker), `golden_test.cpp` (unit test framework), and
`query_tester/file_helpers.cpp` (a standalone developer CLI tool, not part of `mongod`'s command
dispatch). None reachable via the wire protocol.

### 2. `SysProfile` command → `execl("/usr/bin/perf", ...)` — closed, explicitly intentional by design

`src/mongo/db/commands/sysprofile.cpp` implements a `sysprofile` command whose
`doCheckAuthorization()` is a literal no-op (`const final {}`) — no privilege check of any kind.
Two real primitives exist in the code as written: `{sysprofile: 1, pid: <N>}` calls
`kill(N, SIGINT)` on a caller-supplied PID with **no verification that N is actually a profiler
child this caller (or even this command) spawned** — an arbitrary-process-signal primitive scoped
to whatever the mongod process's UID can signal; and `{sysprofile: 1, filename: <path>, mode:
"record"}` passes the filename unsanitized as `perf record`'s `-o` argument — a path-traversal-style
arbitrary-file-write-location primitive (content is genuine `perf` profile data, but the path is
fully attacker-chosen).

Both are real as code, but **not a submittable finding**: `sysprofile.idl` documents the missing
check explicitly — `access_check: none: true # No auth needed because it only works when enabled
via command line` — and the command is registered `.testOnly()`, meaning it doesn't even exist
unless the deployment was started with `--setParameter enableTestCommands=1`, a flag MongoDB's own
documentation says must never be set in production. This is the same accepted-risk shape already
established in this program for `configureFailPoint`/`waitForFailPoint` (used in the resolved
prepared-txn lead) — `testOnly()`-gated commands are outside MongoDB's own threat model by design,
and this one says so in its own source comment.

## Binary-level confirmation of the existing Critical finding

Decompiled `mongo::doc_diff::(anonymous namespace)::DiffApplier::applyDiffToArray` (the pad loop
behind the `$_internalApplyOplogUpdate` concurrent-OOM Critical finding) directly. The compiled
loop bound comparison (`uVar17 < uVar5`, both full 64-bit unsigned values) matches the source-level
mechanism exactly — no compiler-introduced truncation, no optimization silently removed or altered
the pad loop's behavior. This was a confirmation pass (verifying the compiled binary matches source
reasoning), not a new discovery, but a worthwhile sanity check now that the tooling exists to do it
directly.

## Net result

Ghidra-MCP is fully operational against the real 8.3.8 binary and available for further targeted
use (specific function decompilation works now; the full auto-analysis pass needed for
program-wide `/get_xrefs_to` sweeps was still running in the background at the time of writing).
No new submittable high/critical bug found via this pass's dangerous-import sweep — both leads
resolve to intentional, already-documented, already-accepted-risk design, consistent with this
program's established pattern of honestly closing well-triaged negatives rather than overselling a
raw code pattern as a vulnerability.

## Candidates for a follow-up pass with this infrastructure now in place

- Let the in-progress full auto-analysis complete, then do a broader `/get_xrefs_to` sweep across
  every `memcpy`/`memmove` call site *within MongoDB's own code* (excluding vendored libraries) for
  a size-mismatch pattern (fixed-size stack buffer target, attacker-influenced length source).
- Binary-diff this exact 8.3.8 build against a different minor version (e.g. 8.3.9 or the next
  patch release once available) using Ghidra's version-tracking/diffing features — a classic
  technique for surfacing silently-patched security fixes that never got a public SERVER-ticket
  writeup, distinct from anything a source-level `git log` sweep alone can find (a source diff
  needs to know which commit fixed something; a binary diff finds behavioral changes even when the
  fixing commit's message doesn't say "security").
