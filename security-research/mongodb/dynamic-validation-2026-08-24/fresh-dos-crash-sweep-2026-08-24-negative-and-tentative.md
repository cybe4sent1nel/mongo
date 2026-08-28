> **Recovery note (2026-08-28):** reconstructed verbatim after the working container was recycled
> before a successful push. Content unchanged from the original.

# MongoDB 8.3.8 — fresh DoS/crash hunting pass, live-tested (2026-08-24, continued)

**Target:** same official `8.3.8` binary as the rest of this directory, standalone, fresh instance
per test. All tests below were run live against a real `mongod` process (not static reasoning) —
following up on the two confirmed findings in this directory
(`bsoncolumn-rle-decompression-bomb/`, `internal-apply-oplog-update-oom-crash/`), this pass swept
several more concrete crash/DoS hypotheses. Recorded honestly regardless of outcome, per this
program's standing "verify before claiming" discipline.

## Ruled out (properly guarded — confirmed live, not assumed)

- **Ordinary `$set` on a huge array positional index** (`db.t.update_one({}, {$set:
  {"arr.999999999": 1}})`) — the *user-facing* update path is properly capped: rejected instantly
  with `"can't backfill more than 1500000 elements"` (code 34). This is the same shape of bug as
  the confirmed `$_internalApplyOplogUpdate` finding, but the ordinary update operator path has an
  explicit bound that the internal oplog-diff-replay path lacks — confirms the vulnerability is
  specific to the internal stage, not a broader defect in MongoDB's update-array-padding logic.
- **Multi-field single-request amplification bypass** — hypothesized that naming several huge
  array indices across multiple fields in *one* `$_internalApplyOplogUpdate` diff might allocate
  N × 125MB in a single request (each field getting its own `BufBuilder`), bypassing the need for
  concurrency. Tested with 20 fields: peak RSS only ~140MB above baseline — the request fails fast
  on the *first* field to exceed the cap, aborting before any other field is processed. Confirms
  the concurrency angle (already documented) is the only way to turn this into a crash.
- **Deep diff-object nesting → stack overflow** — hypothesized the diff applier's mutual recursion
  (`applyDiffToObject`/`applyDiffToArray`) could be driven to stack-exhaustion via a deeply nested
  diff. Tested depths 50/190/200/500/5000: BSON's standard nested-object depth limit (200) rejects
  anything at or past that depth with a clean `"BSONObj exceeds maximum nested object depth"`
  error *before* the diff applier's own recursion ever runs. Closed.
- **Regex ReDoS** (`{$regex: "^(a+)+$"}` against a 41-char adversarial string) — resolved in ~5ms,
  no observable backtracking blowup. Not chased further at larger scale given the instant result.
- **Date arithmetic extreme values** (`$dateAdd`/`$dateSubtract`/`$dateDiff`/`$dateTrunc` with
  amounts up to ~10^12 and int64-boundary millisecond values) — every case either cleanly rejected
  with a specific validation error or returned a correct (if large) result. No crash, no uncaught
  exception. Consistent with the earlier, already-completed audit of this operator family.
- **`$graphLookup` deep-chain traversal** (50,000-node linked chain, no `maxDepth` specified) —
  completed in ~10s with the correct full-chain result, no stack overflow. Confirms an iterative
  (not naively recursive) implementation — chain depth alone isn't a crash vector, only a
  proportional-cost one (and the cost is proportional to data the caller already wrote themselves,
  not an amplification).

## Tentative / unresolved — flagged honestly, not claimed as a qualifying vulnerability

**Nested, uncorrelated `$lookup` pipelines show apparent quadratic-per-depth-level CPU cost with
no time-based or count-based safeguard, only a *result-size* safeguard that a carefully-shaped
query can avoid.**

Reproduction: a trivial `pipeline`-form `$lookup` (no `localField`/`foreignField`, so each level
runs uncorrelated to the outer document) nested inside another, against a collection of `N`
`{_id: i}` documents, innermost stage `{$limit: 1}` so no intermediate array ever grows large:

```js
db.a.aggregate([
  { $lookup: { from: "a", pipeline: [
    { $lookup: { from: "a", pipeline: [ { $limit: 1 } ], as: "sub" } }
  ], as: "sub" } }
])
```

Measured wall time (single connection, no concurrency): **N=1000 → 10.4s; N=2000 → 42.5s** — a
~4x cost increase for a 2x increase in N, consistent with quadratic (`O(N^2)`) scaling at this
depth, entirely from a collection any ordinary `find`/`aggregate`-privileged user can populate and
query themselves. One level deeper (depth 3) hit a different, pre-existing guard first (`"Total
size of documents in a matching pipeline's $lookup stage exceeds..."`) in this specific
construction — but that guard bounds *accumulated result size*, not *invocation count* or *CPU
time*, and this test's own innermost `{$limit: 1}` stage was specifically chosen to keep results
tiny, so the guard's trigger at depth 3 looks incidental to this particular shape rather than a
deliberate defense against the underlying re-execution-count blowup.

**Why this is flagged as tentative rather than a finding:** MongoDB, like every general-purpose
query engine, does not impose a default CPU-time budget on a client's own query (`maxTimeMS` is
opt-in, set by the caller, not enforced server-side by default), and "you can write an expensive
query" is not itself typically treated as a vulnerability in any database — including by MongoDB's
own security program, which has closed similar-shaped reports as "expected query-cost behavior."
What makes this worth flagging rather than dismissing outright: the *request* needed to produce
this cost is trivial (a few hundred bytes, no special skill, no need to understand this pattern's
cost implications — this isn't an "obviously expensive query" a query-cost-aware developer would
avoid, it looks structurally innocuous), and the resulting CPU consumption is not bounded by
anything but the size guard, which this construction can plausibly dodge while continuing to scale
with `N^depth`. This is genuinely uncertain territory — recorded here as a data point for a future
pass (ideally with a build/debugger available to inspect whether `$lookup`'s "cacheable if
uncorrelated" optimization is supposed to apply here and isn't, which would reframe this as an
optimization regression rather than a missing safeguard) rather than written up as a standalone
Critical/High finding without a build environment to confirm root cause.

## Net result of this pass

No new crash bug confirmed. Several concrete hypotheses tested and closed with real evidence
(good — these are genuine defenses working as intended, not gaps). One CPU-cost data point
recorded honestly as unresolved rather than inflated into a claim this session can't fully back.
The two confirmed Critical findings elsewhere in this directory
(`bsoncolumn-rle-decompression-bomb/`, `internal-apply-oplog-update-oom-crash/`) remain this
program's validated output for MongoDB 8.3.8 crash/DoS bugs to date.
