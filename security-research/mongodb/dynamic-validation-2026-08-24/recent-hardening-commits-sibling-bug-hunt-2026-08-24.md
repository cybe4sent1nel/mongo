> **Recovery note (2026-08-28):** reconstructed verbatim after the working container was recycled
> before a successful push (the persistent GitHub App 403 authorization gap on
> `cybe4sent1nel/mongo` was never resolved). Content unchanged from the original.

# MongoDB 8.3.8 — mining recent hardening commits for un-fixed siblings (2026-08-24, continued)

**Technique:** the same one that found the confirmed BSONColumn RLE decompression bomb earlier in
this program: read the actual diffs of recent, ancestor-of-`r8.3.8` security/crash-fix commits,
understand precisely what each closed, then hunt for adjacent code with the *same shape* of gap
that the fix didn't reach. All commits below are already ancestors of the `r8.3.8` tag (confirmed
via `git log r8.3.8`) — none of them are directly exploitable on this target; the value here is in
what their *aftermath* does or doesn't still expose.

## Confirms the existing Critical finding is targeting a genuinely incomplete fix

`1d4ba92fb9` (`SERVER-129936`, *"[v8.3] Tighten validation of $idLookup internal fields"*) is the
**exact commit that introduced** the `viewPipeline` guard my confirmed Critical finding
(`../README.md`, `$_internalSearchIdLookup.viewPipeline` → cross-tenant `$merge` write) shows is
bypassable via `db.createView()`'s null-`opCtx` construction. Read in full: this commit also fixed
`src/mongo/s/commands/query_cmd/cluster_pipeline_cmd.h` to pass a **real** `opCtx` into
`LiteParsedPipeline` construction on the direct-`aggregate`-via-mongos path — but did **not** touch
`src/mongo/db/views/view_catalog_helpers.cpp`'s own separate, still-argument-less
`LiteParsedPipeline` construction used by `db.createView()`. This is exactly the residual gap the
existing finding demonstrates live. This was already correctly identified and cited in the earlier
static write-up (`../../mongo-8.3.8-findings.md`, the `SERVER-129936` vendor-timeline row) —
re-confirmed here, not new, but worth restating: the existing finding is not something already
fixed elsewhere: it's the one call site this exact hardening commit missed.

## Six more recent hardening commits examined for siblings — none yielded a fresh bug

- **`58c8bdff08` (`SERVER-130544`, Copilot-Autofix-flagged) — "Enforce internal user for
  commitTransaction/abortTransaction for prepared txn."** Before this fix, any ordinary
  `readWrite` user could directly commit or abort a prepared 2PC participant on an individual
  shard, bypassing the coordinator and breaking cross-shard atomicity (own
  `jstests/sharding/txn_prepared_participant_unauthorized_commit_abort.js` demonstrates the
  pre-fix exploit in full, including racing the coordinator's decision-writing failpoint). Checked
  every other command that can commit/abort/prepare a transaction
  (`PrepareTransactionCmd`, `CoordinateCommitTransactionCmd` in
  `src/mongo/db/s/txn_two_phase_commit_cmds.cpp`) — both already use the same airtight
  `ActionType::internal` cluster-resource check this session has independently verified elsewhere
  rejects even the `root` superuser. No sibling command found lacking the check. **Not dynamically
  re-verified**: doing so needs a genuine 2-shard `ShardingTest`-style cluster (mongos + 2
  single-node replica sets) to reproduce the precise coordinator-freeze race the vendor's own test
  exercises; assessed as lower expected value than other leads given the fix already covers the
  exact adversarial timing window in its own test, and no static gap was found in the adjacent
  surface. (Follow-up: infrastructure for this was stood up in a later pass — see
  `../prepared-txn-commit-abort-race-lead/`.)

- **`1fb8c78406` (`SERVER-130168`) — "Validate size of fixed size BinData subtypes and ban
  conversion to Encrypt BinData subtype in `$convert`."** Traced `UUID::fromCDR()`'s hard
  `invariant()` (an uncatchable process-abort, not a `uassert`) to every non-test caller in the
  tree. The two call sites reachable from ordinary aggregation (`evaluate_math.cpp`'s
  `performConvertBinDataToString`, both the `kAuto` and `kUuid` format branches) each check
  `binData.length == UUID::kNumBytes` **before** calling `.getUuid()` — safe. The one call site
  that skips this check (`change_stream_event_transform.cpp`'s `makeResumeToken`) only receives
  its `uuidVal` from a real oplog entry's `ui` field, which requires the caller to already have
  applyOps-level privilege to forge — not a privilege-escalation path. **Live-tested the more basic
  question directly**, since it hadn't been confirmed empirically before now: ordinary `insert_one`
  **does** still accept a BinData subtype 4 (UUID) or subtype 5 (MD5) value of the wrong length
  (3 bytes tested, both accepted with no server-side error) — the fix only closed `$convert`'s own
  *construction* path, not the general BSON-acceptance gap that lets such a malformed value exist
  in a collection at all. This is a real, standing landmine: any *future* code that reads a
  UUID/MD5-subtype field via `Value::getUuid()` (or an equivalent unchecked-length accessor)
  without first checking length itself would crash the server on this pre-existing data, and nothing
  currently reachable from an ordinary client's own read/write privilege currently does that
  unchecked read. Recorded as a residual observation, not a standalone finding, since no consumer
  reachable today was found.

- **`420bda02cb` (`SERVER-130247`) — "Treat Decimal128 values as potentially invalid when
  preparing to yield or detach cursor."** A genuine use-after-free-shaped bug: SBE's
  `PlanStage::shouldCopyValue()` (`src/mongo/db/exec/sbe/stages/stages.h`) had `NumberDecimal`
  in its explicit "doesn't need an owned copy across cursor detach" list, when Decimal128 values
  are stored by pointer into the BSON buffer being detached — exactly a dangling-pointer read.
  Reachable via nothing more than a timeseries collection with a `Decimal128` meta field and a
  small `batchSize` forcing repeated inter-batch detach/reattach (the vendor's own added test,
  `jstests/core/query/sbe/sbe_prepare_for_decimal123_invalidation.js`, is exactly this — no
  special privilege). Traced the *canonical* shallow/deep classification (`isShallowType()` in
  `value.h`, based on the `TypeTags` enum ordering relative to `EndOfShallowTypeTags`) and
  confirmed it has **always** correctly classified `NumberDecimal` as non-shallow — the bug was
  isolated to this one redundant, hand-rolled switch statement duplicating that logic and getting
  it wrong. Checked every other `isShallowType`-adjacent call site in `sbe/` — all of them call the
  canonical function directly rather than re-implementing the classification, so this specific
  drift-between-two-classifiers shape doesn't recur elsewhere. The fixed code's remaining explicit
  "doesn't need copying" list (`StringBig`, `Array`, `ArraySet`, `ArrayMultiSet`, `Object`,
  `ObjectId`, `RecordId`) is now the only place a *similar* miscategorization could hide, and the
  post-fix `default: return true` makes any *newly introduced* SBE type fail safe (copied) by
  default. Did not find grounds to suspect any of those seven without materially deeper SBE study
  than this pass justified.

- **`67609b7ef5` (`SERVER-130404`) — "Bound recursion in `$convert` from object or array to
  string."** Before this fix, `$convert`'s object/array→string (`JsonStringGenerator`) had **no**
  recursion-depth check at all — an unbounded-recursion stack-overflow shape. The fix caps it at
  `2 × BSONDepth::getMaxAllowableDepth()` (400), a deliberately generous multiple of the normal
  200-level BSON nesting limit, implying the author expected some legitimate construction to reach
  up to ~2x the ordinary depth. **Live-tested two candidate ways to build an in-memory value
  deeper than the normal 200-level limit, independent of `$convert`, to see whether some other
  unbounded consumer might still be reachable:** (1) `$reduce` accumulating a wrapped array
  200+ times — rejected cleanly at exactly the BSON depth limit with its own dedicated error
  (`"$reduce accumulated value exceeded max allowable BSON depth"` — a check independent of this
  fix); (2) chaining ~250 sequential `$project` stages, each wrapping the previous stage's field one
  level deeper, starting from a legally-inserted 150-level-deep document (total attempted depth
  ~450) — also rejected cleanly (`"cannot convert document to BSON because it exceeds the limit of
  200 levels of nesting"`), confirming there's an inter-stage output check independent of any
  single expression's own bookkeeping. Both paths are evidently already guarded by mechanisms
  unrelated to this specific fix; did not find a construction that reaches the now-guarded
  `$convert` code path with a value between 200 and 400 levels deep to probe the new cap's own
  correctness, nor an alternative *unguarded* stringification consumer (e.g. error-message
  formatting via `Value::toString()`/`Document::toString()`) that a deep value could reach instead.

- **`0ea3713b31` (`SERVER-130117`) — "Fix race condition causing heap use after free in big
  polygon."** A real data-race/UAF in `BigSimplePolygon`'s lazily-initialized border caches
  (`_borderPoly`/`_borderLine`), reachable when a shared `BigSimplePolygon` instance is queried
  concurrently (S2's internal edge index mutates shared state even on nominally read-only spatial
  queries). The fix adds a mutex around all access. Read but did not attempt to dynamically
  reproduce or find a sibling in this pass: doing so needs sustained, precisely-timed concurrent
  stress against whatever code path shares a single `BigSimplePolygon` object across threads
  (plausibly a plan cache entry or a cached index bound reused across concurrent operations on the
  same large/antimeridian-crossing polygon geometry) — a materially larger investment for a
  probabilistic race than this pass's other checks. (Follow-up: this was tested in a later pass —
  see `../big-polygon-uaf-race-lead/RESULTS.md` — negative result, no crash across ~8,700
  concurrent iterations.)

- **`e62efcbfab` (`SERVER-130110`) — "Gate `$function`'s internal-only `_internalSetObjToThis`
  field behind an internal-client check."** Checked whether this follows the same
  lite-parse-time/null-`opCtx` shape as the confirmed `$idLookup` bug. It does not: the check
  (`expression_function.cpp`'s `ExpressionFunction::parse()`) reads `expCtx->getOperationContext()`
  — the same execution-time-real-opCtx pattern already confirmed safe against the `db.createView()`
  bypass for every other site checked in the earlier
  `createview-null-opctx-bypass-class-closure-sweep.md` pass. Consistent with that sweep's
  conclusion that `$idLookup`'s `viewPipeline` remains the only site using the vulnerable shape.

## Net result

No new exploitable bug from this pass. Positive value: independent confirmation (via primary-source
commit history, not just static reasoning) that the existing Critical finding targets a real,
still-open gap in an incomplete fix, plus a live-confirmed residual observation (malformed-length
UUID/MD5 BinData is still ordinarily insertable) that's worth keeping in mind for any future
consumer of those fields. Two commits (`SERVER-130544`'s prepared-txn race and `SERVER-130117`'s
big-polygon race) were flagged as needing more infrastructure/time than this pass allocated — both
were followed up on in a subsequent pass (see the two lead directories alongside this file); the
big-polygon race came back negative, and the prepared-txn race's infrastructure was stood up but
not completed before this session's container was recycled.
