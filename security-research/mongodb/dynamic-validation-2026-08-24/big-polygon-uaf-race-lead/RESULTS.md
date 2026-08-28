# Results: BigSimplePolygon concurrent-race stress test (2026-08-25)

**Status: negative (no crash, no result mismatch).** Recorded honestly per this program's
verify-before-claiming discipline — a negative result on a data race is much weaker evidence of
"no residual gap" than the positive confirmations elsewhere in this program, since a race is
inherently probabilistic and this pass didn't have an ASAN/debug build to catch corruption that
doesn't happen to crash.

## Method

Standalone `mongod` 8.3.8, a `2dsphere`-indexed collection of 20,000 randomly-scattered GeoJSON
points, and the strict-winding "big polygon" query from `LEAD.md`. Established a sequential
baseline count (`19,124` matching documents) via `count_documents()`, then launched 80 concurrent
persistent connections, each looping the identical `count_documents()` call against the identical
polygon literal for 90 seconds, comparing every result against the baseline and logging any
mismatch, while polling `/proc/<mongod_pid>` for liveness throughout.

## Result

```
expected count (sequential baseline): 19124
...
t=54.0s  iters=5202  mismatches=0  errors=0
t=90.0s  iters=8637  mismatches=0  errors=0
FINAL: {'iters': 8717, 'mismatches': 0, 'errors': 0}  mongod_alive: True  crashed: False
```

8,717 concurrent query executions across 80 simultaneous connections over 90 seconds, zero
result mismatches, zero errors, `mongod` alive throughout.

## Interpretation

The `stdx::mutex _borderMu` fix (`SERVER-130117`) appears to hold under this level of concurrent
stress — substantial, but not exhaustive, evidence. This test did not confirm that a single
`BigSimplePolygon` instance was actually *shared* across the concurrent connections (the plan-cache
sharing hypothesis in `LEAD.md` item 1) — it's possible each connection's query got its own fresh
instance every time, in which case this test never actually exercised the race condition's
precondition at all, and the negative result would say nothing about the fix's correctness rather
than confirming it. Distinguishing those two possibilities would need either an ASAN build (to
catch corruption that doesn't crash) or direct instrumentation of `BigSimplePolygon` construction
to confirm/deny instance reuse — neither available in this pass.

## Status of the other lead in this directory

`prepared-txn-commit-abort-race-lead/` — completed 2026-08-28: negative result, the SERVER-130544
fix holds under the exact adversarial timing tested. See that lead's own `RESULTS.md`.
