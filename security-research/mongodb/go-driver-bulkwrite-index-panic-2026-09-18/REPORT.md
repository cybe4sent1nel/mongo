# Title

`bulkWrite.runInsert`'s caller in `mongo/bulk_write.go` indexes `batch.models`/`batch.indexes` directly with a raw, unvalidated server-supplied `writeErrors[].index`/`upserted[].index` — unpatched sibling of GODRIVER-4096 (out-of-range slice panic) in the driver's newer unified `BulkWrite` API

## Summary

Commit `15ca7a00` (GODRIVER-4096, in the current release `v2.9.1`) fixed a real, server-triggerable panic in `Collection.insert`'s legacy `InsertMany` path: the old code computed `idIndex := int(we.Index) - i` and sliced `result` with it, assuming the server always returns `writeErrors[].index` values in ascending order. It doesn't have to (per the fix's own commit message: *"the server does not guarantee ascending Index order for an unordered bulk write"*), and an out-of-order or duplicate-valued response caused `result[:idIndex]`/`append(result[:idIndex], ...)` to receive a negative or otherwise invalid index, panicking with `slice bounds out of range`. The fix replaced the positional arithmetic with a map-based `keepInsertedIDs` helper that looks up each index directly instead of assuming order.

That fix only touched `mongo/collection.go` (the older `Collection.InsertMany`/`insert` code path). The newer, unified `BulkWrite` API — `mongo/bulk_write.go`, the code path for `Client.BulkWrite`/`Collection.BulkWrite`, handling mixed insert/update/delete/replace operations in one call — has the exact same class of bug, worse: it doesn't even attempt positional arithmetic, it just **indexes the batch's own slices directly with the raw server-supplied index, with no bounds check of any kind**:

```go
// mongo/bulk_write.go (current, present on v2.9.1 and master)
case *ReplaceOneModel, *UpdateOneModel, *UpdateManyModel:
    res, err := bw.runUpdate(ctx, batch)
    ...
    for _, upsert := range res.Upserted {
        batchRes.UpsertedIDs[int64(batch.indexes[upsert.Index])] = upsert.ID   // <-- unchecked index
    }
}

batchErr.WriteErrors = make([]BulkWriteError, 0, len(writeErrors))
convWriteErrors := writeErrorsFromDriverWriteErrors(writeErrors)
for _, we := range convWriteErrors {
    request := batch.models[we.Index]           // <-- unchecked index
    we.Index = batch.indexes[we.Index]           // <-- unchecked index
    batchErr.WriteErrors = append(batchErr.WriteErrors, BulkWriteError{
        WriteError: we,
        Request:    request,
    })
}
```

`batch.models` and `batch.indexes` (`bulkWriteBatch` struct, `mongo/bulk_write.go:23-27`) are both slices sized to the number of write models in that batch. `we.Index` and `upsert.Index` are both raw values taken from the server's response with **no validation at all**, traced back to their origin:

```go
// x/mongo/driver/errors.go:480-483 — parsing "writeErrors" from the raw server response
if index, exists := doc.Lookup("index").AsInt64OK(); exists {
    we.Index = index   // raw int64 off the wire; WriteError.Index is declared `int64`; no range check
}
```

`writeErrorsFromDriverWriteErrors` (`mongo/errors.go:537-549`) narrows this to `int` with a bare cast (`Index: int(err.Index)`), still with no validation, and that's the value that reaches `batch.models[we.Index]` / `batch.indexes[we.Index]` in `bulk_write.go`. The `Upserted[].Index` field driving line 156 comes from the analogous `"upserted"` array parsing, with the same lack of validation.

## Impact

A malicious or compromised server (or a MITM on a non-TLS connection) can respond to any bulk write issued through `Client.BulkWrite`/`Collection.BulkWrite` with a `writeErrors` or `upserted` array containing an `index` value that is negative, or ≥ the number of models in that batch. The very first such value reaching `batch.models[we.Index]`, `batch.indexes[we.Index]`, or `batch.indexes[upsert.Index]` panics with `index out of range` (or a negative-index variant), and — being unrecovered — crashes the whole client process, exactly the impact class GODRIVER-4096 was fixed to prevent for the older API. Any application that has migrated to (or exclusively uses) the newer unified `BulkWrite` API, which MongoDB's own driver documentation and blog posts have been steering users toward as the modern replacement for per-collection bulk methods, is exposed via this path instead of the one that was patched.

## Weakness

CWE-129 (Improper Validation of Array Index) / CWE-617 (Reachable Assertion, in the Go-panic sense) — same class as the parent fix, reachable from an untrusted or compromised server response, no special server privilege required beyond controlling what a configured endpoint replies with.

## Component / Version

- Repository: `mongodb/mongo-go-driver`
- Confirmed present in `mongo/bulk_write.go` on the latest tagged release `v2.9.1` (the exact tag containing the GODRIVER-4096 fix) and unchanged on `master` at the time of this audit (2026-09-18) — this is not a regression introduced elsewhere, it is the sibling code path the fix didn't reach.

## Suggested fix

Validate `we.Index`/`upsert.Index` against `len(batch.models)`/`len(batch.indexes)` (and against being negative) before using them to index, treating an out-of-range value as a malformed/untrusted server response (an error) rather than trusting it implicitly — mirroring the defensive, no-ordering-assumption approach `keepInsertedIDs` already takes for the sibling code path:

```go
for _, we := range convWriteErrors {
    if we.Index < 0 || we.Index >= len(batch.models) {
        return BulkWriteResult{}, batchErr, fmt.Errorf("server returned invalid write error index %d for a batch of %d models", we.Index, len(batch.models))
    }
    request := batch.models[we.Index]
    we.Index = batch.indexes[we.Index]
    ...
```
(and the analogous check before `batch.indexes[upsert.Index]` at line 156).

## Suggested repro (static analysis only — not executed against a live server in this environment)

1. Using a mock deployment (the same `mtest.ClientType(mtest.Mock)` harness GODRIVER-4096's own regression tests use), issue `Client.BulkWrite` with an unordered batch of, say, 2 write models.
2. Mock a response whose `writeErrors` array contains `{"index": 5, "code": 11000, "errmsg": "duplicate key error"}` (an index outside the batch's range) — or, more minimally, reuse the exact out-of-order-index response shape from GODRIVER-4096's own added test cases (`{"index": 1}, {"index": 0}` — a response that already crashed the old code for being *out of order*; here the new code path never even checks order, but the same "trust the server's index" root cause applies to bounds instead).
3. Observe `batch.models[we.Index]` panic with `index out of range [5] with length 2`.

## Notes on scope

Found while sibling-hunting the Go driver's own recent GODRIVER-4096 fix, in the same audit pass as the two decompression-allocation findings reported alongside this one. Fresh finding, not part of the originally reviewed CVE list, not yet reported upstream.
