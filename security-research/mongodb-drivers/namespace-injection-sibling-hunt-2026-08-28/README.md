# Sibling hunt: namespace/identifier-injection CVEs published 2026-08-28

**Scope note:** these 8 CVEs are a different bug *class* from the pre-auth wire-protocol
crash bugs found earlier in this engagement. They're not "attacker sends bytes over the
network before auth" bugs — they're "driver builds a namespace/query/connection-string from
caller-supplied identifiers without validating/escaping them" bugs. The "pre-auth" angle here
is: the entity that can trigger the bug is an untrusted end-user of an application built on
the driver, not someone holding valid MongoDB credentials — no cluster auth is required to
exploit the class, only the ability to influence an identifier/value the app passes into the
driver.

CVEs given:
- CVE-2026-81523 — libmongocrypt: unsanitized db identifier in auto-encryption context → wrong schema selection
- CVE-2026-81521 — **Go Driver**: `Client.BulkWrite` builds namespace from unescaped db name
- CVE-2026-81522 — C++ Driver: unescaped namespace identifiers → cross-tenant read/write
- CVE-2026-81524 — C Driver: unsanitized db/collection name components in namespace composition
- CVE-2026-81526 — Rust Driver: unescaped target identifier → write to unintended target
- CVE-2026-81527 — C# Driver: LINQ-to-aggregation translation NoSQL injection
- CVE-2026-81528 — C# Driver: replacement path omits validation other write paths apply
- CVE-2026-81529 — C# Driver: connection-string builder round-trip injects options

Only Go, Java, and Node driver source is cloned in this environment
(`/home/user/drivers/{mongo-go-driver,mongo-java-driver,node-mongodb-native}`). C++, C, Rust,
C#, and libmongocrypt were **not** checked — no local clone available this round.

## CVE-2026-81521 (Go Driver) — confirmed present, this is the published CVE, not a new finding

`mongo/client.go:1067` (checked at `v2.8.2`, commit `1af6d00dbeb70805a69cc9f8fc0828e1f4cef1ee`,
the current latest tag):

```go
writePairs[i] = clientBulkWritePair{
    namespace: fmt.Sprintf("%s.%s", w.Database, w.Collection),
    ...
```

`w.Database`/`w.Collection` come directly from the caller-supplied
`ClientNamespacedWriteModel` on each `Client.BulkWrite` item, with no validation — a
`Database` value containing a reserved separator (`.`) shifts what the server treats as the
database segment when it splits the resulting `nsInfo[].ns` string, exactly as the CVE
describes. This is the same code this engagement already read while auditing the Go driver's
`OP_COMPRESSED` decompression bug — same file tree, different function
(`clientBulkWriteWriteModelsToPairs`/batch-building path vs. `decompressWireMessage`). No new
report written for this: it's already a filed, published CVE as of today, matching the code
exactly. Confirmed still present at the latest release tag (`v2.8.2`) — not yet patched as of
this check.

Collection-level `Collection.BulkWrite` (`mongo/bulk_write.go`) is not affected the same way —
it operates on a single already-fixed `*Collection` (whose db/collection names were set once,
outside the per-operation model), not a per-operation caller-supplied namespace pair.

## Java Driver — not vulnerable to this pattern

`MongoNamespace(String databaseName, String collectionName)`
(`driver-core/.../MongoNamespace.java:116-124`) calls `checkDatabaseNameValidity(databaseName)`
unconditionally, which explicitly **rejects** `'\0', '/', '\\', ' ', '"', '.'` in the database
name (lines 43-44, 68-76) before any namespace string is ever built. The client-level bulk
write model types (`ConcreteClientNamespacedUpdateOneModel` etc., in
`driver-core/.../internal/client/model/bulk/`) are built on top of `MongoNamespace`, so they
inherit this validation for free. No sibling of CVE-2026-81521 in the Java driver.

Also re-checked the Go driver's replace-vs-update dollar-key handling while in the area, in
case it mirrored CVE-2026-81528's "replace path skips validation another path applies" shape:
`marshalUpdateValue` (`mongo/mongo.go:295-304`) always validates, just with the *opposite*
check depending on operation type — `ensureDollarKey` for update docs (must contain an update
operator), `ensureNoDollarKey` for replacement docs (must not). `checkDollarKey: false` on
`ReplaceOneModel` paths (both `bulk_write.go` and `client_bulk_write.go`) selects the correct
opposite check, it isn't a validation being skipped. Not a sibling of CVE-2026-81528 in Go.

## Node.js Driver — different API shape, doesn't reproduce the pattern

`src/operations/client_bulk_write/common.ts:39`: the client-level bulk write model requires
the caller to supply the **full** `namespace: string` (`"<database-name>.<collection>"`)
directly — there's no separate `database`/`collection` fields that the driver itself
concatenates. `command_builder.ts` takes `model.namespace` as an opaque string and puts it
straight into `nsInfo.ns` with no further splitting/rebuilding on the driver's part. Since the
driver never performs the unescaped-concatenation step itself, this specific defect shape
doesn't apply — the caller is responsible for the same string they'd pass to `db.collection()`
anywhere else in the API, no new trust boundary is crossed by this call in particular.

## Not checked (no local clone this round)

C++, C, Rust, and C# drivers, and libmongocrypt — CVE-2026-81522, -81523, -81524, -81526,
-81527, -81528 (partially, see above Go note), -81529 were not independently verified against
those codebases. Would need those repos cloned to check for genuine siblings (e.g., does the
Rust driver's namespace-building have an equivalent to Go's `fmt.Sprintf` concatenation without
validation; does any driver's `ConnectionString`/URI builder round-trip untrusted text back
into authoritative options the way CVE-2026-81529 describes for C#).

## Conclusion

No new pre-auth-class sibling vulnerability found in this round. The one real hit (Go driver)
is the already-published CVE-2026-81521 itself, confirmed still present in the current latest
release tag — useful confirmation, not a new report. Java and Node were checked and found not
to share the underlying defect pattern.
