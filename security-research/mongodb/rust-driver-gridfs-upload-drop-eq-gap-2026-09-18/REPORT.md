# Title

`GridFsUploadStream`'s `Drop` impl still deletes chunks with a raw, unwrapped `files_id` filter — unpatched sibling of RUST-2469/RUST-2502 (CVE-2026-88024) in the mongo-rust-driver, present in the shipped fix release `v3.9.1`

## Summary

`mongo-rust-driver` v3.9.1 fixed CVE-2026-88024 (GridFS query-operator injection via a caller-supplied file id reaching a MongoDB filter unescaped) by wrapping every `_id`/`files_id` filter in GridFS delete/download/rename with `{"$eq": id}` (commit `2282e853`, back-merging the 3.9.1 release changes, applied identically to `driver/src/action/gridfs/delete.rs`, `download.rs`, `rename.rs`, and `driver/src/gridfs/download.rs`, plus the explicit `abort()`-driven cleanup path in `driver/src/gridfs/upload.rs::clean_up_chunks`).

One call site doing the exact same "delete this upload's chunks by `files_id`" operation was missed: `GridFsUploadStream`'s `Drop` implementation (`driver/src/gridfs/upload.rs:263-273`). It builds the identical `files_id` filter from the identical caller-controlled `id` field, but without the `$eq` wrap:

```rust
impl Drop for GridFsUploadStream {
    fn drop(&mut self) {
        if !matches!(self.state, State::Closed) {
            let chunks = self.bucket.chunks().clone();
            let id = self.id.clone();
            self.drop_token.spawn(async move {
                let _result = chunks.delete_many(doc! { "files_id": id }).await;
            })
        }
    }
}
```

`self.id` is the exact same `Bson` value that `abort()` — two functions above, in the same `impl` block (line 252-260) — passes through the **fixed** `clean_up_chunks()` helper:

```rust
pub async fn abort(&mut self) -> Result<()> {
    match self.state {
        State::Closed => Err(ErrorKind::GridFs(GridFsErrorKind::UploadStreamClosed).into()),
        _ => {
            self.state = State::Closed;
            clean_up_chunks(self.id.clone(), self.bucket.chunks().clone(), None).await   // fixed: wraps in $eq
        }
    }
}
```
```rust
async fn clean_up_chunks(id: Bson, chunks: Collection<Chunk<'static>>, original_error: Option<Error>) -> Result<()> {
    match chunks.delete_many(doc! { "files_id": { "$eq": id } }).await {   // upload.rs:447 — the actual fix
        ...
```

So the fix exists in the file, is applied correctly to the explicit `abort()` path, and is simply not reused by the implicit `Drop` cleanup path a few lines away — the two code paths do the same thing (delete this upload's orphaned chunks) and only one of them got the security fix.

## Weakness

CWE-943 (Improper Neutralization of Special Elements in Data Query Logic / NoSQL Injection) — the same class as the parent CVE. Confirmed present as `delete_many` (unbounded, matches every document satisfying the filter across the whole `chunks` collection of the bucket), not `delete_one`.

## Why this is reachable with an entirely ordinary `id`

`GridFsUploadStream::id` is directly caller-settable, by design — the driver's public API explicitly supports supplying a custom GridFS file id instead of letting the driver generate an `ObjectId`:

`driver/src/action/gridfs/upload.rs:44-60`:
```rust
pub struct OpenUploadStream<'a> {
    bucket: &'a GridFsBucket,
    filename: String,
    id: Option<Bson>,
    options: Option<GridFsUploadOptions>,
}

impl OpenUploadStream<'_> {
    /// Set the value to be used for the corresponding [`FilesCollectionDocument`]'s `id`
    /// field.  If not set, a unique [`ObjectId`] will be generated ...
    pub fn id(mut self, value: Bson) -> Self {
        self.id = Some(value);
        self
    }
}
```

`value: Bson` places no restriction on the shape of the id — a `Bson::Document` such as `bson!({"$gt": Bson::MinKey})` is accepted exactly like an `ObjectId` and is passed straight through to `GridFsUploadStream::new(..., id, ...)` (`upload.rs:68-82`), landing in `self.id` unchanged.

An application that lets any part of an upload's identity be influenced by request data — e.g. a multi-tenant service that lets a (low-privileged, otherwise sandboxed) caller specify a custom GridFS file id for their own upload, a common and intentional use of this API (idempotency keys, externally-correlated ids, migrated ids from another store) — and then has that upload stream **not** call `.close()` on some code path (an early `?`-propagated I/O error, a cancelled `select!`/timeout branch, a panic elsewhere in the same task unwinding through the stream's scope, or simply a bug/oversight in caller error handling) causes `Drop::drop` to fire with the attacker-chosen `id` still unwrapped. `delete_many(doc! { "files_id": id })` with `id = {"$gt": MinKey}` (or any always-true operator document) deletes the chunks of every file in the bucket — a bucket usually shared across all of that application's users/tenants — not just the aborted upload's own chunks. This is exactly the "one call could strip the chunks from every file in the bucket" impact the parent CVE's own fix commit describes for the sibling drivers (Ruby's equivalent advisory text, near-identical bug), just reached through the implicit-drop path instead of the explicit-delete path.

No special driver configuration is needed: this is the default, always-registered `Drop` impl on the stream type returned by the ordinary `open_upload_stream()` builder; there is no opt-out.

## Component / Version

- Repository: `mongodb/mongo-rust-driver`
- Confirmed present in tag `v3.9.1` (the tagged fix release for CVE-2026-88024 itself) at `driver/src/gridfs/upload.rs:263-273` — i.e. the vulnerable code shipped in the same release that fixed the rest of this bug class.
- Also present on `HEAD` (commit `2282e853` and later) at the time of this audit (2026-09-18).

## Suggested fix

Route `Drop::drop`'s cleanup through the same `clean_up_chunks()` helper `abort()` already uses (it takes `id: Bson` by value and already does the `$eq`-wrapped `delete_many`, so this is a direct swap — no new logic needed):

```rust
impl Drop for GridFsUploadStream {
    fn drop(&mut self) {
        if !matches!(self.state, State::Closed) {
            let chunks = self.bucket.chunks().clone();
            let id = self.id.clone();
            self.drop_token.spawn(async move {
                let _ = clean_up_chunks(id, chunks, None).await;
            })
        }
    }
}
```
(or, minimally, inline the same `doc! { "files_id": { "$eq": id } }` filter used at `upload.rs:447`.)

## Suggested repro (static analysis only — not executed against a live server in this environment)

1. Connect to a `mongod`/`mongos` instance with a low-privileged account that only has read/write access to its own GridFS bucket's `files`/`chunks` collections (an entirely ordinary GridFS-writer permission level — no admin/special privilege needed, since this is a client-side driver bug, not a server authorization bug).
2. `bucket.open_upload_stream("x").id(bson!({"$gt": Bson::MinKey})).await?`
3. Write zero or more chunks, then drop the returned `GridFsUploadStream` without calling `.close()` (e.g., let it go out of scope after an early `return Err(...)`, or drop it explicitly).
4. Observe (e.g. via a debug log point in `Drop::drop`, or by inspecting the `chunks` collection before/after) that the spawned `delete_many(doc! { "files_id": {"$gt": Bson::MinKey}})` matches and deletes the chunks of every other file in the same bucket, not just the aborted upload.

## Notes on scope

This finding is specific to the mongo-rust-driver's GridFS upload-stream `Drop` path. As part of the same audit I checked all other `_id`/`files_id` filter-construction sites across `driver/src/gridfs/` and `driver/src/action/gridfs/` (delete-by-id, delete-by-name via `$in` over server-resolved ids, download-by-id, rename, and the explicit-`abort()` chunk cleanup) — all of them correctly use the `$eq` wrap or a `$in` list built exclusively from ids already resolved from the server (never a raw caller-supplied id document), and are not siblings of this bug.

The Go, Java, and Ruby drivers' equivalent GridFS fixes were also audited (separately) for the same "cleanup path forgot the wrap" gap; no equivalent gap was found in those three — this pattern appears to be specific to the Rust driver's additional, implicit `Drop`-based cleanup path, which the other audited drivers do not have (their upload/write-stream types do not auto-delete chunks on drop).
