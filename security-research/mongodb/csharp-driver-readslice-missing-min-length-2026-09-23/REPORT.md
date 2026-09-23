# Title

`ByteBufferStream.ReadSlice()`/`ThrowIfEndOfStream()` silently bypass their own bounds check for a raw BSON length < 4, and `BsonStreamAdapter.ReadSlice()` performs no length validation at all — unpatched sibling of CVE-2026-93395 (libbson `bson_new_from_buffer()` integer underflow), causing malformed-document acceptance or an `OutOfMemoryException`/crash from a 4-byte crafted length prefix

## Summary

CVE-2026-93395 (fixed in libbson/libmongoc 1.30.11) was an integer underflow in the C driver's `bson_new_from_buffer()`: it read a 32-bit little-endian length prefix off raw bytes and used it directly in arithmetic/indexing without first validating a minimum of 5 (the smallest possible valid BSON document). A crafted tiny length caused the underflow and a heap out-of-bounds read/crash.

The root helper, `BsonBinaryReader.ReadSize()` (`src/MongoDB.Bson/IO/BsonBinaryReader.cs:846-860`), only checks `size < 0` and `size > MaxDocumentSize` — it never checks `size < 5` — and that unvalidated value flows into subtraction (`length - 4`) in multiple places. The clearest, most directly reachable instance is `IByteBuffer ReadSlice()`, the method backing `ReadRawBsonDocument()`/`ReadRawBsonArray()` — the driver's "parse raw bytes into a document/array" fast path:

```csharp
// src/MongoDB.Bson/IO/ByteBufferStream.cs:491-501
public override IByteBuffer ReadSlice()
{
    var position = _position;
    var length = ReadInt32();
    ThrowIfEndOfStream(length - 4);   // length-4 is negative for length<4 -> check is bypassed
    Position = position + length;
    return _buffer.GetSlice(position, length);
}
```

```csharp
// src/MongoDB.Bson/IO/ByteBufferStream.cs:352-363
private void ThrowIfEndOfStream(int count)
{
    var minimumLength = _position + count;   // count negative -> minimumLength smaller than it should be
    if (_length < minimumLength) { throw ... }
    ...
}
```
When `length < 4`, `count = length - 4` is negative, so `minimumLength` computed from it is *smaller* than the real current position — the exact same "subtract without a lower-bound check first" pattern that caused the CVE's underflow, just one arithmetic step removed from the indexing itself. The `ThrowIfEndOfStream` guard is effectively defeated for any length in `0..4`, and the method returns a slice smaller than the 5-byte BSON minimum with no error.

A second, worse instance has no validation at all:

```csharp
// src/MongoDB.Bson/IO/BsonStreamAdapter.cs:337-347
public override IByteBuffer ReadSlice()
{
    var position = _stream.Position;
    var length = ReadInt32();
    var bytes = new byte[length];      // <-- no bound check whatsoever
    _stream.Position = position;
    this.ReadBytes(bytes, 0, length);
    return new ByteArrayBuffer(bytes, isReadOnly: true);
}
```

## Impact

- `ByteBufferStream.ReadSlice()`: accepts and returns a raw document/array slice smaller than the 5-byte BSON minimum (e.g. length 0 or 3) instead of rejecting it — a validation bypass that lets a malformed/truncated "document" flow further into the driver as if it were legitimate, mirroring the CVE's missing lower bound rather than its exact crash.
- `BsonStreamAdapter.ReadSlice()`: a crafted 4-byte length prefix of `int.MinValue`/`-1` reaches `new byte[length]` with a negative `int` reinterpreted as an allocation request, throwing `OutOfMemoryException` — a crash/denial-of-service triggerable by any `Stream`-backed BSON read of untrusted bytes (e.g. `ReadRawBsonDocument`/`ReadRawBsonArray` over a network stream or file).

Because .NET array/`IByteBuffer` accesses in this call chain are bounds-checked managed code (no `unsafe`), and `ByteArrayBuffer.GetSlice` independently re-validates `length < 0` one layer below, this cannot become a true memory-unsafe heap OOB read as in the original C CVE — the observable impact is a validation bypass plus a crash/DoS vector, the same severity class MongoDB rated CVE-2026-93395 at (CVSS 6.9, DoS).

## Weakness

CWE-191 (Integer Underflow) / CWE-20 (Improper Input Validation) — same missing-lower-bound-before-arithmetic root cause as CVE-2026-93395, in an unpatched sibling code path.

## Component / Version

- Repository: `mongodb/mongo-csharp-driver`
- Files:
  - `src/MongoDB.Bson/IO/ByteBufferStream.cs:491-501` (`ReadSlice`) and `:352-363` (`ThrowIfEndOfStream`)
  - `src/MongoDB.Bson/IO/BsonStreamAdapter.cs:337-347` (`ReadSlice`)
  - Root cause: `src/MongoDB.Bson/IO/BsonBinaryReader.cs:846-860` (`ReadSize()` — missing `size < 5` check)
- Confirmed present, byte-identical, on both the default branch `main` (commit `33214730`) and the latest release tag `v3.12.0`.

## Proof of Concept / verification method

The sandbox environment could not reach `builds.dotnet.microsoft.com` (network egress policy), so the real `dotnet` SDK/NuGet restore of the actual `MongoDB.Bson.dll` was not available. To verify the logic dynamically rather than relying on source-reading alone, the method bodies of `ReadSlice`, `ThrowIfEndOfStream`, the `Position` setter, and `ByteArrayBuffer.GetSlice` were copied **verbatim** (diffed line-by-line against the real source files to confirm an exact match) into a minimal stand-in class hierarchy, compiled and run with Mono (`mcs`/`mono`, installed via `apt`):

| path | crafted length | result |
|---|---|---|
| `ByteBufferStream.ReadSlice` | 0 | **no exception** — returns a 0-byte "document" slice; `ThrowIfEndOfStream` bypassed |
| `ByteBufferStream.ReadSlice` | 3 | **no exception** — returns a 3-byte slice (below the BSON minimum of 5); bypassed |
| `ByteBufferStream.ReadSlice` | -1 | throws `ArgumentOutOfRangeException`, caught one layer below by the `Position` setter's own `value < 0` check — not the intended guard |
| `ByteBufferStream.ReadSlice` | 5 (valid) | works normally, no regression |
| `BsonStreamAdapter.ReadSlice` | 0 | **no exception**, 0-byte slice, no validation at all |
| `BsonStreamAdapter.ReadSlice` | -1 / `int.MinValue` | `OutOfMemoryException` — negative `int` reinterpreted as a huge array-size argument |

This is labeled "confirmed via faithful re-execution" rather than "confirmed against the compiled `MongoDB.Bson.dll`" for that reason — the control flow, exception types, and arithmetic shown are exact matches for the real source (verified by direct line-by-line diff against the checked-out files at both `main` and `v3.12.0`), but the harness recompiles that logic standalone rather than invoking the official build artifact.

## Suggested fix

Add a `< 5` lower-bound check to `BsonBinaryReader.ReadSize()` itself (the single choke point both `ReadSlice` implementations and every other length-consuming caller flow through), so the fix applies uniformly rather than needing to be duplicated at each call site:

```csharp
private int ReadSize()
{
    ...
    if (size < 5)
    {
        throw new FormatException($"Document size {size} is invalid since it is smaller than the smallest allowed document size of 5 bytes.");
    }
    if (size > __maxDocumentSize) { ... }
    return size;
}
```

## Notes on scope

Found while sibling-hunting CVE-2026-93395 (libbson integer underflow in `bson_new_from_buffer()`) across all official MongoDB driver BSON implementations. libbson itself (mongo-c-driver, `src/libbson/src/bson/bson.c`, `bson-iter.c`, `bson-reader.c`) was audited first and found clean — every length-prefix read site already carries the correct `length < 5` guard. This finding is a genuinely independent, unpatched sibling in the C# driver's own from-scratch BSON implementation. Not part of the originally published CVE, not yet reported upstream.
