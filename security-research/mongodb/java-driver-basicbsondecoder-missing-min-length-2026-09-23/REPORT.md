# Title

`org.bson.BasicBSONDecoder.readFully(InputStream)` reads a raw, unvalidated BSON length prefix and immediately uses it in allocation (`new byte[size]`) and subtraction (`size - 4`) — unpatched sibling of CVE-2026-93395 (libbson `bson_new_from_buffer()` integer underflow), crashing with `NegativeArraySizeException`/`ArrayIndexOutOfBoundsException` on a 0–3 byte malicious length prefix

## Summary

CVE-2026-93395 (fixed in libbson/libmongoc 1.30.11) was an integer underflow in the C driver's `bson_new_from_buffer()`: it read a 32-bit little-endian length prefix off raw bytes and used it directly in arithmetic/indexing without first validating a minimum of 5 (4-byte length + 1-byte terminator, the smallest possible valid BSON document). A crafted tiny length caused the underflow and a heap out-of-bounds read/crash.

The Java driver's modern NIO-backed decode path (`BsonBinaryReader`/`ByteBufferBsonInput`) validates every length via `ensureAvailable()` before use and is clean. However, the driver also ships a legacy, still-public stream-based decoder with the identical missing-lower-bound pattern:

```java
// bson/src/main/org/bson/BasicBSONDecoder.java:100-109
private byte[] readFully(final InputStream input) throws IOException {
    byte[] sizeBytes = new byte[4];
    Bits.readFully(input, sizeBytes);
    int size = Bits.readInt(sizeBytes);           // raw, attacker-controlled int32 length

    byte[] buffer = new byte[size];                // <-- no size >= 5 (or even >= 4) check first
    System.arraycopy(sizeBytes, 0, buffer, 0, 4);   // arithmetic/copy using unvalidated size
    Bits.readFully(input, buffer, 4, size - 4);     // <-- size - 4 underflows for size < 4
    return buffer;
}
```

This is the direct analog of `bson_new_from_buffer`: the four-byte length header is read and immediately fed into an allocation and a subtraction with zero validation, unlike the driver's own `BsonBinaryReader.readSize()`, which at least checks `size < 0`.

## Impact

Any caller that hands `BasicBSONDecoder` (via its public `readObject(InputStream)` / `decode(InputStream, BSONCallback)` methods) bytes originating from an untrusted source — a network peer, a file, an IPC channel — can crash the calling JVM thread with an unrecovered `RuntimeException` by sending a 4-byte "document" whose length prefix is 0–3. Because Java arrays and `arraycopy` are always bounds-checked, this cannot become a true memory-unsafe heap OOB read as in the original CVE, but the observable consequence — an uncaught exception terminating request processing / crashing the process if unhandled at a higher layer — is the same denial-of-service impact class MongoDB rated CVE-2026-93395 at (CVSS 6.9). `BasicBSONDecoder` is a legacy but still fully public, exported API (`org.bson.BasicBSONDecoder`), independent of the modern wire-protocol path, so it is exposed to any application code that chooses to decode untrusted BSON bytes with it directly.

## Weakness

CWE-191 (Integer Underflow) leading to CWE-789-class uncontrolled allocation / index errors, downgraded from memory-unsafe (C) to a bounds-checked exception (JVM) — same missing-lower-bound root cause as CVE-2026-93395, in an unpatched sibling code path.

## Component / Version

- Repository: `mongodb/mongo-java-driver`
- File: `bson/src/main/org/bson/BasicBSONDecoder.java`, `readFully(InputStream)` (lines 100-109), reached from public `readObject(InputStream)`/`decode(InputStream, BSONCallback)`
- Also relevant: `bson/src/main/org/bson/Bits.java:51-67` (`readInt`, no validation — by design, validation is the caller's responsibility)
- Confirmed present, byte-identical, on both the default branch `main` (HEAD `ff744701`) and the latest release tag `r5.12.0` — diffed directly, no differences in the relevant methods.

## Proof of Concept

Verified by compiling the real driver sources with `javac` (only unrelated annotation/logging stub classes were stubbed for compilation — the decoder logic under test is untouched) and running crafted byte sequences against the actual compiled `BasicBSONDecoder`:

```java
// PocTest.java (abridged) — feeds crafted 4-byte length prefixes into
// org.bson.BasicBSONDecoder.readObject(InputStream), reading real compiled classes
byte[] len0 = {0x00, 0x00, 0x00, 0x00}; // declared length = 0
byte[] lenNeg = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}; // declared length = -1
byte[] len1 = {0x01, 0x00, 0x00, 0x00}; // declared length = 1
byte[] len3 = {0x03, 0x00, 0x00, 0x00}; // declared length = 3
```

| crafted length prefix | result |
|---|---|
| `0x00000000` (0) | `ArrayIndexOutOfBoundsException: arraycopy: last destination index 4 out of bounds for byte[0]` |
| `0xFFFFFFFF` (-1) | `NegativeArraySizeException: -1` |
| `0x00000001` (1) | `ArrayIndexOutOfBoundsException` (same arraycopy failure) |
| `0x00000003` (3) | `ArrayIndexOutOfBoundsException` (same arraycopy failure) |
| `0x00000004` (4) | passes `readFully`, later rejected cleanly downstream in `BsonBinaryReader` |
| `05 00 00 00 00` (valid empty doc) | decodes fine, no exception |

Every crafted input in the 0–3 range throws an unrecovered `RuntimeException` straight out of `readFully`, before any of the driver's own error-handling/validation logic gets a chance to produce a clean, typed `BSONException`.

## Suggested fix

Validate `size` before using it, mirroring the modern path's `ensureAvailable`/`readSize` checks:

```java
private byte[] readFully(final InputStream input) throws IOException {
    byte[] sizeBytes = new byte[4];
    Bits.readFully(input, sizeBytes);
    int size = Bits.readInt(sizeBytes);
    if (size < 5) {
        throw new IOException("invalid BSON length: " + size);
    }
    byte[] buffer = new byte[size];
    System.arraycopy(sizeBytes, 0, buffer, 0, 4);
    Bits.readFully(input, buffer, 4, size - 4);
    return buffer;
}
```

## Notes on scope

Found while sibling-hunting CVE-2026-93395 (libbson integer underflow in `bson_new_from_buffer()`) across all official MongoDB driver BSON implementations. libbson itself (mongo-c-driver, `src/libbson/src/bson/bson.c`, `bson-iter.c`, `bson-reader.c`) was audited first and found clean — every length-prefix read site already carries the correct `length < 5` guard. The modern Java driver decode path (`BsonBinaryReader`) is likewise clean. This finding is specifically in the legacy `BasicBSONDecoder`, a genuinely independent, unpatched sibling that implements the same length-read-then-use pattern the CVE's fix addressed elsewhere. Not part of the originally published CVE, not yet reported upstream.
