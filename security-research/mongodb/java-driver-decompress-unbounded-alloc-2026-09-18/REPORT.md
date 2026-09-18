# Title

`CompressedHeader.uncompressedSize` is read straight off the wire with **zero** validation and used to pre-allocate the decompression buffer — cross-driver sibling of the Go driver's GODRIVER-4135 (negative-size panic fix), and strictly worse: the Java driver validates neither the negative nor the oversized case

## Summary

While sibling-hunting the Go driver's newly-landed GODRIVER-4135 fix (a server-supplied, negative `int32` `uncompressedSize` field in an `OP_COMPRESSED` reply reaching `make([]byte, ...)` unguarded and crashing the client with a panic), I checked whether the same "trust a server-declared wire-header field for a buffer allocation" pattern exists in the other official drivers. It reproduces in the Java driver — and there it's worse, because unlike Go's post-fix state, **no bound is enforced in either direction**.

`CompressedHeader.java` reads the field with no check at all:

```java
// driver-core/src/main/com/mongodb/internal/connection/CompressedHeader.java:56-58
originalOpcode = header.getInt();
uncompressedSize = header.getInt();     // raw server-controlled int32, no validation
compressorId = header.get();
```

That value is then used directly to size the buffer the decompressed message is written into, before any decompression happens and before any relationship to the actual compressed payload size is checked:

```java
// driver-core/src/main/com/mongodb/internal/connection/InternalStreamConnection.java:1105 (and :1207, the async path)
uncompressedBuffer = getBuffer(compressedHeader.getUncompressedSize());
compressor.uncompress(messageBuffer, uncompressedBuffer);
```

`getBuffer(int size)` (`InternalStreamConnection.java:1139`, delegating to `PowerOfTwoBufferPool.getByteBuffer`/`createNew`) ultimately calls `ByteBuffer.allocate(size)`:

```java
// PowerOfTwoBufferPool.java
private ByteBuffer createNew(final int size) {
    ByteBuffer buf = ByteBuffer.allocate(size);
    ...
```

The only length check performed anywhere before this point is on the **outer** wire-message length, in `MessageHeader`'s constructor:

```java
// MessageHeader.java
MessageHeader(final ByteBuf header, final int maxMessageLength) {
    messageLength = header.getInt();
    ...
    if (messageLength > maxMessageLength) {
        throw new MongoInternalException(...);
    }
}
```

That bounds the physical number of bytes the server claims are in the whole message — it says nothing about `uncompressedSize`, a separate 4-byte value inside the `OP_COMPRESSED` sub-header (`CompressedHeader`, parsed after `MessageHeader`), which is fully decoupled from how many bytes were actually received.

## Impact

A malicious or compromised server (or a MITM on a connection not using TLS — a supported, non-default-enforced configuration) can send a tiny, otherwise-valid `OP_COMPRESSED` reply that declares `uncompressedSize = Integer.MAX_VALUE` (2,147,483,647). Two distinct failure modes result, neither guarded against:

1. **Negative value** (e.g. `-1`): `ByteBuffer.allocate(-1)` throws `IllegalArgumentException`. This is the exact input class GODRIVER-4135 was fixed to reject client-side in Go (there, the same input causes an unrecovered panic that crashes the whole process; in Java it's a catchable exception, so the blast radius is narrower, but it is still unvalidated attacker-controlled input reaching an allocation call with no defensive check — the same root-cause gap, just a less catastrophic manifestation in a memory-safe, exception-based runtime).
2. **Large positive value** (up to `Integer.MAX_VALUE`, ~2 GiB): `ByteBuffer.allocate(2147483647)` attempts to reserve ~2 GiB for a single buffer, **regardless of how many bytes were actually in the compressed message on the wire**. On a JVM with a heap smaller than that (the common case — default/typical heap sizes are far below 2 GiB in most deployed configurations), this throws `OutOfMemoryError`. `OutOfMemoryError` is a JVM `Error`, not an `Exception`; ordinary `catch (Exception e)` handling elsewhere in the connection-handling code does not catch it, so it is far more likely to propagate uncaught, destabilizing the JVM thread (and, depending on GC behavior under memory pressure at the moment of the attempted allocation, other threads/connections sharing the same JVM heap) — this is the client-crashing DoS impact class the driver's own Go counterpart was judged worth a dedicated, immediate fix for.

Both cases are triggerable with a single small reply per connection, require no authentication-bypass and no special privilege beyond controlling (or spoofing/MITM-ing) what the client's configured server endpoint answers with.

## Weakness

CWE-789 (Memory Allocation with Excessive Size Value) / CWE-1284 (Improper Validation of Specified Quantity in Input), reachable from an untrusted or compromised server response.

## Component / Version

- Repository: `mongodb/mongo-java-driver`
- Confirmed present at `driver-core/src/main/com/mongodb/internal/connection/CompressedHeader.java` and `InternalStreamConnection.java` on latest tag `r5.12.0` (the current release at the time of this audit, 2026-09-18) — both the synchronous read path (`InternalStreamConnection.java:1105`) and the asynchronous read path (`:1207`) share the same unguarded `getBuffer(compressedHeader.getUncompressedSize())` call.

## Why the sibling drivers differ

Checked every other official driver for the same "server-declared header field used directly for a decompression-buffer pre-allocation" pattern, as part of the same audit pass:

- **C driver (`mongoc-cluster.c:3501`)** — correctly bounds both directions before allocating: `uncompressed_size < 0 || uncompressed_size > max_msg_size - message_header_length`. This is the reference-correct implementation; the C++ and PHP-extension wire-protocol layers build on libmongoc and inherit this check.
- **Python driver (`network_layer.py:612,800`)** — correctly bounds both directions: `uncompressed_size <= 0 or uncompressed_size + 16 > max_message_size`.
- **Go driver (`compression.go`)** — as of GODRIVER-4135, bounds the negative case only; still unbounded above (reported separately in this audit as a sibling of its own fix).
- **Node.js, C#, Ruby, Rust drivers** — architecturally not exposed to this pattern at all: each decompresses first (letting the underlying compression library size its own output from the actual compressed bytes) and only afterward compares the result's length against the declared `uncompressedSize`/`header.length` as a post-hoc sanity check, so the untrusted field is never used to size an allocation up front.

Java is the one driver in the set with no bound in either direction.

## Suggested fix

Validate `uncompressedSize` where `CompressedHeader` is constructed, mirroring the C driver's check — reject negative values and anything exceeding the connection's negotiated `maxMessageSize` (already available as `description.getMaxMessageSize()` at the `InternalStreamConnection` call site, and already threaded through to `MessageHeader`'s constructor for exactly this kind of bound):

```java
CompressedHeader(final ByteBuf header, final MessageHeader messageHeader, final int maxMessageSize) {
    ...
    uncompressedSize = header.getInt();
    if (uncompressedSize < 0 || uncompressedSize > maxMessageSize) {
        throw new MongoInternalException(format(
            "The uncompressed message size %d is invalid or exceeds the maximum message size %d",
            uncompressedSize, maxMessageSize));
    }
    ...
```

## Suggested repro (static analysis only — not executed against a live server in this environment)

1. Stand up a rogue TCP listener speaking enough of the MongoDB wire protocol to complete a handshake a Java driver client accepts (or MITM a non-TLS connection).
2. Reply to any command with an `OP_COMPRESSED` message: valid original opcode, `compressorId = 2` (zlib), `uncompressedSize = 0x7FFFFFFF`, and a small valid zlib stream as the payload.
3. Observe `InternalStreamConnection` call `getBuffer(2147483647)` → `ByteBuffer.allocate(2147483647)` for that single, small reply, and (heap-size dependent) throw `OutOfMemoryError`.
4. For the negative case, repeat with `uncompressedSize = -1` and observe the unguarded `IllegalArgumentException` from `ByteBuffer.allocate(-1)`.

## Notes on scope

This finding, and the Go driver finding it was found alongside, are both fresh discoveries from cross-driver sibling-hunting of the recently-fixed GODRIVER-4135 pattern — not part of the originally reviewed CVE list, and not yet reported upstream. The C, C++, PHP Library, Python, Node.js, C#, Ruby, and Rust drivers were all checked for the same pattern in the same pass; only Go (partially) and Java (not at all) lack the bound.
