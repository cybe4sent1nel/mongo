# mongo-java-driver: pre-auth response parsing audit (OP_COMPRESSED, SCRAM/SASL)

**Status: clean negative result for the exact bug class found in the Go driver. The Java
driver's architecture deliberately defends against it. One minor robustness/code-quality
observation noted, not a security bug.**

## What was checked

Same bug shape as the confirmed Go driver finding (see
`../go-driver-2026-08-28/decompress-negative-size-panic.md`): does an attacker-controlled,
unvalidated length field from an `OP_COMPRESSED` reply, or from the SCRAM authentication
conversation, reach an allocation/parse operation in a way that crashes the process rather
than producing a catchable error?

### OP_COMPRESSED decompression (`InternalStreamConnection.java`)

- `CompressedHeader`'s constructor (`CompressedHeader.java`) reads `uncompressedSize` as a raw
  `int` off the wire with **no validation** — same as Go.
- `receiveResponseBuffers` (sync path, line ~1097) and `MessageCallback.onResult` (async path,
  line ~1199) both do `uncompressedBuffer = getBuffer(compressedHeader.getUncompressedSize())`
  — passing the attacker-controlled value straight into a buffer allocation, same as Go.
- **But**: both call sites sit inside a `catch (Throwable t)` that wraps the *entire*
  receive-and-decompress sequence (`receiveResponseBuffers` line 1112; the async
  `MessageCallback` line 1217). This is deliberate, documented design:
  `rethrowIfError(Throwable)` (line 998, sync path) explicitly re-throws only genuine JVM
  `Error`s (e.g. `OutOfMemoryError`) unchanged, while everything else — including
  `NegativeArraySizeException`/`IllegalArgumentException` from a bad allocation size — gets
  translated into a normal, catchable `MongoException` via `translateReadException`. The
  connection is closed first (`close()`), then the translated exception propagates as an
  ordinary application-visible error, not a JVM crash.
- Also checked `MessageHeader`'s constructor: it validates `messageLength > maxMessageLength`
  but does **not** reject a negative or too-small `messageLength`. This looked like a possible
  second angle (a negative `messageLength` flowing into
  `stream.read(messageHeader.getMessageLength() - MESSAGE_HEADER_LENGTH, ...)`), but it lands
  inside the exact same broad `catch (Throwable t)` in `receiveResponseBuffers`, so it resolves
  the same way — a translated `MongoException`, not a crash.

Net: this is architecturally different from (and safer than) the Go driver's model. Go's
unrecovered panic kills the whole process by language design; Java's unchecked exceptions are
just exceptions, and this driver's read path is deliberately wrapped broadly enough to catch
them (while still correctly *not* swallowing real `Error`s like OOM, which should propagate).

### SCRAM/SASL parsing (`ScramShaAuthenticator.java`, `SaslAuthenticator.java`)

- `parseServerResponse` (`ScramShaAuthenticator.java:290-298`) splits the server's
  comma-separated SCRAM response and does `pair.split("=", 2)` per entry, then unconditionally
  indexes `parts[0]`/`parts[1]`. **A malicious server sending a key/value pair with no `=` at
  all (e.g. `"foo,r=abc,s=def,i=4096"`) makes `"foo".split("=", 2)` return a 1-element array,
  and `parts[1]` throws `ArrayIndexOutOfBoundsException`.** Likewise `computeClientFinalMessage`
  (line 199-218) calls `.startsWith()` on `map.get("r")` and `Base64.getDecoder().decode()` on
  `map.get("s")` with no null-check — a response missing the `r` or `s` key throws
  `NullPointerException` instead of a clean protocol error. This is genuinely reachable by an
  unauthenticated, malicious/MITM server crafting the SCRAM server-first-message during the
  live authentication exchange.
- **But**: every `evaluateChallenge(...)` call site in `SaslAuthenticator.java` (lines 82, 94,
  145, 158, 189, 356) sits inside a `catch (Exception e)` (line 101) or `catch (Throwable t)`
  (line 120, the async entry point) that wraps the whole conversation loop and converts the
  result via `wrapException(e)` into a normal driver exception delivered to the caller (sync:
  thrown from `authenticate()`; async: delivered via the `callback.onResult(null, t)` error
  path). `ArrayIndexOutOfBoundsException`/`NullPointerException` are ordinary `RuntimeException`
  subclasses, so both catches apply.

Net: same story — reachable malformed input, but converted to a normal catchable error rather
than an unhandled crash, thanks to broad exception handling already in place at the
conversation-orchestration layer.

## Minor observation (not a security finding)

`parseServerResponse` throwing a raw `ArrayIndexOutOfBoundsException`/`NullPointerException`
instead of a purpose-built `SaslException` with a clear message ("malformed SCRAM response:
missing required field") is a code-quality/debuggability gap, not a vulnerability — the
exception is still caught and wrapped, so behavior is safe, just less informative for whoever
has to diagnose a connection failure caused by a broken/hostile server. Not written up as a
finding in its own right; mentioning it here for completeness since it's the same code path
being audited.

## Conclusion

The Java driver does not share the Go driver's vulnerability. Its layered, deliberate
exception-handling design (broad catches at both the connection-read layer and the
auth-conversation layer, with an explicit, documented distinction between recoverable
`Exception`s and fatal JVM `Error`s) absorbs exactly the kind of malformed-length/malformed-field
input that crashes the Go driver outright. No pre-auth crash found in the Java driver for this
bug class.
