# Pre-auth wire-protocol black-box fuzzing against a live local mongod (v8.3.8)

**Status: clean negative result across two rounds (~4,662 frames total). No crash, no
fatal/invariant/signal log entry, no memory blow-up. Documenting the setup, coverage, and
an honest scope caveat rather than treating "no crash" as "no bugs."**

## Setup

No route existed in this sandbox to build this repo's own HEAD (targets an unreleased
`9.0.0-alpha0`, pinned to a MongoDB-custom Bazel fork whose binary fetch URL is blocked by
this environment's egress proxy, same wall as `downloads.mongodb.org` and Docker Hub's blob
CDN — all confirmed via direct `curl`/`docker pull` 403s, not assumed). The user supplied a
real official generic-Linux build (`mongodb-linux-x86_64-ubuntu2204-8.3.8.tgz`, sha256
`af813f78...`) via their own `cybe4sent1nel/mongo_tar` repo. Extracted and ran it as a fully
local, disposable instance:

- `--bind_ip 127.0.0.1` only, dedicated scratch dbpath, port 27099, no exposure beyond this
  container.
- `--auth` not enabled, but irrelevant to what was tested: wire-protocol/BSON parsing runs
  identically before any auth check fires regardless of whether `--auth` is on, and the
  auth-negotiation commands (`saslStart`/`hello`) were fuzzed directly as their own category.
- No sanitizers, no source instrumentation — this is the vendor's stock release binary.

## What was fuzzed

Custom Python TCP client (`fuzz_wire.py`), one fresh connection per test case, monitoring
target liveness (`kill -0`) and the mongod log for fatal/signal/invariant markers after every
frame; any suspicious outcome saves the exact payload bytes for replay.

**Round 1 (574 frames):**
- OP_MSG: every flagBits combination incl. `checksumPresent`+bad CRC, lying declared message
  length (too big/small/negative/zero), invalid section-kind bytes, duplicate body sections,
  a doc-sequence with a lying declared size, a header claiming far more bytes than actually
  sent (partial-read handling).
- 12 malformed-BSON body variants reused across OP_MSG/OP_QUERY/OP_INSERT: truncated/negative/
  zero-length docs, unterminated field names, **5,000-level nested objects** (25x past the
  200-level limit), invalid type bytes, **garbage BinData(Column) control bytes** (direct hit
  on the BSONColumn parser audited earlier this session), huge BinData declared length vs.
  actual buffer, string-length/NUL mismatch, a **malformed CodeWScope embedded scope object**
  (the exact shape of SERVER-104907, found earlier this session), garbage array contents.
- Legacy OP_QUERY/OP_INSERT: extreme `ntoskip`/`ntoreturn` (`INT32_MIN`/`MAX`), unterminated
  namespace cstring, lying declared lengths.
- Unknown/negative/`INT32_MAX` opcodes; OP_COMPRESSED with bogus compressor IDs over an
  uncompressed inner payload.

**Round 2 (4,088 frames, deeper/adjacent surfaces):**
- OP_COMPRESSED with **genuine zlib-compressed payloads** but a lying `uncompressedSize`
  field (tiny/zero/`INT32_MAX`/negative), a truncated compressed stream, and a real **10MB
  zlib decompression bomb** (honestly declared size) — targets the decompression
  buffer-allocation path specifically, not just compressor-ID rejection.
- `saslStart`/`saslContinue`/`hello` (the actual pre-auth handshake commands): oversized
  BinData `payload` field, negative `conversationId`, malformed `compression` array, a
  300-level-nested `client` metadata sub-document.
- Doc-sequence (kind=1) section fuzzing: declared size 1 byte short of / far beyond actual
  content, 20 back-to-back sequences, unterminated sequence-identifier cstring.
- 4,000 further frames: random 1-6 byte mutations seeded from every case above.

## Result

Both rounds: target alive throughout, `0 suspicious event(s)` from the harness, and a
post-hoc `grep` across the full ~16k-line mongod log for `Fatal|invariant|abort|segv|
assertion` came back empty. Only ordinary startup warnings appear at `"s":"W"`. Memory
(171MB RSS) is back to idle-normal after the decompression-bomb case — no OOM, nothing in
`dmesg`. The message-length bounds check (`recv(): message msgLen ... Min 16 Max: 48000000`)
and the BSON validator's depth/type checks caught essentially everything at the door, and
the decompressor cleanly rejected every size-lie variant without over-allocating.

## Honest scope caveat

This is **black-box mutation fuzzing against an uninstrumented release binary**, not the
coverage-guided, sanitizer-instrumented fuzzing MongoDB's own `protocol_fuzzer`/libFuzzer
target (found earlier this session in `src/mongo/rpc/BUILD.bazel`) is built for. A release
binary without ASan/UBSan will often *not crash* on a small out-of-bounds read, a benign-looking
use of already-freed-but-not-yet-reused memory, or other subtle memory-safety issues — exactly
the class of bug this session's static audit *did* find twice (the H1-reported BSONColumn
depth-reset issue, and SERVER-104907's CodeWScope dummy-frame read), neither of which
reliably crashes an optimized release build even though both are real defects under a
sanitizer. So: **no reproducible pre-auth crash found**, but that's meaningfully weaker
evidence of absence than a sanitizer-instrumented run would be — worth stating plainly rather
than oversold.

## Assessment

A genuine, reasonably broad black-box campaign (~4,662 frames across every pre-auth wire
surface reachable without a build toolchain) against a real, disposable, local-only mongod
instance, with a clean result. Given the environment's build/download constraints, the
higher-yield next step for *this specific bug class* would be a source-level audit continuing
in the style that already found two real (if not-fresh) bugs this session, rather than more
black-box mutation volume against an uninstrumented binary.
