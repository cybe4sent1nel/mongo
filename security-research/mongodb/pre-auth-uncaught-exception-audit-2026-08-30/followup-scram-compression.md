# Follow-up pass: SCRAM message parsing + wire-compression decompression (2026-08-30)

Continuation of the same-day pre-auth uncaught-exception audit, after the fuzzing pass
(`README.md`) came back negative across ~112M pre-auth inputs. This pass targets two areas
*neither* the original static sweep nor the fuzzers meaningfully covered:

- The original static audit focused on IDL command-field deserializers and `std::sto*` call
  sites reachable via `Command::parse()`. It did not look inside the SASL/SCRAM conversation
  state machine itself, which parses attacker-controlled data in a different code path
  (`SaslSCRAMServerMechanism::stepImpl`), still fully pre-authentication (no successful login
  has occurred at any point during a SCRAM exchange).
- The raw-byte mutation fuzzers (fuzzA/B/C) send effectively random bytes; the probability of
  random mutation producing a validly-framed `OP_COMPRESSED` envelope wrapping a payload that's
  even superficially plausible to a real zstd/zlib/snappy decoder is negligible. So the
  decompression path was fuzzed in name only — worth a direct static look.

## SCRAM message parsing (`sasl_scram_server_conversation.cpp`)

Traced `_firstStep`/`_secondStep` (parse `client-first-message` / `client-final-message` per
RFC 5802) field-by-field. Every substring extraction is preceded by an explicit `.find()`/
`.rfind()` bounds check or a `.size() <` guard before any `.substr()`/indexing — no unchecked
slice. `absl::StrSplit` is used for the comma-delimited fields, which cannot throw. No raw
`std::sto*` calls anywhere in this file.

**`base64::decode(proof)`** (the `ClientProof` field, fully attacker-controlled arbitrary bytes
post-base64-decode) was the most promising lead — `base64_detail::decodeImpl` throws via
`uassert(10270, ...)` / `uassert(40537, ...)` on malformed length or invalid characters. Both are
`uassert`, which produce `DBException`, not a raw C++ exception type — so unlike the known
`MemorySize::parse()` bug (raw `std::invalid_argument`/`std::out_of_range` from `std::stod`),
this cannot slip past a `catch (const DBException&)`, and it's caught cleanly at the top-level
command dispatch regardless. Not exploitable under this bug class.

## SCRAM crypto internals (`mechanism_scram.h`)

`Secrets::verifyClientProof()` takes the base64-decoded `ClientProof` (arbitrary attacker-chosen
length after decode) and passes it to `HashBlock::fromBuffer(ptr, len)`
(`crypto/hash_block.h:151`), which explicitly checks `inputLen != kHashLength` and returns
`Status(ErrorCodes::InvalidLength, ...)` **before** any `memcpy` — confirmed against the same
pattern in `sha1_block_test.cpp`/`sha256_block_test.cpp`/`sha512_block_test.cpp`. The result is
wrapped in `uassertStatusOK`, so a length mismatch is a clean `DBException`, not an OOB
memcpy and not a raw exception. Same for `verifyServerSignature`'s explicit `sig.size() !=
HashBlock::kHashLength` check before any comparison. No memory-safety bug, no uncaught-exception
bug.

## Wire-compression decompression (`transport/message_compressor_{zstd,zlib,snappy}.cpp`)

`MessageCompressorManager::decompressMessage()` (`message_compressor_manager.cpp:99`) allocates
the output buffer from the attacker-supplied `compressionHeader.uncompressedSize`, after checking
it's non-negative and under `maxMessageSize`, then hands a `DataRange` bounded to exactly that
buffer to the codec. Checked each codec's actual decompress call for whether it honors that bound
regardless of what the compressed data claims/decodes to:

- **zstd**: `ZSTD_decompress(dst, dstCapacity, src, srcSize)` — the bounded one-shot API; it
  errors (`ZSTD_isError`) rather than overflowing if the frame would need more than
  `dstCapacity`. Safe.
- **zlib**: `::uncompress(dst, &destLen, src, srcLen)` where `destLen` is pre-set to
  `output.length()` — zlib's `uncompress()` respects `*destLen` as the buffer capacity and
  returns `Z_BUF_ERROR` rather than overflowing. Safe. (Also independently validates the RFC1950
  header's `CMF`/`FLG` checksum before calling into zlib at all.)
- **snappy**: explicitly calls `GetUncompressedLength()` first and requires an *exact* match
  against `output.length()` before calling `RawUncompress()` — if the compressed data's declared
  length doesn't exactly equal the pre-allocated buffer, it's rejected before decompression runs
  at all. Safe.

All three are one-shot, capacity-bounded native APIs, correctly wired to the pre-validated output
buffer. No OOB write found.

## Net result

No new finding. This pass specifically targeted two structurally distinct pre-auth surfaces that
the original static sweep and the dynamic fuzzing campaign did not meaningfully exercise, and both
came back clean for the same reasons the rest of the tree has: consistent use of `Status`/
`uassert` (not raw exceptions) and explicit length checks before any unchecked memory operation.

Combined with the original audit and ~112M fuzzed pre-auth inputs with zero crashes, this
continues to be a genuine negative result, not a partial one.
