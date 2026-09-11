# mongos + mongod r8.3.8 — live pre-auth crash/DoS hunt (negative result)

**Status: no crash found.** This documents a live-binary campaign against the real `8.3.8` server
(from `cybe4sent1nel/mongo_tar`'s `mongodb-linux-x86_64-ubuntu2204-8.3.8.tgz`), continuing from a
static-analysis lead that did NOT survive live testing (see the retraction note below), then
extended from `mongod` to `mongos` specifically.

## Setup

- `mongod` standalone, `--dbpath ... --port 27017 -vv` (verbosity 2, to also exercise debug-only
  log lines).
- A minimal real sharded topology: one-node config server replica set (`mongod --configsvr
  --replSet cfgrs --port 27019`, initiated via `replSetInitiate`), then `mongos --configdb
  cfgrs/127.0.0.1:27019 --port 27020 -vv`. No shards added — sufficient for testing `mongos`'s own
  pre-auth wire-ingest and command-dispatch layer, which is what was in scope.
- All testing done with raw TCP sockets (no driver), i.e. genuinely pre-authentication.

## Retracted lead: unguarded `jsonStringGenerator()` recursion

A static-analysis pass had concluded that MongoDB's `BSONObj`/`BSONElement::jsonStringGenerator()`
(used by the default JSON log formatter, e.g. the "Slow query" log line) has no recursion-depth
guard, and that nothing on the request-ingest path validates BSON nesting depth before a command
reaches that logging path — implying a ~2,000-level-deep pre-auth `ping` (fits in ~16KB, under the
pre-auth message-size cap) could stack-overflow a connection thread (deliberately sized to exactly
1MB, `service_executor_utils.cpp:80-81`).

**Live-tested against the real binary: the payload was rejected before it ever reached command
dispatch.** `mongod`'s log showed:
```
"ex":"Overflow: BSONObj exceeds maximum nested object depth in element with field name 'x.a.a...'"
```
Root cause of the static-analysis miss: `src/mongo/rpc/op_msg.cpp:184` reads the OP_MSG body as
`sectionsBuf.read<Validated<BSONObj>>()`. `Validated<T>` is a generic template whose real validator
hides behind a specialization in `src/mongo/rpc/object_check.h`:
```cpp
template <> struct Validator<BSONObj> {
    inline static Status validateLoad(const char* ptr, size_t length) {
        if (!serverGlobalParams.objcheck) return Status::OK();
        return validateBSON(ptr, length);   // the depth-checked validator (bson_validate.cpp)
    }
};
```
`serverGlobalParams.objcheck` defaults to `true`, so every incoming OP_MSG command body — on both
`mongod` and `mongos`, since `op_msg.cpp` is shared — is depth-validated by default at
`BSONDepth::kDefaultMaxAllowableDepth` (200), well below what the jsonStringGenerator scenario
needed. The original static grep for `validateBSON(` missed this indirect, template-specialization
call site. `jsonStringGenerator()` itself is still unguarded as dead code, but it is not reachable
with attacker-controlled depth in practice, because nothing that deep survives ingest.

## Structural malformed-message battery (28 tests) — both `mongod` and `mongos`, all survived

Legacy opcodes (OP_QUERY/UPDATE/INSERT/GET_MORE/DELETE/KILL_CURSORS/REPLY), header corruption
(zero/negative/oversized/undersized `messageLength`, unknown opcodes), OP_MSG malformations
(reserved flag bits, checksum-bit-without-checksum, unknown section kinds, duplicate body
sections, oversized/unterminated document-sequence fields), and OP_COMPRESSED malformations
(bad compressor IDs, negative/zero/huge declared `uncompressedSize`, garbage compressed payloads,
a nested-compression trick setting `originalOpCode` to `dbCompressed` itself to probe for
re-entrant-decompression mishandling). `OP_QUERY`/`OP_GET_MORE` return real (error) responses —
traced to a deliberate, explicit rejection (`"OP_QUERY is no longer supported"`,
`service_entry_point_shard_role.cpp:2406-2408`), not a gap.

## Mutation fuzzing campaigns — no crash

- `mongod`: 355,280 mutated OP_MSG messages over 4 minutes, focused on `BinData` subtype 7
  (**Column** encoding — confirmed via code reading that `validateBSON()`'s default mode dispatches
  into `ColumnValidator::doValidateBSONColumn()`, `bson_validate.cpp:717`, for *any* BinData(Column)
  field in *any* command body, pre-auth), plus other BinData subtypes and whole-message byte flips.
- `mongos`: 214,520 mutated `find` command bodies over 150 seconds, specifically mutating the
  sharding-routing metadata fields `mongos` parses that `mongod` never sees
  (`$readPreference`, `shardVersion`), plus the same BinData(Column) mutation.
- RSS stayed flat throughout on all three processes (`mongod` 216MB, configsvr 239MB, `mongos`
  90MB) — no memory leak surfaced either.

## Code-level checks that ruled out the obvious bug shapes before/alongside fuzzing

- `Cursor::skip()` (`bson_validate.cpp:473`): `(ptr += len) < end` is safe against a `uint32_t`
  attacker-controlled `len` — can't wrap a 64-bit pointer, so oversized lengths are rejected by the
  post-addition comparison rather than exploited.
- `numSimple8bBlocksForControlByte()` caps block count at 16 — no overflow room in the derived
  buffer-size arithmetic.
- Compression decompress (`ZSTD_decompress`, zlib `uncompress()`) both take the allocated output
  buffer's real size as a hard bound (memory-safe library APIs), and that buffer's size is itself
  capped against `gPreAuthMaximumMessageSizeBytes` before allocation — closes off a
  compression-bomb OOM.
- `decompressRequest()` (`session_workflow.cpp:632`) decompresses at most once per work item, no
  loop — a nested/re-labeled `dbCompressed` payload doesn't get re-entered.
- `ClientMetadata::parse` has real size caps (`kMaxApplicationNameByteLength=128`, a document-size
  ceiling) checked before use.
- `mongos`'s own command-dispatch logging (`strategy.cpp`) never logs a full raw command body the
  way `mongod`'s `OpDebug::report` does — only command names, exceptions, or db/headerId — so the
  (already-closed) `jsonStringGenerator` lead doesn't reopen on the `mongos` side either.
- `checkForHTTPRequest` (`asio_session_impl.cpp:1041`) is TLS-handshake-path-only in this build
  (no TLS configured in this lab) and is trivially bounds-checked regardless.

## Assessment

This corner of `r8.3.8` — wire ingest, BSON/BSONColumn validation, and both `mongod`'s and
`mongos`'s pre-auth command-dispatch entry points — held up against ~570,000 combined fuzzed
messages and a systematic malformed-message battery on the real binary, plus manual code review of
every bounds-check-shaped concern that came up along the way. This is consistent with it being the
part of the codebase MongoDB's own continuous fuzzer (`src/mongo/rpc/protocol_fuzzer.cpp`, which
calls this exact `validateBSON()` path) has been exercising the longest and hardest.

## Round 2: real sharded topology + SCRAM/SASL handshake

Extended the lab to a genuine (if minimal) sharded cluster: one-node config server replica set
(`cfgrs`, port 27019), one-node shard replica set (`shard1rs`, port 27021, added via `addShard`),
`mongos` on 27020. Sharded a real collection (`testdb.testcoll`, shard key `k`) with a manual
chunk split, so `shardVersion`/`databaseVersion` routing metadata is genuinely live rather than
theoretical.

**Important scope correction:** `shardVersion`/`databaseVersion` are attached to (and validated
on) data-bearing commands like `find` — none of which are on the actual pre-auth-allowed command
list (`hello`/`isMaster`, `ping`, `buildInfo`, `saslStart`/`saslContinue`, `authenticate`,
`getnonce`, `logout`, `endSessions`). This lab has no `--auth` configured (deliberately, to make
raw-socket testing straightforward), so every command including `find` was reachable without
credentials *in this lab* — but on a real, properly-configured deployment, `find` requires
authentication first. So the shard-version/chunk-routing surface tested below is **post-auth /
cluster-aware**, not pre-auth, despite being reachable unauthenticated in this specific sandbox.
Flagging this now rather than letting the "pre-auth" framing carry over incorrectly.

- Captured the real wire shape of `shardVersion` (`{e: ObjectId, t: Timestamp, v: Timestamp}`) and
  `databaseVersion` (`{uuid: Binary, timestamp: Timestamp, lastMod: int}`) directly from a live
  request in the shard's own log (verbosity already high enough to show full command args).
  Built a realistic base `find` document with `bson.encode()` (avoids hand-rolled BSON bugs in the
  fuzzer itself) and mutated it.
- 126,120 mutated `find`+shardVersion/databaseVersion messages sent **directly to the shard
  `mongod`** (27021, bypassing `mongos` entirely) — no crash.
- Same campaign against `mongos` (27020) — no crash.

**SCRAM/SASL handshake** (genuinely pre-auth — `saslStart`/`saslContinue` are on the allowed-before-auth
list on both `mongod` and `mongos`):

- Read `src/mongo/db/auth/sasl_scram_server_conversation.cpp`'s GS2-header and SCRAM
  message-parsing code end to end (`_firstStep`/`_secondStep`) — every `substr()` call operating on
  attacker-controlled offsets is preceded by an explicit length/prefix check (e.g.
  `authzId.starts_with("a=")` before `authzId.substr(2)`, `input[0].size() < 3` before
  `input[0].substr(2)`) — no unguarded `substr`/`rfind`/`find` arithmetic found. `std::string::npos`
  arithmetic (`gs2_cbind_comma + 1` when `gs2_cbind_comma == npos`) wraps to `0`, which is a
  well-defined, safe `substr`/`find` starting position, not an OOB read — checked this explicitly
  since it's the classic shape of bug in hand-rolled protocol parsers.
- Read `HashBlock::fromBuffer()` (`src/mongo/crypto/hash_block.h:159`) — the base64-decoded
  `ClientProof` from `saslContinue`'s final step is length-validated (`inputLen != kHashLength`
  rejected) *before* the `memcpy` into the fixed-size hash buffer in `verifyClientProof()`
  (`mechanism_scram.h:244`) — closes off the "attacker sends a too-short/too-long base64 proof to
  under/overflow a fixed HMAC buffer" bug shape before it was ever fuzzed.
- Fuzzed anyway: 123,780+ mutated `saslStart`/`saslContinue` messages (mutated mechanism names,
  mutated GS2/SCRAM payload strings — malformed comma counts, missing fields, oversized
  usernames/nonces, invalid base64 in the proof field, negative/huge `conversationId` values) against
  both `mongod` and `mongos` — no crash, consistent with the code review above.

## What this pass did not cover (candidates for continuing)

- Much longer / coverage-guided fuzzing (this was minutes, not hours) — blind random mutation is
  a weak tool against a target this well-validated; a grammar-aware or coverage-guided fuzzer would
  likely need to run substantially longer to find anything new here.
- The SASL/authentication handshake state machine specifically (`saslStart`/`saslContinue`
  mechanism negotiation, SCRAM implementation) — not fuzzed this round; different code shape
  (stateful, base64-decoding, mechanism-specific) than the BSON-structural surface covered above.
- `mongos`-specific routing/targeting logic with actual shards registered (this lab had zero shards
  — `find` on an unsharded db returned empty rather than exercising real shard-targeting code); a
  bug in stale-shard-version retry handling or chunk-routing logic would need a real 2+-shard
  topology to reach.
- Internal-command-exposure angle on `mongos` (commands meant to be internal-cluster-only,
  reachable from an external client without proper `isInternalClient` gating) — not investigated
  this round; a different bug class (auth-bypass-adjacent) than crash/DoS, but worth a dedicated
  pass given `mongos` has ~57 command files and only a handful were read here.
