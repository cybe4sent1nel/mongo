# mongo-go-driver: generic BSON decode (`bson.M`/`bson.D`/`interface{}`) — unbounded recursion → uncatchable stack overflow

Sibling-bug hunt triggered by three HackerOne triage outcomes on the same bug class
(`mongo-csharp-driver` #3996918, Duplicate of #3790290, High 7-8.9 — confirms the class is
real and paid; `bson-rust` #3996627, Informative; `mongosh` OIDC issue, Informative,
unrelated class). `mongo-c-driver` was checked first and is **clean**: `bson_validate()`
and `bson_as_json`/`bson_as_canonical_extended_json` both explicitly thread a depth
parameter (`BSON_VALIDATION_MAX_NESTING_DEPTH`, `BSON_MAX_RECURSION = 200`) through their
recursive walks — confirming the earlier PHP-driver finding's own conclusion that the bug
lives in each language binding's *own* glue code, not in libbson itself.

`mongo-go-driver` (tag `v2.9.0`, commit `099a81f05c5`) is **not** clean: decoding into
`bson.M`, `bson.D`, or `interface{}` — the standard way to consume ad-hoc query results
without a fully-typed Go struct — recurses through `mapCodec`/`dDecodeValue`/
`emptyInterfaceCodec` with zero depth tracking anywhere on `DecodeContext`. Confirmed
empirically: a 16MB BSON document nested 2,000,000 levels deep (`{"a":{"a":{"a": ...}}}`,
8 bytes/level) crashes `bson.Unmarshal(data, &result)` (the same code path
`Cursor.Decode`/`Cursor.All` use on every query result) with a genuine, unrecoverable Go
`fatal error: stack overflow` (exit code 2) — not a `panic`, so `recover()` cannot catch it.
The identical crash reproduces for array-nesting too (`sliceCodec`, same missing-depth
architecture), confirmed as an independently-triggered second variant.

This is distinct from the previously-reported `mongo-go-driver` extJSON finding
(`extjson-array-nesting-depth-bypass-2026-08-30`) — that one is about the *text*
Extended-JSON parser's `maxNestingDepth` check applying to objects but not arrays. This
finding is about the **binary BSON wire-format decode path**, which the extJSON fix does
not touch and which has no depth tracking of any kind, for either objects or arrays.

See `HACKERONE-REPORT.md` for the full write-up, code citations, and impact analysis.
`main.go` is the PoC source (O(depth) flat-buffer construction, `doc`/`array` mode
argument); `poc_output_doc.txt`/`poc_output_array.txt` are the raw crash traces from both
variants.

## Sibling status across the other drivers checked in this pass

- **mongo-c-driver**: clean (see above) — `security-research/mongo-c-driver/` has no
  separate note since this was a negative result on the specific class being hunted, not a
  new finding.
- **mongo-python-driver**: not yet checked for this specific class (existing note in that
  directory covers a different bug, `OP_COMPRESSED` decompression bomb).
- **mongo-tools**: its own `mongoimport --legacy` finding is the *text* JSON path
  (`common/bsonutil`), a different code path from this one; its handling of real binary
  `.bson` files (`bsondump`, `mongorestore` against non-JSON dumps) goes through this exact
  `mongo-go-driver` `bson` package it vendors, so it very likely inherits this same crash —
  not independently re-verified against a `mongo-tools` binary in this pass since the root
  cause and reachability are already fully established against the driver itself.
