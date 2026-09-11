# Non-DoS sibling sweep, round 2 — SERVER-131202 (updateLookup injection) and SERVER-132125 (hybrid-search view injection)

Continuing the sibling hunt for the 8.3.9 non-DoS CVE batch, using the two Jira tickets you pasted
directly (both blocked-domain tickets I couldn't otherwise reach). Both led to real code, but
neither produced a second confirmed finding — reported honestly as such, plus one hypothesis
tested live and ruled out.

## SERVER-131202 — updateLookup `$match` injection via unescaped shard-key values

**The bug, as described in the ticket:** change streams' `updateLookup` mode injects a changed
document's `_id`/shard-key values straight into an internally-built `$match` expression with no
escaping. A shard-key value that's itself an object with `$`-prefixed keys (plausible if
CVE-2026-82060's insert-time validation gap let one get stored) gets reinterpreted as a query
operator, turning a point lookup into a multi-document lookup.

**Located and confirmed the fix in r8.3.9:**
`src/mongo/db/exec/agg/change_stream_add_post_image_stage.cpp:128-130`:
```cpp
boost::optional<Document> escapedKey;
if (containsDollarPrefixedFieldNamesOnTopLevel(documentKey)) {
    escapedKey = Document{convertDocumentIntoQuery(documentKey.toBson())};
}
```
using `escapedKey ? *escapedKey : documentKey` at the actual `lookupSingleDocument()` call. The
escaping functions (`convertDocumentIntoQuery`/`containsDollarPrefixedFieldNamesOnTopLevel`,
`src/mongo/s/commands/document_shard_key_query_conversion.{h,cpp}`) are a pre-existing, separately
tested utility — not new code written for this fix, just newly applied here.

**Sibling sweep:** the actual injection point — `AggregateCommandRequest aggRequest(nss, {BSON("$match"
<< documentKey)})` in `common_mongod_process_interface.cpp:885` — is reached only through the
`lookupSingleDocument()` interface method (as opposed to `lookupSingleDocumentLocally()`, a
different method). Traced every production caller of `lookupSingleDocument()` specifically:
`change_stream_add_post_image_stage.cpp` is the **only** one. The other two files that reference
`lookupSingleDocument` (`find_and_modify_image_lookup_stage.cpp`,
`change_stream_add_pre_image_stage.cpp`) both call `lookupSingleDocumentLocally()` instead, with
keys built from server-generated data (session/txnNumber, oplog timestamp/applyOpsIndex) — not
attacker/shard-key-influenced, so the injection precondition doesn't apply there regardless of
escaping.

**Conclusion: no live sibling.** The fix's single call site is the only production consumer of the
vulnerable construction; the fix is structurally complete for this exact mechanism as it exists in
r8.3.9.

## SERVER-132125 — `$_isHybridSearch` banned at top level to prevent view injection

**The bug:** `$_isHybridSearch` (aggregate command field, `stability: internal` — an IDL annotation
only, not a runtime restriction) told the server "trust that this pipeline is the pre-desugared
form of `$rankFusion`/`$scoreFusion`," skipping some processing. Setting it directly let an external
client claim that trust without it being true, related (per the ticket) to view injection.

**Fix located and verified comprehensive.** The enforcement:
`aggregation_request_helper.cpp:196-201` (`assertIsHybridSearchNotSetByClient`):
```cpp
uassert(13212500, "... is an unknown field",
        isInternalOrDirectClient(&client) || !aggregate.getIsHybridSearch().has_value());
```
Grepped every IDL struct carrying an `isHybridSearch`-shaped field — there are exactly three:
`aggregate_command.idl` (top level, the one above), `document_source_lookup.idl` ($lookup's own
embedded flag), `document_source_union_with.idl` ($unionWith's). Both of the latter two call a
shared `hybrid_scoring_util::validateIsHybridSearchNotSetByUser(expCtx, elem.Obj())` at the very
top of their `createFromBson()`, before their own IDL struct is even parsed
(`document_source_lookup.cpp:1108-1110`, `document_source_union_with.cpp:283-285`) — same
protection, applied to all three known locations.

**Conclusion: no live sibling for this exact field.** All three places this flag can appear are
covered. (This is consistent with SERVER-131917, the linked "audit command fields for
internal-only validation" ticket, having been a real, apparently-thorough sweep on MongoDB's side
— not evidence there's nothing left, just that this specific flag's story is closed.)

## Adjacent hypothesis tested live, ruled out: `$_translatedForViewlessTimeseries`

Sitting right next to `$_isHybridSearch` in the same IDL struct, with an analogous "trust me, this
already happened" shape (`db/query/timeseries/timeseries_translation.cpp:251`,
`run_aggregate.cpp:1088-1090`) but **no client-type check at all** — a real candidate for the same
bug class, since `stability: internal` alone provides no runtime protection (proven by the fact
`$_isHybridSearch` needed an explicit check despite already being so annotated).

**Tested directly against the real 8.3.9 binary:** created a native (`type: "timeseries"`)
collection, inserted documents with a `temp` measurement field, then sent
`{$_translatedForViewlessTimeseries: true}` on the top-level aggregate command as an ordinary
external client alongside a `{$match: {temp: 42}}` predicate that should only match correctly if
the pipeline gets properly translated to the bucket-internal schema when needed.

**Result: no observable difference from the untouched baseline** — same single correct document
matched, with or without the flag. Also tried it combined with an index `hint` (the other place
this flag is checked, to skip hint-rewriting) — got a normal `BadValue` for a nonexistent index,
no different behavior. This doesn't rule out every possible misuse of the flag, but the specific
"skip translation to bypass a query predicate" mechanism I hypothesized did not reproduce.
**Not reporting this as a finding — ruled out by direct empirical test, not just left unconfirmed.**

## Net result this round

One dead end each on two well-documented tickets (both fixes are structurally complete for the
mechanism described), and one plausible-looking sibling hypothesis tested live and disproven. No
new confirmed vulnerability this round — reporting the negative results honestly rather than
stretching any of these into a claim they don't support. The `$_internalOwningShard` finding from
the previous round stands as this engagement's confirmed result for the 8.3.9 CVE batch.
