# Lead: residual race in BigSimplePolygon's lazy border caches (SERVER-130117)

> **Recovery note (2026-08-28):** reconstructed verbatim after the working container was recycled
> before a successful push. The stress test against this lead **did** complete before the reset —
> see `RESULTS.md` in this directory for the outcome (negative: no crash, no result mismatch across
> ~8,700 concurrent iterations over 90s).

**Status before this pass:** static-only. This document is the plan; `RESULTS.md` in this
directory carries the live outcome.

## Background — what's already fixed

`0ea3713b31` (`SERVER-130117`, ancestor of `r8.3.8`) fixed a genuine heap-use-after-free-shaped
data race in `src/mongo/db/geo/big_polygon.cpp`. `BigSimplePolygon` represents a polygon whose area
exceeds a hemisphere (2π steradians) — the "big polygon" case in MongoDB's S2-based geospatial
support, entered when a `$geometry` polygon (in `$geoWithin`/`$geoIntersects`) is large enough, or
wound such, that S2 treats it as covering "more than half the globe."

`Contains()`/`Intersects()` against such a polygon lazily materialize and cache an `S2Polygon`
(`_borderPoly`) or `S2Polyline` (`_borderLine`) border representation on first use
(`GetPolygonBorder()`/`GetLineBorder()`, pre-fix). The fix's own comment states the real
mechanism: **S2's internal edge index mutates shared state (`query_count_`) on every spatial
query**, even ones that only look "read-only" (`const` methods) at the C++ signature level — so
two threads concurrently calling e.g. `Contains()` against the *same* `BigSimplePolygon` instance
race on (a) the lazy-init of `_borderPoly`/`_borderLine` themselves, and (b) S2's own internal
mutable query-count state inside the already-constructed border objects. The fix wraps every
access (including `Invert()`, which mutates `_loop`/`_isNormalized` directly) in a new
`stdx::mutex _borderMu`.

## Reachability question this pass is for

A `BigSimplePolygon` object only becomes a concurrency hazard if the **same instance** is actually
shared and queried across concurrent operations, rather than being freshly constructed per-request.
Static reading alone can't settle which real, ordinary-user-reachable query patterns cause that
sharing — plausible candidates, in descending order of how directly they'd need to be confirmed:

1. **The query planner's plan cache.** If a cached `SolutionCacheData`/index-bounds structure for a
   `$geoWithin`/`$geoIntersects` query against a big polygon retains a `BigSimplePolygon` (or a
   wrapping `S2Region`) that's reused across subsequent, *concurrently executing* invocations of the
   same cached plan (multiple client connections running the same shape of geo query
   simultaneously), that's the most direct path to the race — and it's reachable by any ordinary
   `find`-privileged user, no special setup beyond a collection with a 2dsphere index and a
   sufficiently large/antimeridian-crossing polygon literal in their query.
2. An index bounds object computed once per index and shared read-only across concurrent query
   executions against that index, if geo index bounds intersection also goes through
   `BigSimplePolygon`.
3. A single aggregation/query execution that itself runs concurrent sub-operations against the same
   polygon object (e.g. a parallelized collection scan) — same instance, same thread-safety
   requirement, but within one client's own request rather than across clients.

## Reproduction plan

1. Stand up a standalone `mongod` (no cluster needed — this is pure query-execution-layer
   concurrency, not sharding/replication-specific).
2. Create a collection with a `2dsphere` index and enough documents that a `$geoWithin` query
   against a big (>1 hemisphere) or antimeridian-crossing polygon literal is expensive enough to
   keep many concurrent executions actually overlapping in wall-clock time (not resolving too fast
   to ever interleave).
3. Fire a sustained storm of concurrent connections (tens to low hundreds), each repeatedly running
   the *identical* `$geoWithin`/`$geoIntersects` query shape against the *same* big-polygon literal,
   for long enough to give the plan cache a chance to actually get hit repeatedly by concurrent
   executions (a single cold run per connection wouldn't necessarily reuse a cached plan/instance;
   sustained repetition per connection is the point).
4. Watch for: a crash (SIGSEGV, most direct confirmation), an ASAN-style corruption signal (not
   available without a debug/ASAN build, which this pass doesn't have — the official release binary
   under test is not instrumented), or — short of an outright crash — visibly wrong/inconsistent
   query results across concurrent runs (a softer signal that the shared object's internal state
   really is being raced on, even if it doesn't segfault this run).
5. Given this is inherently probabilistic (a data race, not a deterministic bug), a negative result
   (no crash observed) is much weaker evidence of "fixed and no residual gap" than the positive
   confirmations elsewhere in this program — recorded honestly as such either way.

## Query used

```js
db.pts.aggregate/find({
  loc: {
    $geoWithin: {
      $geometry: {
        type: "Polygon",
        crs: {type: "name", properties: {name: "urn:x-mongodb:crs:strictwinding:EPSG:4326"}},
        coordinates: [[[-170,-80],[170,-80],[170,80],[-170,80],[-170,-80]]]
      }
    }
  }
})
```
The `crs` name `urn:x-mongodb:crs:strictwinding:EPSG:4326` (`geoparser.h`'s `CRS_STRICT_WINDING`)
is what routes parsing to `BigSimplePolygon` (`geoparser.cpp`'s `parseGeoJSONPolygon`, `crs ==
STRICT_SPHERE` branch) rather than the ordinary `S2Polygon` path — confirmed by reading the parser
before constructing this query, not guessed.

## What a positive finding would look like

A crash, an inconsistent/wrong result across concurrent identical queries that only appears under
concurrency (never under sequential re-runs of the same query), or any other observable symptom of
the same class of race the fix targeted — surviving after the mutex fix is supposed to have closed
it, implying either a code path that doesn't take `_borderMu` or a construction that shares a
`BigSimplePolygon` instance somewhere the fix's audit didn't cover.
