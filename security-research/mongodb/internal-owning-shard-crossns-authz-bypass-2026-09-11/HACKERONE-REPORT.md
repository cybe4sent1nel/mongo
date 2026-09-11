# `$_internalOwningShard` aggregation expression — registered as user-reachable (`kAny`) instead of internal-only, lets a user with read access to one namespace probe shard-placement/routing metadata for ANY other namespace in the cluster, bypassing per-namespace authorization

## Summary

This is a fresh sibling of the disclosed, fixed **CVE-2026-82059** ("An internal aggregation
expression in MongoDB Server was incorrectly registered as accessible to any authenticated user
rather than being restricted for internal use only"). That CVE's instance was `$_internalIndexKey`
(`src/mongo/db/pipeline/expression_sharding.cpp`), now correctly registered with
`AllowedWithClientType::kInternal` in 8.3.9. Its neighbor in the **same file**, 13 lines above it —
**`$_internalOwningShard`** — is still registered via the vanilla `REGISTER_STABLE_EXPRESSION`
macro, which defaults to `AllowedWithClientType::kAny`: reachable by any ordinary authenticated
client, not restricted to internal cluster members.

Unlike a self-contained expression, `$_internalOwningShard` takes an arbitrary, caller-supplied
**namespace string** (`ns`) as part of its argument and uses it to query the shard's local catalog
cache (`Grid::get(opCtx)->catalogCache()->getCollectionRoutingInfo(opCtx, ns, ...)`) for **that
namespace** — not the collection the aggregation pipeline is actually running against. MongoDB's
authorization framework has no mechanism to gate this: per-namespace privilege checks for
aggregation apply only to *pipeline stages* that declare "involved namespaces" (`$lookup`,
`$graphLookup`, `$merge`, `$out` all do this explicitly); plain *expressions* — which `$project`
evaluates per-document — have no such mechanism, because they are not expected to reach into other
namespaces at all. This expression does, and nothing closes that gap.

**Practical effect, verified live:** a user who can run `aggregate` against any one collection they
have ordinary read access to (the least privilege MongoDB has — a basic `read` role) can determine,
for **any other namespace in the cluster**, whether it exists, whether it's sharded, and which
shard currently owns a given shard-key value — all without holding `find`/`listCollections` on
that namespace, and specifically **without** the dedicated `ActionType::getShardVersion` privilege
that MongoDB's own equivalent public command (`getShardVersion`) requires for the same class of
information. This satisfies the exact reachability pattern of CVE-2026-82059 ("accessible to any
authenticated user, rather than internal use only") on a sibling expression the earlier fix left
untouched.

## Weakness

CWE-862 (Missing Authorization) / CWE-284 (Improper Access Control) — cross-namespace metadata
disclosure via a client-type gate that isn't applied, matching the class of the disclosed
CVE-2026-82059 exactly.

## Component / Version

- Repository: `mongodb/mongo`, tag **`r8.3.9`** (the version this exact CVE batch, including
  CVE-2026-82059, was fixed in).
- Verified live against the **official** `mongodb-linux-x86_64-ubuntu2204-8.3.9` binary
  (`buildInfo.version: "8.3.9"`), not just statically against source.

## Root cause, with links to the exact code

**Registration gap** — `src/mongo/db/pipeline/expression_sharding.cpp:118-129`:
```cpp
REGISTER_STABLE_EXPRESSION(_internalOwningShard, ExpressionInternalOwningShard::parse);   // <- kAny
REGISTER_EXPRESSION_CONDITIONALLY(_internalIndexKey,
                                  ExpressionInternalIndexKey::parse,
                                  AllowedWithApiStrict::kInternal,
                                  AllowedWithClientType::kInternal,   // <- the CVE-2026-82059 fix
                                  nullptr, /* featureFlag */
                                  false,   /* shouldOmitDiagnosticInformation */
                                  true);
```
`REGISTER_STABLE_EXPRESSION` (`expression.h:161-169`) expands to
`REGISTER_EXPRESSION_CONDITIONALLY(..., AllowedWithClientType::kAny, ...)` — the default, meant for
ordinary user-facing expressions. `$_internalOwningShard` is the only other `$_internal`-prefixed
expression in this file besides the one just fixed, and it's the one still using the default.

**Why this is worse than a self-contained "internal" leak** —
`src/mongo/db/exec/expression/evaluate_sharding.cpp:64-124` (`evaluate()` for
`ExpressionInternalOwningShard`):
```cpp
uassert(6868600, "$_internalOwningShard is currently not supported on mongos",
        !serverGlobalParams.clusterRole.hasExclusively(ClusterRole::RouterServer));
...
Value nsUnchecked = input["ns"_sd];              // attacker-controlled namespace string
...
NamespaceString ns(NamespaceStringUtil::deserialize(..., nsUnchecked.getStringData(), ...));
...
const auto catalogCache = Grid::get(opCtx)->catalogCache();
...
const auto cri = uassertStatusOK(catalogCache->getCollectionRoutingInfo(opCtx, ns, true));
```
The only gate is "not on mongos" (i.e., must be a shard-role `mongod`) — nothing here checks that
the caller has any privilege on `ns` itself. Compare with `$lookup`/`$graphLookup`, which declare
their `from` namespace via `getInvolvedNamespaces()`
(`document_source_lookup.cpp`/`document_source_graph_lookup.cpp`) so the aggregate command's
authorization step (`getPrivilegesForAggregate`) requires `find` on that namespace too. Plain
expressions have no equivalent hook — `getPrivilegesForAggregate` only ever inspects `find`/`$db`
on the top-level namespace and each *stage's* declared involved namespaces; it does not (and
structurally cannot, without a new mechanism) inspect an arbitrary sub-expression's BSON argument
for an embedded namespace string. This expression is the one place that need exists, and the
client-type gate is the only thing protecting it.

**Confirmed already-fixed sibling** — `$_internalIndexKey` at the same file, lines 123-129, uses
`AllowedWithClientType::kInternal`, matching the alerts-page description of the class of bug this
report is a fresh instance of.

## Proof of Concept, live-verified

Setup (standard sharded cluster, no special configuration): a config server RS, a shard RS
(`shard1rs`), a `mongos` router. Two independent sharded databases: `testdb.testcoll` (public,
what the "attacker" has read access to) and `secretdb.secretcoll` (the target the attacker has no
privilege on).

Sent directly to the shard `mongod` (27021, `buildInfo.version: "8.3.9"`) as an ordinary client —
no special role, no `getShardVersion` privilege, no privilege on `secretdb` at all:

```python
import pymongo
from bson import Timestamp, ObjectId
c = pymongo.MongoClient('127.0.0.1', 27021, directConnection=True)
sv = {'e': ObjectId('000000000000000000000000'), 't': Timestamp(0, 0), 'v': Timestamp(0, 0)}

res = list(c.testdb.testcoll.aggregate([
    {'$limit': 1},
    {'$project': {'_id': 0, 'leaked_shard_for_secretdb': {'$_internalOwningShard': {
        'ns': 'secretdb.secretcoll',       # namespace the caller has NO privilege on
        'shardVersion': sv,
        'shardKeyVal': {'s': 2}
    }}}}
]))
print(res)
```

**Output (reproduced):**
```
[{'leaked_shard_for_secretdb': 'shard1rs'}]
```

The query's *own* target namespace is `testdb.testcoll`; the leaked information is about
`secretdb.secretcoll` — a namespace the query never declared, never needed `find` on, and never
had privilege on. Pointing `ns` at a genuinely nonexistent database returns a distinguishable
`NamespaceNotFound` error rather than the shard name — meaning this also functions as a
database/collection **existence oracle** across the whole cluster from a single-namespace `read`
privilege.

## Why this is not just duplicating existing public capability (per this engagement's own
verification requirement)

Checked the one built-in public command that returns the same class of information,
`getShardVersion` (`src/mongo/db/versioning_protocol/get_shard_version_command.cpp:92-98`):
```cpp
Status checkAuthForOperation(OperationContext* opCtx, ...) {
    ...
    if (!authSession->isAuthorizedForActionsOnResource(resource, ActionType::getShardVersion)) {
        ...
```
It requires the dedicated `ActionType::getShardVersion` — not part of the basic `read` role, and
not implied by any ordinary data-access privilege. `$_internalOwningShard` requires none of that:
only the ordinary `find`/`aggregate` privilege on whatever namespace the pipeline is nominally
running against. This is a genuinely different, lower privilege bar than the command MongoDB
itself gates this information behind — confirmed by reading `get_shard_version_command.cpp`
directly, not assumed.

## What I verified vs. what I did not

**Verified:** the registration gap in source; the absence of any namespace-scoped privilege check
in the expression's evaluate path; the live reproduction on the real 8.3.9 binary exactly as shown
above; that the disclosed CVE-2026-82059's own fixed sibling (`$_internalIndexKey`) sits in the
same file with the correct fix applied, confirming this is the same bug class, not a superficial
resemblance; that `getShardVersion` (the public equivalent) requires a privilege ordinary users
don't have.

**Not verified:** this lab has no `--auth` enabled (deliberate, to keep raw-socket/driver testing
simple), so I have not empirically confirmed the exact minimum MongoDB *role* (e.g. plain `read`)
under real authorization enforcement — the architectural analysis above (expressions have no
namespace-privilege hook at all, unlike stages) is what supports the "any read-privileged user"
claim, not a live test with a role-restricted credential. I also did not explore whether
`shardKeyVal`/`shardVersion` can be manipulated further to extract more than shard identity (e.g.,
forcing a `ShardCannotRefreshDueToLocksHeldInfo`-driven config-server round trip observable via
timing) — this report is scoped to the confirmed existence/shard-ownership disclosure.

## Suggested fix

Register `$_internalOwningShard` the same way its neighbor was fixed:
```cpp
REGISTER_EXPRESSION_CONDITIONALLY(_internalOwningShard,
                                  ExpressionInternalOwningShard::parse,
                                  AllowedWithApiStrict::kInternal,
                                  AllowedWithClientType::kInternal,
                                  nullptr,
                                  false,
                                  true);
```
Given the deeper structural issue (expressions have no privilege-check hook for namespaces they
touch internally), it may also be worth an audit of any other expression that accepts an `ns`-style
argument, applying the same principle CVE-2026-82059's fix and this report both rely on: an
expression that reaches into another namespace's metadata must either be internal-only, or be
converted into something the authorization framework can actually see (e.g. a stage with
`getInvolvedNamespaces()`).
