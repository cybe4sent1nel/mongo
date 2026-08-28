# mongos: audit for auth-bypass and code-injection bugs

**Status: no confirmed vulnerability found in this pass.** Chased the historically-relevant bug
classes for a sharding router to a concrete conclusion each, rather than a shallow pattern-match
pass. Setting expectations up front: `mongos` is ~14 years of continuously-audited,
security-critical C++ with an active internal fuzzing/static-analysis pipeline and a public bug
bounty; finding a genuine 0-day auth-bypass or injection bug here in one review session is a very
high bar, and I want to be upfront that I didn't clear it, rather than stretch a weak lead into a
claim.

Target: this repo's own `src/mongo/s/` (the sharding-router / `mongos` source), current checkout
on `claude/hackerone-bug-reports-juhef8`.

## Code-injection angle: structurally very unlikely in mongos specifically

Two blanket checks, both clean:

- **No subprocess execution capability at all.** `grep`'d `src/mongo/s/` for
  `system(`/`popen(`/`execve`/`boost::process` — every hit is a function *named* `execute*`
  (`executeRequests`, `executeBatch`, `executeCommandOnPrimary`, etc. — ordinary C++ method names
  for "run this operation"), not a call into an OS shell or process-spawning API. `mongos` never
  shells out to an external binary.
- **No dynamic/string-built BSON commands.** `grep`'d for `fromjson(` (the pattern that would
  indicate a command object assembled by concatenating a JSON string with untrusted input, rather
  than a type-safe `BSONObjBuilder`/IDL-generated struct) across `src/mongo/s/` non-test code:
  zero hits.

Put together: `mongos` doesn't run a JavaScript engine and doesn't shell out, so the "attacker
input reaches a code-execution sink" precondition for classic code injection doesn't exist in
this component. Server-side JS (`$where`, `$function`, `mapReduce`) is mongod-only — `mongos`
routes those pipelines to the shards, where mongod's own guards apply (a separate, already
extensively audited surface, not part of `src/mongo/s/`). This isn't "no bug is possible here" so
much as "this specific bug class doesn't have the ingredients it needs in this component" — code
injection in a MongoDB deployment is a mongod-side question, not a mongos-side one.

## Auth-bypass angle: spot-checked the historically-relevant command classes

Reviewed the auth-check overrides (`checkAuthForOperation`) across `src/mongo/s/commands/` — 23
files override it; read every one, focused deep-dives on the three classes with the strongest
history of this kind of bug elsewhere:

### `abortTransaction`/`commitTransaction` — unconditional `Status::OK()`, but that's correct

`cluster_abort_transaction_cmd_s.cpp` / `cluster_commit_transaction_cmd_s.cpp` both return
`Status::OK()` unconditionally from `checkAuthForOperation`, which looks alarming in isolation —
but transactions are identified purely by `lsid`/`txnNumber`, and session ownership (that the
`lsid` in the command belongs to the *authenticated caller*) is enforced by the logical-session
layer independently of this per-command hook, the same way `endSessions` doesn't need a separate
resource-privilege check. No additional check is missing; the check just lives at a different
layer than this file.

### `killOp` on mongos — correctly *more* restrictive than expected, not less

`cluster_kill_op.cpp` (mongos) extends the shared `KillOpCmdBase` (`db/commands/kill_op_cmd_base.cpp`,
used by both mongod and mongos). Traced the logic for the mongos-specific
`killOp({op: "<shardid>:<opid>"})` form (targeting an op running on a shard, string-typed `op`
field): `KillOpCmdBase::checkAuthForOperation`'s local-op branch only matches when `op` is a
number or array (`isKillingLocalOp`) — a string `op` falls through every branch to the final
`return Status(ErrorCodes::Unauthorized, ...)`. Net effect: killing a shard-targeted op via mongos
requires the general `killop`/`inprog`-class privilege; there's no path for a user to
self-service-kill their own op running on a shard through this string form the way they could kill
their own *local* op. That's a usability wrinkle (fails toward *more* restrictive), not a bypass.

### `replSetGetStatus` on mongos — intentional no-op stub

`cluster_repl_set_get_status_cmd.cpp` also returns unconditional `Status::OK()` from its auth
check, with an explicit comment ("Require no auth since this command isn't supported in mongos").
Confirmed `errmsgRun` does nothing but return the string "replSetGetStatus is not supported
through mongos" — no data or capability behind the skipped check.

No mislabeled or missing auth check found among the checked files; every other
`checkAuthForOperation` override does perform a real, resource-scoped check appropriate to its
command.

## What this pass did not cover (candidates for continuing)

This was a targeted, historically-informed spot-check of `src/mongo/s/commands/` (roughly 15 of
its 56 files read in depth) plus two blanket structural greps — not a line-by-line review of the
whole `src/mongo/s/` tree, and not a review of `src/mongo/db/auth/` (the shared authorization
engine both mongod and mongos call into) at all. Areas that would be next in a deeper round:
- The mongos-side `AuthorizationManager`/user-cache invalidation path (`UserCacheInvalidator` and
  friends) for a staleness/TOCTOU window — e.g., does a just-revoked role keep working on mongos
  for some window after revocation on the config server, longer than intended/documented.
- Internal cluster authentication (keyfile and x.509 member-certificate validation) for the
  mongos↔shard and mongos↔config-server links — a different trust boundary than client-facing
  auth, not touched this round.
- The remaining ~40 command files in `src/mongo/s/commands/` not yet opened.
- `src/mongo/db/auth/` itself (shared by mongod and mongos) — out of scope for a "mongos-specific"
  pass, but a bug there would affect mongos too.
