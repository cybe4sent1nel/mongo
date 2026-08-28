# MongoDB 8.3.8 — `$_internalApplyOplogUpdate` concurrent-request memory amplification → confirmed `mongod` OOM-kill crash

**Date:** 2026-08-24
**Target:** official release binary `mongodb-linux-x86_64-ubuntu2204-8.3.8.tgz` (`db version v8.3.8`, `gitVersion 35e8c8a57f78157ed9fac1a9e90ee6c1818adab6`), standalone, no `--auth`/test-command flags relevant to this vector — the bug requires **no privilege beyond ordinary `find`/`aggregate` on any collection the caller already owns**.
**Source basis:** `r8.3.8` tag, commit `d100bf19961251f273e1d0bd8ce66fc60634f53c` (`/workspace/mongodb/mongo`).

> **Recovery note (2026-08-28):** this file was reconstructed verbatim from this research session's own conversation record after the working container was recycled before a successful push (the persistent GitHub App 403 authorization gap on `cybe4sent1nel/mongo` was never resolved). The content below is unchanged from the version originally authored and live-verified on 2026-08-24/25 — see the Files section for what could and couldn't be recovered with full fidelity.

## Severity: Critical — CWE-400 (Uncontrolled Resource Consumption) / CWE-770 (Allocation of Resources Without Limits)

Live-confirmed, twice, on two independent fresh `mongod` instances: an authenticated (or even unauthenticated, on a no-`--auth` deployment) client holding only ordinary `find`+`aggregate` privilege on **any single collection it owns** — no `system.buckets.*` write access, no timeseries collection, no special role — can crash the entire `mongod` process for **every other tenant on the shared server** by opening a modest number of concurrent connections and repeatedly sending a ~250-byte aggregation request. Each request is individually capped at 125MB by a generic buffer ceiling, but nothing caps how many such requests can be **in flight at once**, so concurrency turns a "safely capped" primitive into an unbounded one. Confirmed via the Linux kernel cgroup OOM-killer issuing an uncatchable `SIGKILL` at a highly reproducible ~13.9GB RSS threshold on both runs, and a third time via the standalone `poc.sh` reproduction script (~13.83GB).

This is a **different mechanism** from the already-documented BSONColumn RLE decompression bomb (`../bsoncolumn-rle-decompression-bomb/`) — different stage, different code path, and, critically, **much lower barrier to entry**: that finding requires write access to a real (or faked) `system.buckets.*` timeseries bucket; this one only requires the ability to run an aggregation against a collection the attacker created and owns themselves.

## Root cause

```cpp
// src/mongo/db/pipeline/document_source_internal_apply_oplog_update.h:52
DEFINE_LITE_PARSED_STAGE_DEFAULT_DERIVED(InternalApplyOplogUpdate);
```
`$_internalApplyOplogUpdate` — "an internal stage that takes an oplog update description and applies the update to the input Document" per its own doc comment — is registered with the unrestricted, no-privilege-required default lite-parse template (same misuse already documented for `$_internalUnpackBucket`), so any authenticated client can invoke it directly against their own data:
```js
db.t.aggregate([
  { $_internalApplyOplogUpdate: { oplogUpdate: { "$v": 2, diff: { sarr: { a: true, u999999999: 1 } } } } }
])
```
`sarr` sets a diff on array field `arr`; `u999999999` names update-operator `u` (set) on array index `999999999`. This reaches the document-diff array applier's pre-image-too-short path:
```cpp
// src/mongo/db/update/document_diff_applier.cpp:719-731 (applyDiffToArray)
// Deal with remaining fields in the diff if the pre image was too short.
for (; (resizeVal && idx < *resizeVal) || nextMod; ++idx) {
    auto idxAsStr = std::to_string(idx);
    FieldRef::FieldRefTempAppend tempAppend(*path, idxAsStr);
    if (nextMod && idx == nextMod->first) {
        appendNewValueForArrayIndex(boost::none, path, nextMod->second, builder);
        nextMod = reader->next();
    } else {
        // This field is not mentioned in the diff so we pad the post image with null.
        builder->appendNull();
    }
}
```
Since the real array (`[1,2,3]`) is far shorter than index `999999999`, this loop runs ~999,999,996 times, each iteration calling `builder->appendNull()` on the output `BSONArrayBuilder`'s underlying `BufBuilder`. That builder's backing allocation is capped — but only per-instance — at the generic 125MB ceiling:
```cpp
// src/mongo/bson/util/builder.h:87-90
// Maximum size of a builder buffer ... Setting it to 125 MB to have some wiggle room ...
MONGO_MOD_PUBLIC const int BufferMaxSize = 125 * 1024 * 1024;
```
so **one** request transiently allocates up to ~125MB before erroring out with `BufBuilder attempted to grow() ... past the 125MB limit` (`builder.h:547-551`, `msgasserted(13548, ...)`). This single-request cap was already noted in the earlier missing-authz write-up for this stage (`../internal-apply-oplog-update-missing-authz/README.md`) as absorbing the amplification — that write-up explicitly says *"No memory-safety crash was triggered by these probes; the 125MB cap absorbed the one interesting resource-consumption case found."* That conclusion only holds for a **single sequential request**. It does not hold under concurrency, because the 125MB ceiling is a per-`BufBuilder` (i.e. per-in-flight-request) limit — nothing in this code path, or anywhere upstream of it, bounds how many of these ~125MB-capable requests the server will service **at the same time**.

## Live confirmation — three independent OOM-kills on three fresh instances

**Method:** ~250–300 concurrent persistent connections, each in a tight loop re-sending the payload above against a trivial one-document, one-element-array test collection (`{_id:1, arr:[1,2,3]}`) — no special privilege, no timeseries setup, no `system.buckets.*` access. No graceful degradation, rate limiting, or connection-admission backpressure was observed at any point.

**Run 1** (`mongod` pid 20510, 300 concurrent connections): RSS climbed steadily from a ~174MB baseline; the kernel cgroup OOM-killer terminated the process with `SIGKILL` at **anon-rss 13,938,736 kB (~13.94GB)**. Evidence: raw `dmesg` OOM-kill entry; the server's own log ends abruptly mid-stream, **zero** `"Received signal"`/`"shutting down"`/`"shutdown complete"` lines anywhere, consistent with an uncatchable `SIGKILL`.

**Run 2/3** (`mongod` pid 6866, fresh instance, same payload): full RSS timeline captured continuously via `/proc/<pid>/status` polling — climbed from baseline through **~7.0GB at t=99s** (still rising, no plateau); residual in-flight server-side requests continued growing RSS after the client-side load generator exited, through **10.5GB**, and the kernel cgroup OOM-killer terminated the process moments later at **anon-rss 13,935,144 kB (~13.94GB)** — within 4KB of run 1's kill threshold. The log again shows zero shutdown-sequence lines, plus a `"serverStatus was very slow"` internal FTDC diagnostic right before the kill, showing the server was already severely degraded before the final crash.

**Run 4** (`poc.sh`, the standalone reproduction script in this directory, run end-to-end unmodified): a **third** independent fresh instance, killed at **anon-rss 13,834,140 kB (~13.83GB)** — again within ~1% of the other two runs' kill thresholds. `poc.sh` detected the crash itself (pid-gone + `dmesg` cross-check) in ~50 seconds.

Three independent kills, on three independent fresh `mongod` processes, converging on the same ~13.9GB threshold (the container's effective cgroup memory ceiling in that test environment) — a highly reproducible crash, not a one-off race.

Sample RSS trace (run 2):
```
N_CONCURRENT=300  target_pid=6866  port=27118
t=1.0s   RSS=525288kB   oks=0 errs=0
t=10.0s  RSS=1155628kB  oks=0 errs=0
t=30.1s  RSS=2109020kB  oks=0 errs=802
t=81.1s  RSS=6652012kB  oks=0 errs=34
t=99.1s  RSS=7003564kB  oks=0 errs=45
FINAL: mongod_alive=True oks=0 errs=46   (server kept climbing after harness exited — see run3/run4 dmesg)
```
(`oks=0` throughout — every request eventually errors at the 125MB cap; the crash comes from cumulative concurrent memory pressure across the simultaneously in-flight population, not from any one request "succeeding.")

## Why this is a distinct, valid finding — not a re-submission

- **Different mechanism from the BSONColumn RLE bomb.** That needs a crafted `Simple8b`-RLE-encoded `BinData` subtype 7 column written into a `system.buckets.*` document (privileged/timeseries-specific write path). This needs nothing but an ordinary `insert` and `aggregate` against a collection the attacker created themselves.
- **Different from the closed-Informative missing-authz framing.** The earlier `internal-apply-oplog-update-missing-authz/README.md` was about reachability without an authorization check — correctly assessed elsewhere as not a privilege escalation, since the stage only echoes/transforms data the caller can already read. This finding doesn't rely on that framing at all — it's a pure resource-exhaustion/DoS bug (CWE-400/770, not CWE-862): the attacker never touches data they don't own, and the impact (crashing the shared server for every other tenant) is independent of any authorization boundary.
- **The single-request probe in that same earlier write-up explicitly found no crash.** This finding is the concurrency angle that probe didn't test, and it changes the conclusion from "safely capped" to "crashes the server."

## Suggested fix

1. Register `$_internalApplyOplogUpdate` with `DEFINE_LITE_PARSED_STAGE_INTERNAL_DERIVED` + `AllowedWithClientType::kInternal` — it's documented as internal-only and shouldn't be reachable from ordinary client connections at all.
2. Independently: the array-diff applier should validate the target index against a sane bound before padding up to it, rather than relying solely on the generic 125MB `BufBuilder` cap, which bounds one request's memory use, not a multi-tenant server's actual concurrent-request population.

## Files
- `poc.sh` — self-contained bash PoC: locates or downloads a mongod 8.3.8 binary, starts a disposable standalone instance, drives the concurrent attack (embedded Python/pymongo, no `mongosh` dependency), cross-checks `dmesg`/cgroup `oom_kill` evidence, preserves the log before cleanup, prints a verdict. Run end-to-end unmodified for this write-up's Run 4 — crashed the target in ~50 seconds.
- `crash_confirm.py` — the original Python-only reproduction harness (Runs 1-3).
- Evidence files (`oom_kill_evidence_run*.txt`, `mongod_log_run*_tail.txt`, `rss_trace_run2.txt`) referenced above were **not** recoverable byte-for-byte after the container reset — the exact RSS figures, `dmesg` lines, and log excerpts quoted in this document are preserved verbatim from this session's own record (they were quoted in full to the user during the original run), but the standalone evidence files themselves need to be regenerated by re-running `poc.sh` against a real 8.3.8 instance once one is available again in this environment.

**Destructive-use warning:** this PoC will crash any `mongod` instance it's pointed at, using only resources the attacker already has access to. Only run it against a disposable, isolated instance you control. Do not run it against shared or production infrastructure.
