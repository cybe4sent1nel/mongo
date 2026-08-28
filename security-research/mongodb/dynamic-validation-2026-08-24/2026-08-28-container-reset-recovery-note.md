# 2026-08-28 — container reset data-loss incident and recovery status

## What happened

This engagement's standing infrastructure issue — Claude has never had GitHub App access to
`cybe4sent1nel/mongo` (every `git push` this whole program returned the same `403`:
*"Claude doesn't have GitHub access to cybe4sent1nel/mongo for your organization"*) — meant every
commit made across this research program's prior sessions stayed local-only. This session's
working container was recycled (an ordinary lifecycle event for this environment, not something
this session did) before that access gap was ever resolved, and everything that lived only in that
container's local git history — reportedly ~897 unpushed commits — was lost. The `master`/`origin`
state of `cybe4sent1nel/mongo`'s `claude/hackerone-bug-reports-juhef8` branch, which this fresh
container cloned from, currently just tracks a much later point in upstream MongoDB's own history
(commit `f0e6adc9`, `SERVER-111072`) with no `security-research/` directory at all.

The locally-stood-up `mongod`/`mongos` binaries, the sharded-cluster test infrastructure, and all
raw evidence files (dmesg captures, RSS traces, log tails) from prior sessions were lost the same
way — they lived only in that container's `/tmp` scratch space, never in git.

## What's been recovered (2026-08-28), and how

Every file below was reconstructed from this program's own conversation record, which had quoted
each file's full content (or, for the two oldest findings, the key mechanism/numbers) verbatim at
authoring time. Nothing here is fabricated from general knowledge of MongoDB — every source-code
citation was **re-verified against a fresh `git fetch` of the exact `r8.3.8` commit**
(`d100bf19961251f273e1d0bd8ce66fc60634f53c`, pulled directly from `github.com/mongodb/mongo`, which
is not blocked by this session's egress policy even though bulk binary/image downloads are) before
being written back down, rather than trusted from memory.

| Recovered file | Fidelity |
|---|---|
| `internal-apply-oplog-update-oom-crash/README.md` | Full text, unchanged (was quoted verbatim to the user twice in this program's own record) |
| `internal-apply-oplog-update-oom-crash/poc.sh` | Full text, unchanged (quoted verbatim) |
| `bsoncolumn-rle-decompression-bomb/README.md` | Reconstructed: mechanism, root cause, and the confirmed-crash numbers (614,400,001 elements / ~7.75MB / ~13.9GB RSS) are preserved from this program's own record; the three "survived-scale" rows' exact byte/timing figures were **not** recoverable and are marked as needing a fresh PoC run; every source citation re-verified against `r8.3.8` |
| `internal-search-id-lookup-viewpipeline-bypass/README.md` | Reconstructed: exploit chain, tested/blocked negative controls, and root-cause mechanism preserved from this program's own record; every source citation re-verified against `r8.3.8` (this is a **new directory name** — the original may have used a different name/location; content is the same finding already covered by `mongo-8.3.8-findings.md` in an earlier, separately-authored static pass, which is also not present in this checkout) |
| `prepared-txn-commit-abort-race-lead/LEAD.md` | Full text, unchanged |
| `big-polygon-uaf-race-lead/LEAD.md` | Full text, unchanged |
| `big-polygon-uaf-race-lead/RESULTS.md` | Reconstructed from this program's own record of the completed test run (negative result: no crash, no mismatch, ~8,700 concurrent iterations) |
| `recent-hardening-commits-sibling-bug-hunt-2026-08-24.md` | Full text, unchanged |
| `fresh-dos-crash-sweep-2026-08-24-negative-and-tentative.md` | Full text, unchanged |
| `createview-null-opctx-bypass-class-closure-sweep.md` | Full text, unchanged |

## What's still lost and not reconstructed here

- `internal-unpack-bucket-missing-authz/`, `internal-apply-oplog-update-missing-authz/`,
  `unpack-bucket-missing-authz-followup.md`, `sort-internal-fields-no-guard-confirmed.md` — the
  earlier, already-invalidated-or-Low-severity findings. Not reconstructed because they carry no
  actionable value beyond what's already summarized in the surviving files that reference them, and
  reconstructing them from a compacted summary risks introducing inaccuracies in findings this
  program has already correctly decided not to submit.
- `mongo-8.3.8-findings.md`, `VIEW-VALIDATION-*`, and the other top-level `security-research/mongodb/*.md`
  static write-ups from even earlier sessions — not reconstructed; their substance for the one
  finding still relevant today (`$_internalSearchIdLookup`) is captured in the recovered
  `internal-search-id-lookup-viewpipeline-bypass/README.md` above.
- All raw evidence artifacts (dmesg captures, mongod log tails, RSS traces) for the BSONColumn
  finding, and the exact three-row "survived scale" measurements for it — genuinely gone, need a
  fresh live run.
- The mongod/mongos binaries and sharded-cluster test infrastructure — gone; **currently
  unrecoverable in this environment**, since both `fastdl.mongodb.org` and Docker Hub's blob CDN
  (`production.cloudfront.docker.com`) are policy-blocked for this session (confirmed via the agent
  proxy's own status log, not something to route around).

## Standing takeaway

Given the GitHub push access gap has never been resolved across this entire program, **any work
this session does that isn't committed AND successfully pushed remains one container recycle away
from this exact same loss again.** Every commit this session makes will keep attempting a push
(retried once per the standing single-retry policy) but should not be assumed durable until that
push actually succeeds.
