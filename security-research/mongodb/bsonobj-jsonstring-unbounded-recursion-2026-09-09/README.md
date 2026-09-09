# bsonobj/bsonelement jsonStringGenerator — unbounded recursion (pre-auth reachable)

See `HACKERONE-REPORT.md` for the full writeup.

Files:
- `build_payload.py` — iterative (non-recursive) generator that builds a raw, wire-ready BSON
  `ping` command with a field nested 1,994 levels deep, and binary-searches the max nesting depth
  that fits under a 16,000-byte budget (the pre-auth message-size cap is 16,384 bytes).
- `build_payload_output.txt` — captured output of running the script.
- `preauth_deep_command.bson` — the actual generated payload (15,997 bytes), ready to be wrapped
  in a standard `OP_MSG` message and sent over a raw, unauthenticated TCP connection to `mongod`.

Audited MongoDB server tag `r8.3.8` (commit `d100bf19961251f273e1d0bd8ce66fc60634f53c`) as part of a
deep, static-analysis pre-auth OOM/CPU-DoS audit of that release branch. No live `mongod` build was
performed in this sandbox (disk-constrained environment) — this is a code-verified, quantified
finding, honestly caveated in the report as to what is proven vs. reasoned-but-unmeasured.
