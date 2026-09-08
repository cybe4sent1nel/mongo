# mongo-tools: bsondump crashes on a single crafted .bson file (uncatchable stack overflow)

Sibling hunt continued from the mongo-go-driver generic-decode finding
(`security-research/mongo-go-driver/bson-generic-decode-unbounded-recursion-2026-09-07/`).
That report speculated mongo-tools' handling of real binary `.bson` files "very likely
inherits this same crash" without independently verifying it — this closes that gap.

Confirmed directly: built the real `bsondump` binary from mongo-tools tag `100.18.0`
(vendoring `mongo-go-driver v2.7.0` — even older than the v2.9.0 tested standalone,
confirming the gap predates that release by multiple minor versions) and ran it against a
single 16MB, 2,000,000-level-nested `.bson` file. `bsondump --type=debug --objcheck` crashes
with `fatal error: stack overflow` (exit code 2) — the crash trace shows the exact same
`dDecodeValue`/`empty_interface_codec.go` cycle from the go-driver report, now inside
`mongo-tools/vendor/go.mongodb.org/mongo-driver/v2/bson/...`.

Also found a second, independent bug while reading this code: `bsondump`'s own `printBSON`
function (always called in `--type=debug` mode, with or without `--objcheck`) recurses into
nested documents/arrays with zero depth limit of its own — first-party mongo-tools code,
not inherited from the driver. Flagged as analytically confirmed (verified absent of any
depth tracking by direct reading) rather than empirically crashed — its lightweight
per-level stack frame plus proportional text output made it too slow to drive to a clean
crash within available testing time, unlike Path 1 which crashed almost immediately.

See `HACKERONE-REPORT.md` for the full write-up. `genfile.go` is the malicious-file
generator (shared construction with the go-driver PoC); `crash_trace_head.txt`/
`crash_trace_tail.txt`/`exit_code.txt` are the raw evidence from the confirmed crash.
