# MongoDB 8.3.8 — memcpy/memmove xref sweep within MongoDB's own code: attempted, hit real infrastructure limits

**Status: attempted properly, no result either way — the technique itself hit a documented,
specific obstacle in this environment, not abandoned early.** Recorded so a future pass doesn't
repeat the same dead end without knowing why it didn't work.

## What was attempted

Goal: find a fixed-size-buffer/attacker-controlled-length mismatch at a `memcpy`/`memmove` call
site within MongoDB's own code (as opposed to vendored third-party libraries), using the same
"map every dangerous-call-site to its enclosing function via objdump/nm" technique that worked for
the `execl`/`popen` sweep in the earlier Ghidra pass.

## Why it doesn't work the same way for memcpy

The `execl`/`popen` sweep worked because those calls are rare (1-8 call sites total) and land in
small, non-templated, easily-identified functions. `memcpy`/`memmove` together have **35,755** call
sites in this binary — even after filtering out vendored-library namespaces (ICU, SpiderMonkey,
Abseil, Boost, protobuf, gRPC, etc.), **13,170 distinct MongoDB-own functions** remain, and
filtering further to parsing/deserialization-keyword function names still leaves **3,451**
candidates. This is not a short list a human can review call-by-call.

Worse: **objdump's "nearest preceding symbol label" heuristic for attributing a call site to its
enclosing function is measurably unreliable on this binary.** Concretely: `nm`/`objdump` attributed
24-27 `memcpy` calls each to `BlockBasedInterleavedDecompressor::decompressGeneral` (both template
instantiations) — a promising target given its direct relationship to this program's existing
BSONColumn RLE-bomb Critical finding. Decompiling the *actual* function bodies at their real,
Ghidra-verified addresses (`050df8e0`, `060a07f0`) via `/decompile_function` shows **zero** `memcpy`
calls in either — the real logic dispatches immediately into a chain of separate lambda/helper
functions (`traverseNoArrays`, `traverseIntoArrays`, `moreData<Decoder64/128>`, etc.), each of which
carries its own distinct symbol. The `memcpy` calls objdump attributed to `decompressGeneral` almost
certainly belong to some of those adjacently-laid-out helper functions instead, misattributed by
objdump's simple "which label appears immediately before this address" heuristic — which breaks
down exactly where it matters most: a heavily templated, lambda-dense modern C++ binary where many
tiny functions are packed close together.

**Confirmed this isn't fixable with a quick query either.** Asked Ghidra directly for
`decompressGeneral`'s real extent via `/get_function_by_address` to filter the memcpy address list
by genuine (not textually-guessed) function range: `body_start` and `body_end` come back identical
(`050df8e0` for both) — Ghidra itself doesn't know this function's true size without the
instruction-level disassembly/code-block analysis that only comes from a real auto-analysis pass
(or at least a per-function disassemble step), which the symbol-table-derived function list alone
doesn't provide.

## Why full auto-analysis wasn't a viable fallback in the time available

Triggered Ghidra's `/run_analysis` (POST) as a background task. It ran for over 30 minutes of CPU
time and was still stuck cycling through `GccExceptionAnalyzer` failures at slowly-advancing
addresses when checked — consistent with a 190,359-function, 168MB binary being a genuinely
multi-hour (possibly much longer) full-analysis job, not something to wait out inline. The run was
killed to free the server for other queries rather than left blocking indefinitely; the server was
restarted without re-triggering it.

## Net result

No memcpy-based finding, positive or negative — this is different from the other write-ups in this
directory, which reached a definite (even if negative) conclusion. Here the conclusion is about the
*technique*: a naive disassembly-text-based call-site sweep is not reliable on this specific binary
without either (a) letting a genuinely long (likely multi-hour) full auto-analysis pass complete
first, so Ghidra's own function/xref database has real boundaries and reference data, or (b) writing
a dedicated Ghidra script that does per-call-site containing-function resolution via the P-code/
listing API directly (which was outside the time budget for this pass). Flagging this precisely so
a future pass with more time budgeted for full analysis can pick up exactly where this one had to
stop, rather than re-discovering the same dead end.
