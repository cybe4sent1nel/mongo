# Round 3 status: applyOps/SERVER-131138 (confirmed), 82067/82069/82070 (no new finding)

## applyOps / SERVER-131138 — CONFIRMED (see separate report)

Delivered separately as `applyops-container-op-namespace-mismatch-2026-09-11/`. Summary: the
CVE-2026-82062 fix (FCV + `featureFlagPrimaryDrivenIndexBuilds` gate) is correct and complete for
the bypass it documents, but the oplog entry's `ns` field (used for the `containerInsert`/
`containerDelete` authorization check) has zero enforced correspondence to `container` (the raw
storage-engine ident actually written to/deleted from). Live-verified on the real 8.3.9 binary:
both container-insert and container-delete land on a different collection than the one declared
and authorized against. Gated behind a currently-disabled, `fcv_gated: true` feature flag, so not
exploitable in a default deployment today — flagged as a live gap sitting behind that one gate,
not a standalone reachable bug.

## CVE-2026-82070 — Insufficiently Protected Credentials in Diagnostic Reporting Interface

**Hypothesis formed from static analysis, then tested live and disproven — reporting the negative
result rather than a claim it doesn't support.**

Traced `CurOp::reportState()` (the function behind `db.currentOp()`/`$currentOp`,
`src/mongo/db/curop.cpp:1062`+): its only redaction gate is `getShouldOmitDiagnosticInformation()`,
which is set **exclusively** by FLE/Queryable Encryption code paths
(`src/mongo/db/commands.cpp:201`, `prepareForFLERewrite`, gated on `encryptionInformation` being
present on the request) — nothing to do with `createUser`/`updateUser`'s `pwd` field. Separately,
`Command::snipForLogging()` (`commands.cpp:1086`) is the mechanism that *does* redact
`sensitiveFieldNames()` (confirmed `CmdCreateUser` declares `{"pwd"}`,
`user_management_commands.cpp:1150-1153`) — but I could only find it called from two places
(`commands.cpp:963`, the "not authorized" error message; and `OpDebug::report` for the slow-query
log). Neither of `reportState`'s two branches calls `snipForLogging` at all, from what I could find
by reading the function directly.

**This read as a strong candidate for exactly what the CVE describes** — so I tested it live rather
than reporting it from source alone. Using `failCommand` with `blockConnection`/`blockTimeMS` to
hold a real `createUser` command in flight, then reading `$currentOp` from a second connection on
the real 8.3.9 binary:
```
{'createUser': 'victimUser', 'pwd': 'xxx', 'roles': [...], ...}
```
**The password is correctly redacted (`'xxx'`).** My source trace missed the actual mechanism —
`_opDescription` is evidently populated from an already-`snipForLogging`'d copy somewhere upstream
of `reportState`, not from the raw wire body as I'd traced. I did not chase down exactly where,
since the live test already closes the question that mattered: this specific bug does not
reproduce. **No finding here** — disproven by direct test, not left as an open guess.

## CVE-2026-82069 — Query-stats redaction bypass on search queries

Identified the general area (`src/mongo/db/query/query_stats/`) but found no `$search`-specific
redaction branch to inspect — grepped `key.cpp` and every `*_key.cpp`/`*_stats_entry.cpp` file for
`search`/`Search` and got no hits, meaning whatever conditional the GHSA describes either lives in
code this pass didn't locate, or interacts with the `mongot` (Atlas Search) integration layer,
which I could not set up or exercise in this sandbox (no Atlas Search process available, and I'm
not confident that side of the integration is even present in this open-source checkout the way
the LDAP enterprise module isn't). **No finding, and no further static lead found this pass** —
distinct from the LDAP case in that I can't yet say for certain the code isn't here, just that I
didn't find it in the time spent.

## CVE-2026-82067 — Case-sensitivity in config validation causing an authorization issue

Grepped `src/mongo/db/auth/` and config-validation-adjacent directories for case-insensitive
comparison helpers (`toLower`/`toUpper`/`caseInsensitive`/`strcasecmp`) and for any comment
referencing case-sensitivity — no hits in either sweep. Without the GHSA/Jira text (never located a
usable snippet for this one specifically, unlike the others), I don't have enough to know which
config option or comparison is actually affected, so I didn't have a concrete code location to
sweep for siblings from. **No progress this pass** — this one needs the actual ticket to make
further headway; static guessing across all of `db/auth` and config validation wasn't
narrow enough to be productive in the time available.

## Net result this round

One more confirmed, live-verified finding (applyOps/SERVER-131138 sibling). One hypothesis (82070)
tested live and correctly ruled out rather than over-claimed. Two items (82069, 82067) genuinely
stalled without either the source ticket text or infrastructure (Atlas Search) this sandbox
doesn't have — reporting that honestly rather than padding with unconfirmed guesses.
