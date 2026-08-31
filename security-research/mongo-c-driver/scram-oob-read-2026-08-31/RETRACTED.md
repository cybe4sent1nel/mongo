# RETRACTED — already fixed upstream, do not submit

This finding was written up against `mongo-c-driver` tag `1.30.8`, which was
**not** the latest release at the time — a filtering mistake in tag discovery
(`git ls-remote --tags | grep -E '^1\.'`) silently excluded the entire `2.x`
major-version line, which is the actual current release line.

Checked directly against the real latest tag, `2.5.1`
(commit `0ecd80a7b40998d48738452eb6be013bf3b9997e`): **both halves of this
finding are already fixed**, in public commits with public JIRA references,
both merged before this finding was written:

- The out-of-bounds read (missing bounds check before the `*ptr != '='`
  dereference) — fixed by `9655909e15c83149c0fc68e53f38e696bbd23569`,
  **CDRIVER-6370 "add tests and fixes for SCRAM parser" (#2350)**,
  2026-07-16.
- The missing `goto FAIL` after the nonce-mismatch check — fixed by
  `6b27da3e0384170ac0efc75321556bd37a2ae03f`,
  **CDRIVER-6315 "fix missing `goto FAIL` along error handling path" (#2308)**,
  2026-06-02.

Neither fix is attributable to this audit. This finding is not fresh and must
not be submitted. Kept in the repo for the record, not as a live report.
