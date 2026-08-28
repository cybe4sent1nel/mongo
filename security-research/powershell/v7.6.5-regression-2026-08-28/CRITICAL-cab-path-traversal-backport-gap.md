# PowerShell v7.6.5: CAB-extraction path-traversal fix was never forward-ported to this branch

**Status: CONFIRMED via direct source comparison of the two official tags, then corrected via
full commit-ancestry analysis (see "Correction" below) after being asked to verify the actual
commit/PR rather than infer intent from a two-tag diff. Severity: Critical either way (arbitrary
file write → RCE) — but the *mechanism* is a backport gap, not an active revert.**

## Correction (read this first)

The initial version of this write-up called this a "regression" implying an active revert commit
undid a fix. That was wrong. Checked `git log v7.6.4..v7.6.5 -- <path>` (commits reachable from
v7.6.5 but not v7.6.4 that touch this file) and it comes back **empty** — no commit in that range
touches `CabinetNativeApi.cs` at all, so there is no removal commit or PR to point to.

The real mechanism, found via `git merge-base --is-ancestor`: the fix (`ValidateExtractionPath`,
from PR #167 "Validate CAB path before expansion") was never merged into `master`. It landed only
as two independent, branch-specific backport commits, each carrying the identical PR title/number
but a different commit hash:

| Commit | PR | Ancestor of |
|---|---|---|
| `ade8e8f9b` | "Merged PR 40623: Validate CAB path before expansion (#167)" | **v7.6.4 only** |
| `bc43c9297` | "Merged PR 40624: Validate CAB path before expansion (#167)" | **v7.4.19 (LTS) only** |
| `9b38a631d` | "Merged PR 40609: Validate CAB path before expansion (#167)" | neither of the above, nor master |

Confirmed directly on the actual file content across every relevant tag:

| Tag | Has `ValidateExtractionPath`? |
|---|---|
| v7.2.24 | No |
| v7.4.18 | **Yes** |
| v7.4.19 (LTS) | **Yes** |
| v7.5.8 | (not checked) |
| v7.5.9 | **Yes** |
| v7.5.10 | **No** |
| v7.6.0 – v7.6.3 | No |
| v7.6.4 | **Yes** |
| v7.6.5 | **No** |
| `origin/master` | No |
| v7.7.0-preview.3 | No |

## Sibling confirmed: this is not unique to the 7.6.x line

This is the part directly answering "is a sibling of this bug present in other releases too" —
yes. **v7.5.10 has the exact same gap as v7.6.5, relative to its own immediate predecessor:**
`v7.5.9` has `ValidateExtractionPath`, `v7.5.10` (the very next patch, tagged Aug 13 2026 — the
same day as v7.6.5) does not. Checked the same way as the 7.6.4/7.6.5 pair:
`git merge-base --is-ancestor v7.5.9 v7.5.10` → **NO** — they diverge at a common ancestor, exactly
mirroring the v7.6.4/v7.6.5 relationship. This means the *same* release-branching pattern (a
patch-release branch cut from a point that predates the fix, with no re-backport) happened
independently in **two separate branch lines in the same patch wave**: 7.5.x and 7.6.x both lost
it; only 7.4.x (the LTS line, built as a clean linear descendant — confirmed `v7.4.18` *is* an
ancestor of `v7.4.19`) kept it.

So the current, real-world exposure as of this audit: **the latest published release in both the
7.5.x and 7.6.x lines (`v7.5.10` and `v7.6.5`) lack this CAB path-traversal protection, and so does
`master`/the 7.7 preview** — only the 7.4.x LTS line has it. This reads less like an isolated
one-off backport miss and more like a systemic gap in how the August 2026 patch wave's release
branches were cut for the two non-LTS lines specifically.

So: this was a coordinated security fix shipped as **targeted, branch-specific backports** to the
versions being patched in mid-to-late July 2026 (7.4.18/19, 7.5.9, 7.6.4) — never merged upstream
to master. When the next patch branches (`release/v7.5.10`, `release/v7.6.5`) were cut about a
month later (to address a *different* batch of issues — the SSH-remoting fix, CIM XSD validation,
etc.), nobody opened the equivalent backport PR for either of them, and
it isn't in master to inherit either. That's why it's absent from 7.5.x and everything after 7.6.4
in the 7.6.x line, and from the 7.7 preview. **No one reverted anything; the fix simply never
reached this branch.** The security consequence is unchanged (v7.6.5, current master, and the 7.7
preview all currently lack this validation) but the causal story is a release-process gap, not a
deliberate or accidental code change — correcting that here since it matters for how this should
be reported and framed.

## Summary

`git diff v7.6.4 v7.6.5` shows that PowerShell's CAB (help-content) extraction code has no
path-traversal protection in v7.6.5 — no `ValidateExtractionPath`-equivalent function anywhere,
and both call sites use naive, unvalidated path construction. v7.6.4 and the 7.4.19 LTS line do
have this protection (via the branch-specific backports above); v7.6.5, current `master`, and the
7.7 preview do not. Whatever the intended CVE this closes (see "External CVE context" below), the
officially tagged `v7.6.5` source — and, more importantly, ongoing mainline development — doesn't
carry it forward.

## Direct evidence

```
$ git show v7.6.4:.../help/CabinetNativeApi.cs | grep -c ValidateExtractionPath
3
$ git show v7.6.5:.../help/CabinetNativeApi.cs | grep -c ValidateExtractionPath
0
```

**v7.6.4** (`abeb8444d065feeccf80bda83eed5675a37719c1`), the protected version:

```csharp
private static string ValidateExtractionPath(string helpDirectory, string entryPath)
{
    // Reject absolute paths, UNC paths, or rooted paths in CAB entries
    if (Path.IsPathRooted(entryPath))
        throw new InvalidOperationException($"CAB entry contains an invalid rooted path: {entryPath}");

    // Reject paths containing a colon to block Windows Alternate Data Streams (e.g. "file.txt:payload").
    if (entryPath.Contains(':'))
        throw new InvalidOperationException($"CAB entry contains an invalid path with a colon: {entryPath}");

    string canonicalHelpDir = Path.GetFullPath(helpDirectory);
    if (!canonicalHelpDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
        canonicalHelpDir += Path.DirectorySeparatorChar;

    string candidatePath = Path.Combine(helpDirectory, entryPath);
    string resolvedPath = Path.GetFullPath(candidatePath);

    if (!resolvedPath.StartsWith(canonicalHelpDir, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException(
            $"CAB entry path is invalid. Entry '{entryPath}' would extract to '{resolvedPath}' which is outside the intended directory '{canonicalHelpDir}'");

    return resolvedPath;
}
```

...called from both `FdintCOPY_FILE` (creating the extracted file) and `FdintCLOSE_FILE_INFO`
(setting its attributes/timestamp) in `FdiNotify`, with any validation failure causing the CAB
entry to be rejected (`return new IntPtr(-1)` / `new IntPtr(0)`).

**v7.6.5** (`7acb29279dd64e646d821f75d1cc8ad59455a9a6`), the current tip of the release branch —
`ValidateExtractionPath` no longer exists anywhere in the file; `FdintCOPY_FILE` is now:

```csharp
case FdiNotificationType.FdintCOPY_FILE:
{
    // TODO: Should I catch exceptions for the new functions?

    // Copy target directory
    string destPath = Marshal.PtrToStringAnsi(fdin.pv);

    // Split the path to a filename and path
    string fileName = Path.GetFileName(fdin.psz1);
    string remainingPsz1Path = Path.GetDirectoryName(fdin.psz1);
    destPath = Path.Combine(destPath, remainingPsz1Path);

    Directory.CreateDirectory(destPath); // Creates all intermediate directories if necessary.

    // Create the file
    string absoluteFilePath = Path.Combine(destPath, fileName);
    return CabinetNativeApi.FdiOpen(absoluteFilePath, (int)OpFlags.Create, (int)(PermissionMode.Read | PermissionMode.Write));
}
```

`fdin.psz1` is the path string taken directly from the CAB archive entry (attacker-controlled —
it's whatever the malicious/tampered CAB file declares). `Path.GetDirectoryName`/`Path.GetFileName`
do **not** reject `..` traversal segments, rooted paths, or drive-letter/UNC prefixes; they just
split a string on separator characters. `Path.Combine(destPath, remainingPsz1Path)` happily walks
back out of `destPath` for every `..` component present. There is no check anywhere in this
function, or in the sibling `FdintCLOSE_FILE_INFO` case (which now does
`Path.Combine(destPath, fdin.psz1)` directly, same problem), that the resulting `absoluteFilePath`
is still inside the intended help directory. The leftover `// TODO: Should I catch exceptions for
the new functions?` comment is original, pre-fix code — this is exactly what the file looked like
before PR #167 was ever written; v7.6.5 was simply never given that patch (see "Correction" above
for the confirmed mechanism: two branch-specific backports, neither targeting this branch, and
nothing merged to master).

## Reachability

`CabinetExtractorFactory.GetCabinetExtractor().Extract(...)` (the only consumer of this class) is
called from exactly one place: `UpdatableHelpSystem.cs:1149`, the implementation backing
`Update-Help` and `Save-Help`. Both cmdlets download (or, via `-SourcePath`, read from an
arbitrary attacker-suppliable path/share) a CAB archive of help content and extract it through
this code. A crafted CAB whose internal entry names contain `..\..\..\` sequences (or an absolute/
UNC path, or a `:`-suffixed alternate-data-stream name — all three classes of input the deleted
function used to reject) can now write files to **any location the current user's process can
write to**, not just the intended help-content directory.

## Impact

This is a textbook Cab-Slip / Zip-Slip arbitrary file write, and from there straight to RCE: an
attacker who can get a target to run `Update-Help`/`Save-Help` against a malicious or
tampered/MITM'd help-content source (a spoofed update endpoint, a compromised internal file share
used as `-SourcePath` in an enterprise/air-gapped deployment, or a supply-chain-compromised module
publisher's custom help package) can drop a file at, for example, the current user's PowerShell
profile script, a Startup-folder shortcut/script, or any other auto-run location reachable by the
running account — executing attacker code the next time PowerShell (or the machine) starts, with
no further interaction needed beyond the initial help update.

## External CVE context (which CVE this backport gap most likely leaves unfixed)

Searched for what security fixes shipped in and around this release for context, per the request:

- **CVE-2026-50523** (CVSS 3.1: 7.8, CWE-77 command injection) — confirmed via a separate part of
  this same diff to be the SSH-remoting argument-injection issue in
  `RunspaceConnectionInfo.cs` (`New-PSSession -HostName`/`-UserName`/`-Port`/`-Options` values were
  embedded unescaped into `ssh` command-line arguments, letting a value containing a space or quote
  inject extra `ssh` arguments — including `-o ProxyCommand=<attacker command>`). Fixed correctly
  in v7.6.5 (and backported to v7.4.19/v7.5.10, both of which already had the safe pattern when
  checked directly). This one *is* a real, effective fix — no regression here.
  [NVD: CVE-2026-50523](https://nvd.nist.gov/vuln/detail/CVE-2026-50523)
- **CVE-2026-70337** — described in public tracking as an "Important" PowerShell Core **path
  traversal** issue from the same August 2026 Patch Tuesday batch, with Microsoft's own advisory
  oddly citing a "PowerShell 7.6.5" as the fixed version before that tag existed publicly (flagged
  by the PowerShell team itself: [PowerShell/PowerShell#27834](https://github.com/PowerShell/PowerShell/issues/27834)).
  Given the description (path traversal, PowerShell Core, same general timeframe) and that
  `ValidateExtractionPath` is the only path-traversal-shaped fix found in this codebase, this is
  the leading candidate for the CVE PR #167 was written to close — and its absence from v7.6.5
  (and master) means that CVE's protection isn't present in ongoing/current PowerShell, regardless
  of what shipped in the 7.4.19/7.6.4 point releases specifically.
- **CVE-2026-70338** (CWE-94, code generation/"auth bypass") — matches the *other* notable change
  in this diff, `ScriptWriter.cs`'s "Add the xsd validation back for CIM cmdlets" (restoring XSD
  schema validation for `.cdxml` cmdletization files, plus a new `invalid_verb.cdxml` test asset).
  Public description ("PowerShell constructs executable statements from input without sufficient
  validation... attacker-supplied content escapes the intended data context and is treated as
  executable code... a malicious script, module, configuration, or input file") matches a
  cmdletization-XML-generates-PowerShell-code path well. This one *does* appear correctly restored
  in v7.6.5 (verified: no similar removal pattern here, the validation call is present and wired
  up) — noted for context, not flagged as a regression.
- **CVE-2026-40400** — a separate Windows PowerShell RCE from June 2026 Patch Tuesday (CVSS 8.0),
  unrelated to this diff (predates the v7.6.4 baseline); noted for background context only, not
  independently investigated in this pass.

None of the above CVE mappings to `RunspaceConnectionInfo.cs`/`ScriptWriter.cs` were assumed —
each is corroborated by matching the public description to the actual code change. The
`CabinetNativeApi.cs` case is the one piece of this diff where the *fixed* branches (7.4.19,
7.6.4) and the *current* branches (7.6.5, master, 7.7 preview) disagree — which is why it's
flagged here as the primary finding even though, per the correction above, it isn't an active
regression.

## Suggested verification / next step

Build `pwsh` from the `v7.6.5` tag exactly as checked out here and run `Update-Help`/`Save-Help`
against a crafted CAB archive with a `..\..\..\evil.ps1`-style entry name to confirm the file
lands outside the help directory — this pass did not build/execute PowerShell itself, only
compared source across the two tags. Also worth checking whether this is specific to the public
GitHub tag (possibly a rebase/merge artifact not present in Microsoft's actual signed build) or
present in the shipped binaries too — the MSRC-advisory version-string confusion noted above
(referencing a "7.6.5" that didn't exist yet on GitHub) raises the possibility these have
diverged, which would need an actual built/signed `pwsh.exe` to check independently.

## Files

- `src/System.Management.Automation/help/CabinetNativeApi.cs` — the regression itself.
- `src/System.Management.Automation/help/UpdatableHelpSystem.cs:1149` — the reachability path
  (`Update-Help`/`Save-Help`).
