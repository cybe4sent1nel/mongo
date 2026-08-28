# PowerShell v7.6.5: path-traversal protection REMOVED from CAB extraction (regression, not a fix)

**Status: CONFIRMED via direct source comparison of the two official tags. This is the headline
finding of the requested v7.6.4→v7.6.5 diff. Severity: Critical (arbitrary file write → RCE).**

## Summary

`git diff v7.6.4 v7.6.5` shows that the entire path-traversal protection in PowerShell's CAB
(help-content) extraction code — a function called `ValidateExtractionPath`, present in **v7.6.4**
— was **deleted** in **v7.6.5**, and both of its call sites were reverted to naive, unvalidated
path construction. This is not a partial regression or an edge case: the whole defensive function
is gone, and nothing replaces it. The newer, "patched" release is the one that is currently
vulnerable to a classic Zip-Slip/Cab-Slip path traversal in `Update-Help`/`Save-Help`, one that a
public CVE (very likely CVE-2026-70337, see "External CVE context" below) appears to have been
issued to fix — meaning the officially tagged `v7.6.5` source does not actually contain that fix,
regardless of what Microsoft's advisory claims shipped.

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
is still inside the intended help directory. Even the leftover `// TODO: Should I catch exceptions
for the new functions?` comment reads like code that predates the validation being added in the
first place, suggesting this is a revert/rebase-onto-stale-branch mistake rather than an
intentional change — the changelog and PR history for v7.6.5 (below) don't mention touching this
file at all, which is consistent with an accidental reintroduction rather than a deliberate one.

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

## External CVE context (why this looks like a regression of an already-assigned CVE)

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
  Given the description (path traversal, PowerShell Core, same patch wave) and that this is the
  *only* path-traversal-shaped change in the entire v7.6.4→v7.6.5 diff, this is almost certainly
  the CVE this `ValidateExtractionPath` function was written to close — and its removal in the
  actual tagged v7.6.5 source means the shipped fix didn't take, at least not in this branch/tag.
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
`CabinetNativeApi.cs` regression is the one piece of this diff where the *source code* and the
*claimed fix* disagree, which is exactly why it's flagged here as the primary finding rather than
confirmation of an existing fix.

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
