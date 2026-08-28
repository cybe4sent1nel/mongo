# Sibling/fresh-bug sweep: zip extraction and dangerous deserialization

Quick, separate checks run alongside the CAB-traversal forensics, per the request to look more
broadly for fresh RCE bugs and siblings of the traversal issue.

## Zip extraction (`UpdatableHelpSystem.cs`, non-Windows help-content path) — safe

The only other archive-extraction call in the codebase besides the CAB path is
`zipArchive.ExtractToDirectory(destination)` in `UpdatableHelpSystem.cs:1100` — the non-Windows
counterpart to the CAB extraction (Windows uses `cabinet.dll` via `CabinetNativeApi.cs`; other
platforms use a plain `.zip`). This is the **.NET BCL's own** `ZipFileExtensions.ExtractToDirectory`,
not a custom implementation. .NET Core has shipped built-in Zip Slip protection in this method
since its original Zip Slip disclosure response (it throws if an entry would extract outside the
destination directory) — so this path doesn't share the CAB code's gap; it was never hand-rolled
in the first place. Not a sibling.

## Dangerous deserialization APIs — none present

Grepped the whole `src/` tree for the classic .NET universal-gadget-chain deserializers
(`BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`) — zero
hits outside test code. PowerShell's own remoting/PSRP serialization uses its own CliXml format,
not these APIs.

## Conclusion

No additional sibling of the CAB path-traversal gap found in the other archive-handling code path
in this codebase, and no dangerous deserialization primitive present to chase as a separate fresh
RCE lead. The CIM/XSD comparison (see the main write-up in this directory) remains the most
useful additional data point: it shows the CAB fix's failure to propagate is closer to a one-off
than a blanket pattern, since a same-week sibling fix propagated cleanly.
