# mongo-tools (Database Tools) — `mongofiles get`/`get <multiple names>` bypasses the
# path-traversal / arbitrary-file-write guard that `get_regex`/`get_id` enforce (2026-08-30)

**Target:** `mongodb/mongo-tools` tag `100.18.0` (commit `21a342d`, the current latest Database
Tools release as of this audit), built from the exact release-tag source (official prebuilt
binaries could not be fetched in this sandbox — `fastdl.mongodb.org` is blocked by outbound
network policy — so the tool was built locally with the matching Go toolchain from the pinned
tag; this is source- and behavior-identical to the official release). Dynamically verified
against a real local `mongod` (8.3.8), standalone, no container/network target.

**Severity:** High — arbitrary local file write with fully attacker-controlled path and content,
in an officially shipped, widely used administrative tool.

## Summary

`mongofiles` already has a deliberate, documented safeguard against a malicious GridFS
`filename` field being used to write outside the operator's current directory — added in
`TOOLS-4019` (PR #853) and hardened for cross-platform edge cases in `TOOLS-4116` (PR #918). Its
own commit message states the intended scope precisely:

> "When `get`ting files by either a **regular expression** or **ID**, and the filename resolves
> to a path outside the current directory, mongofiles now refuses to restore the files."

That scoping is implemented literally: the guard in `getTargetGFSFiles()`
(`mongofiles/mongofiles.go:308`) is wrapped in `if len(mf.FileNameList) == 0 { ... }`.
`mf.FileNameList` is populated **only** for the plain `get <name...>` command
(`mongofiles.go:126-133`, shared with `put`); it stays empty for `get_regex` (uses
`FileNameRegex`) and `get_id` (uses `Id`). The practical effect: **`mongofiles get <name>` — the
single most common, most literally-named command in the tool — completely bypasses the guard
that `get_regex` and `get_id` correctly enforce**, including when the requested name resolves via
an exact-match query to a GridFS document whose stored `filename` is an absolute path or a
`../`-traversal path. No warning, no `--allowUnsafeTraversal` prompt — it just writes there.

## Why "the user typed the name themselves" doesn't hold in practice

The implicit reasoning for exempting `get <name>` looks like: *the user explicitly typed this
exact filename, so restoring to wherever it resolves is their own informed choice.* That
assumption breaks in the workflow the tool itself encourages:

1. `mongofiles list` prints GridFS filenames completely unsanitized
   (`mongofiles.go:200-201`, `display += fmt.Sprintf("%s\t%d\n", gridFile.Name, ...)`), with no
   flag, truncation, or warning for a name that is actually an absolute path or contains `..`.
2. The natural next step — for a human eyeballing a long list, and *especially* for any
   automation/scripting ("list what's there, then download each by name" is a far more common
   pattern to script than `get_regex`) — is `mongofiles get <name>` on entries read back from
   `list`, or a loop over all of them. Nothing in the tool signals that this specific path is
   unprotected while the superficially-similar `get_regex '.*'` (which *would* catch the same
   malicious name) is protected.
3. An attacker only needs *any* means of getting a `fs.files` document with a hostile `filename`
   into a bucket an operator will later browse/download from — direct insert access to a shared
   or multi-tenant database, a `mongofiles put --local <content> '<hostile-path>'` if they have
   write access, or a restored dump/import from an untrusted source.

## Reproduction (against the real built 100.18.0 binaries)

```
# attacker: plant a GridFS file whose stored name is an absolute path outside any operator's cwd
$ mongofiles --port 27777 --db test put --local payload.txt '/tmp/mongofiles_poc_absolute.txt'
2026-08-30T10:54:20.820+0000  added gridFile: `/tmp/mongofiles_poc_absolute.txt`

# victim (different, unrelated working directory), the *protected* path — correctly refused:
$ cd /some/safe/dir && mongofiles --port 27777 --db test get_regex '.*'
Failed: `/tmp/mongofiles_poc_absolute.txt` lies outside the current directory; set
--allowUnsafeTraversal if you really want to write to that path

# victim, the *unprotected* path — silently succeeds, zero warning:
$ mongofiles --port 27777 --db test get '/tmp/mongofiles_poc_absolute.txt'
2026-08-30T10:54:20.836+0000  finished writing to `/tmp/mongofiles_poc_absolute.txt`
$ cat /tmp/mongofiles_poc_absolute.txt
PAYLOAD-CONTENT-FROM-ATTACKER
```

Also confirmed for the multi-name form of `get` (mixing a legitimate name with the malicious
one in a single invocation — exactly what a "download this batch of files" script would do):

```
$ mongofiles --port 27777 --db test get 'report.csv' '/tmp/mongofiles_poc_multiname.txt'
finished writing to `/tmp/mongofiles_poc_multiname.txt`
finished writing to `report.csv`
```

Both writes succeed silently, side by side, with no indication that one of them landed
completely outside the intended directory.

## Root cause (precise)

`mongofiles/mongofiles.go`, `getTargetGFSFiles()`:

```go
if len(mf.FileNameList) == 0 {
    cwd, err := os.Getwd()
    ...
    for _, gf := range gridFiles {
        absPath, err := filepath.Abs(gf.Name)
        ...
        rel, err := filepath.Rel(cwd, absPath)
        ...
        if !filepath.IsLocal(rel) {
            if mf.StorageOptions.AllowUnsafeTraversal {
                log.Logvf(log.Always, "WARNING: %#q lies outside the current directory...", gf.Name)
            } else {
                return nil, fmt.Errorf("%#q lies outside the current directory; set --allowUnsafeTraversal...", gf.Name)
            }
        }
    }
}
```

`mf.FileNameList` is set in `ValidateCommand()` for the `Put, Get` case
(`mongofiles.go:126-133`) directly from the CLI positional arguments, and is left empty for
`GetRegex` and `GetID`. So the entire traversal check — the one piece of code that exists
specifically to stop a database-supplied `filename` from controlling where `mongofiles` writes
on disk — never runs at all when the command is plain `get`.

The eventual write happens in `writeGFSFileToLocal()` (`mongofiles.go:421-465`), which calls
`getLocalFileName(gridFile)` (returns `gridFile.Name` — the raw, DB-sourced filename — whenever
`--local` isn't given) and passes it straight to `os.Create`/`os.OpenFile` with no further
validation of any kind.

## Suggested fix

Apply the same `filepath.IsLocal`-based check unconditionally to every `gfsFile` about to be
written locally, regardless of which command produced it — i.e. move the check out from under
`if len(mf.FileNameList) == 0` (or apply it to `mf.FileNameList`-derived results too) so `get`
gets the identical protection `get_regex`/`get_id` already have. The `--allowUnsafeTraversal`
escape hatch is already there and works correctly for the other two commands; it just needs to
cover the third.

## Scope / eligibility note

This is `mongodb/mongo-tools`, mapping to the HackerOne MongoDB program's "Database Tools" scope
line (Executable type, Critical severity eligible) — real, official prebuilt binaries are
published at `https://www.mongodb.com/try/download/database-tools` for this exact tag/version.
