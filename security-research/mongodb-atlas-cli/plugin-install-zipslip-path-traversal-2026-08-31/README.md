# mongodb-atlas-cli: Zip Slip path traversal in `atlas plugin install`/`update`

Finding from a targeted search for path-traversal (CWE-22) bugs across `github.com/mongodb`
repositories. Tag audited: `atlascli/v1.58.2`, commit `9724aaa0c78eeeee4810a8af04ebc47905ca2104`.

See `HACKERONE-REPORT.md` for the full write-up. Short version: `extractArchive()` in
`internal/cli/plugin/plugin_github_asset.go` extracts a GitHub-release archive (`.tar.gz`/`.zip`)
by computing each entry's destination as `filepath.Join(pluginDirectoryName,
strings.TrimPrefix(fileInfo.NameInArchive, prefix))`, with **no check that the result stays
inside `pluginDirectoryName`**. A malicious plugin release containing an entry named e.g.
`../../../../.bashrc` writes directly into the victim's home directory instead of the intended
`~/.config/atlascli/plugins/<owner>@<name>/` sandbox — classic Zip Slip, with a direct path to
code execution via `~/.bashrc`, `~/.ssh/authorized_keys`, cron, etc.

Reachable via both `atlas plugin install <owner>/<repo>` (installing anything
attacker-controlled) and `atlas plugin update` (a previously-trusted plugin's *later* release, if
its maintainer's account/CI is compromised). The optional signature-verification step provides no
protection against either: it only runs at all if the release happens to include `.sig`/
`signature.asc` assets, and simply logs a warning (not an error) when they're absent.

## Files

- `zipslip_poc_test.go` — the actual PoC: an in-package Go test (`package plugin`, dropped into
  `internal/cli/plugin/` in a checkout of the real repo) that builds a malicious `.tar.gz` and
  drives the real, unexported `extractArchive()` function directly, then asserts a file landed
  outside the intended plugin directory.

## Running it

```
cp zipslip_poc_test.go <atlas-cli-checkout>/internal/cli/plugin/
cd <atlas-cli-checkout>
go test ./internal/cli/plugin/... -run TestExtractArchive_ZipSlip_PathTraversal -v
```

Expected output:
```
escape entry name baked into the malicious archive: "../../../pwned-by-plugin-install"
CONFIRMED path traversal: extractArchive() wrote ".../home/victim/pwned-by-plugin-install"
  (outside intended plugin directory ".../home/victim/.atlas/atlas-cli-plugins/attacker@evil-plugin")
--- PASS: TestExtractArchive_ZipSlip_PathTraversal
```

## Other repos checked this pass, no path-traversal surface found

- **`mongo-python-driver`** (pymongo, `4.17.0`) — `gridfs/` is pure buffer-to-buffer, no local
  file I/O anywhere in the driver itself.
- **`mongo-cxx-driver`** (`r4.5.1`) — same result, confirmed via an exhaustive grep for
  `ofstream`/`ifstream`/`fopen`/`std::filesystem` across the whole `src/` tree: zero matches.
- **`mongodb-atlas-cli`'s own `download` commands** (`atlas backups snapshots download`,
  `atlas logs download`, `atlas streams instance download`) — all single-file downloads where the
  local output path (`--out`) is either supplied directly by the invoking user or derived from a
  fixed/enum-validated argument (e.g. `logname` is constrained to a 5-item `ValidArgs` list); none
  of them derive a local path from untrusted server/API response data, and none extract an
  archive with multiple internally-named entries. The plugin system above is the one place in
  this CLI that does both (untrusted remote content + multi-entry archive extraction), which is
  exactly why it's the one that's vulnerable.
