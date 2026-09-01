# Title

Zip Slip: `atlas plugin install`/`atlas plugin update` extract archive entries with no path-traversal containment check, allowing a malicious or compromised plugin's GitHub release to write arbitrary files anywhere on the victim's filesystem (e.g. `~/.bashrc`, `~/.ssh/authorized_keys`) — a direct path to code execution

## Summary

`mongodb-atlas-cli`'s plugin system (`atlas plugin install <owner>/<repo>`, and `atlas plugin update`) downloads a release archive (`.tar.gz` or `.zip`) from a GitHub repository the user names, and extracts it locally using `extractArchive()` in `internal/cli/plugin/plugin_github_asset.go`. For every entry in the archive, the destination path is computed as:

```go
destPath := filepath.Join(pluginDirectoryName, strings.TrimPrefix(fileInfo.NameInArchive, prefix))
```

**`fileInfo.NameInArchive` — the entry's own path, taken verbatim from inside the untrusted archive — is never checked for `../` segments, never required to stay under `pluginDirectoryName`, and `filepath.Join` does not enforce any such containment on its own.** I confirmed empirically (via a Go test that drives this exact, unexported function directly) that a release archive containing an entry such as `../../../pwned-by-plugin-install` (or, in the real default plugin directory layout, `../../../../.bashrc`) causes the CLI to write a file **outside** the intended plugin directory, at a location entirely of the archive author's choosing.

The optional "signature verification" step provides no real protection: it only runs `if sigAssetID != 0 && pubKeyAssetID != 0` — i.e., **only if the release happens to include a `.sig` asset and a `signature.asc` public key asset**. An attacker publishing their own malicious plugin release simply omits both, and the code proceeds anyway with nothing but a warning log line (`"no corresponding signature asset found"`) — not a hard failure. There is no requirement anywhere that a plugin be signed to be installed.

Because the affected code is shared by both `atlas plugin install` (any first-time install of an attacker-controlled or attacker-compromised repository) and `atlas plugin update` (any subsequent release of a *previously legitimate* plugin, if its maintainer's account or CI is later compromised — a classic supply-chain scenario), this is reachable in both the "install something new and malicious" and "a plugin you already trusted goes bad later" threat models.

## Weakness

CWE-22 (Path Traversal) via unsanitized archive-entry names during extraction ("Zip Slip") → arbitrary file write outside the intended directory, with a direct, well-known escalation path to code execution (overwriting shell startup files, `~/.ssh/authorized_keys`, cron files, etc., in the CLI user's own account).

## Authentication Required

**None beyond what the feature already requires: the user themselves running `atlas plugin install <owner>/<repo>` (or `atlas plugin update`) against a repository the attacker controls or has compromised.** No MongoDB Atlas credentials, no special privileges, and no interaction beyond the plugin-install/-update command the user already intends to run. The attacker's contribution is solely the content of the GitHub release archive being installed/updated — something entirely outside the Atlas CLI's own trust boundary once a user points the command at a malicious or compromised repository (a realistic scenario given plugins are explicitly a third-party extension mechanism: `atlas plugin install <github-owner>/<github-repository-name>`).

## Component / Version

- Repository: `mongodb/mongodb-atlas-cli` (HackerOne scope: **Atlas CLI**)
- Tag audited: `atlascli/v1.58.2` (confirmed latest by both `git tag --sort=-v:refname` on the `atlascli/` prefix and `--sort=-creatordate` across all tags; the repo also carries an older, separate `mongocli/` tag lineage, not relevant here)
- Commit: [`9724aaa0c78eeeee4810a8af04ebc47905ca2104`](https://github.com/mongodb/mongodb-atlas-cli/commit/9724aaa0c78eeeee4810a8af04ebc47905ca2104)
- Confirmed with a from-source Go build/test (`go1.24.7`, toolchain auto-upgraded to `go1.26.0` per `go.mod`) against the actual, unmodified `internal/cli/plugin` package.

## Root cause, with links to the exact code

[`internal/cli/plugin/plugin_github_asset.go#L405-L476`](https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/plugin_github_asset.go#L405-L476), `extractArchive`:

```go
func extractArchive(ctx context.Context, pluginArchivePath string, pluginDirectoryName string) error {
	// Strip prefix
	prefix, err := getArchivePrefix(ctx, pluginArchivePath)
	...
	format, _, err := archives.Identify(ctx, pluginArchivePath, archiveFile)
	...
	ex, ok := format.(archives.Extractor)
	...
	if err := ex.Extract(ctx, archiveFile, func(_ context.Context, fileInfo archives.FileInfo) error {
		// Get the destination path
		destPath := filepath.Join(pluginDirectoryName, strings.TrimPrefix(fileInfo.NameInArchive, prefix))   // <-- L434, no containment check

		if fileInfo.IsDir() {
			return os.MkdirAll(destPath, fileInfo.Mode())
		}
		...
		if err := os.MkdirAll(filepath.Dir(destPath), os.ModePerm); err != nil { ... }

		destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileInfo.Mode())   // <-- writes wherever destPath resolved to
		...
		if _, err := io.Copy(destFile, file); err != nil { ... }
		return nil
	}); err != nil { ... }

	return nil
}
```

`fileInfo.NameInArchive` comes straight from the archive being extracted (via `github.com/mholt/archives`, which — I confirmed directly — passes entry names through completely unmodified, including any `../` segments they contain). `filepath.Join` performs no sandboxing: it lexically concatenates and `Clean`s the result, which is exactly the mechanism that lets `../` segments walk back out of `pluginDirectoryName` — that is the entire Zip Slip bug class, and nothing in this function guards against it (no `filepath.Rel` + reject-if-starts-with-`..` check, no `strings.HasPrefix(destPath, pluginDirectoryName)` check, nothing).

`getArchivePrefix` ([lines 478-500](https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/plugin_github_asset.go#L478-L500)) only strips a prefix when the archive root contains **exactly one** entry that is a directory — an attacker crafting a malicious archive doesn't even need to think about this: placing the malicious entry as a second root-level entry (trivial to do) makes `prefix` empty and the entry name is used completely verbatim.

Both call sites reach this code identically:
- `atlas plugin install`: [`install.go#L117`](https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/install.go#L117) → `extractPluginAssetArchiveFile` → `extractArchive`
- `atlas plugin update`: [`update.go#L177`](https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/update.go#L177) → `extractPluginAssetArchiveFile` → `extractArchive`

The optional signature check that could otherwise have mitigated a compromised-release scenario is bypassable simply by omitting the signature assets ([`getSignatureAssetandKeyID`, lines 247-278](https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/plugin_github_asset.go#L247-L278)):

```go
if signatureAsset == nil {
	_, _ = log.Warningf("-- plugin warning: no corresponding signature asset found for package %s\n", name)
	return 0, 0, nil   // <-- proceeds anyway; verification is simply skipped
}
```

## Steps to Reproduce

Built and tested against `atlascli/v1.58.2` (`9724aaa0c78eeeee4810a8af04ebc47905ca2104`) with Go, driving the exact unexported `extractArchive` function via an in-package test (this is not a reimplementation — it is the real, unmodified function from the real checked-out source):

```go
func TestExtractArchive_ZipSlip_PathTraversal(t *testing.T) {
	tmp := t.TempDir()

	// Mirrors the real default plugin directory layout:
	// $XDG_CONFIG_HOME/atlascli/plugins/<owner>@<name>/
	pluginsRoot := filepath.Join(tmp, "home", "victim", ".atlas", "atlas-cli-plugins")
	pluginDirectoryPath := filepath.Join(pluginsRoot, "attacker@evil-plugin")
	os.MkdirAll(pluginDirectoryPath, 0o755)

	// A high-value target outside the plugin directory entirely --
	// stands in for ~/.bashrc, ~/.ssh/authorized_keys, etc.
	targetFile := filepath.Join(tmp, "home", "victim", "pwned-by-plugin-install")
	escapeEntryName, _ := filepath.Rel(pluginDirectoryPath, targetFile) // "../../../pwned-by-plugin-install"

	archivePath := filepath.Join(tmp, "malicious-plugin-release.tar.gz")
	buildMaliciousTarGz(t, archivePath, escapeEntryName, "pwned\n") // a plausible-looking plugin archive, plus this one entry

	err := extractArchive(context.Background(), archivePath, pluginDirectoryPath)
	// err == nil -- extractArchive raises no error and happily writes the file
	data, _ := os.ReadFile(targetFile)
	// data == "pwned\n" -- the file now exists OUTSIDE pluginDirectoryPath
}
```

**Result:**

```
escape entry name baked into the malicious archive: "../../../pwned-by-plugin-install"
CONFIRMED path traversal: extractArchive() wrote "/tmp/.../home/victim/pwned-by-plugin-install"
  (outside intended plugin directory "/tmp/.../home/victim/.atlas/atlas-cli-plugins/attacker@evil-plugin")
  from a malicious archive entry
--- PASS: TestExtractArchive_ZipSlip_PathTraversal
```

The real default plugin directory (confirmed by reading `plugin.GetDefaultPluginDirectory()` → `atlas-cli-core`'s `config.CLIConfigHome()`) is `$XDG_CONFIG_HOME/atlascli/plugins/<owner>@<name>/` — the same nesting depth used in this PoC (three directories deep before the plugin's own directory). A real attacker would use an entry named `../../../../.bashrc` (or `.profile`, `.ssh/authorized_keys`, a user crontab path, etc.) to land the write directly in the victim's home directory. I did not need to guess this depth: it's derivable from `GetDefaultPluginDirectory()`'s own source, and — since the archive layout the extractor accepts is entirely attacker-controlled — an attacker can trivially include several copies of the malicious entry at a few different depths to cover any uncertainty, or an installed plugin's manifest.yml (which is validated only *after* extraction — see `validatePlugin` in `install.go`) is irrelevant to whether the traversal write already happened.

I also confirmed independently that `github.com/mholt/archives` (the extraction library in use) passes `NameInArchive` through with any `../` sequences intact — it performs no sanitization of its own, so the entire containment responsibility falls on `extractArchive`, which has none.

Both `.tar.gz` and `.zip` release assets are accepted by this same code path (`contentTypePriority` in `plugin_github_asset.go` lists both `application/gzip`/`application/x-gtar`/`application/x-gzip` and `application/zip`), and the vulnerable line operates on the archive-format-agnostic `archives.FileInfo.NameInArchive`, so this is not specific to one archive format.

## Impact

Any user who runs `atlas plugin install <owner>/<repo>` against a malicious or later-compromised GitHub repository — including via `atlas plugin update` on a plugin that was legitimate at install time but whose maintainer's account or CI pipeline is compromised afterward — can have arbitrary files written anywhere their own OS-level permissions allow, with content and location entirely chosen by the archive's author. This is a direct, well-trodden path to code execution: overwriting `~/.bashrc`/`~/.profile`/`~/.zshrc` (executes on the victim's next shell), `~/.ssh/authorized_keys` (grants the attacker remote SSH access), a user crontab or systemd user unit (executes on a timer/next login), or git hooks, IDE startup scripts, etc. None of this requires any privilege beyond what the CLI process itself already has as the invoking user. The "signature verification" feature does not mitigate this: it is optional, and any attacker publishing their own malicious release simply omits the signature assets, hitting only a warning log line, never a hard failure.

## Suggested Fix

In `extractArchive`, after computing `destPath`, verify it stays within `pluginDirectoryName` before creating any directory or file — e.g.:

```go
cleanDest := filepath.Clean(destPath)
if !strings.HasPrefix(cleanDest, filepath.Clean(pluginDirectoryName)+string(os.PathSeparator)) {
    return fmt.Errorf("plugin archive entry %q attempts to write outside the plugin directory", fileInfo.NameInArchive)
}
```
(or equivalently, use `filepath.Rel(pluginDirectoryName, destPath)` and reject any result starting with `..`). This is the standard Zip Slip mitigation and should be applied unconditionally, independent of whether `prefix` stripping succeeded. Separately, plugin installation should not silently proceed when a release has no signature — at minimum, require an explicit opt-in flag (distinct from `--skipSignatureVerification`, which today makes unsigned-by-default look identical to unsigned-by-choice) or a hard warning/prompt before installing an unsigned plugin, since right now there is no meaningful difference in user experience between "this maintainer chose not to sign" and "this is entirely unverified content from anyone with a GitHub account."

## Supporting Material

- Vulnerable extraction loop: https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/plugin_github_asset.go#L405-L476
- Optional, bypassable signature check: https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/plugin_github_asset.go#L247-L278
- `install` call site: https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/install.go#L117
- `update` call site: https://github.com/mongodb/mongodb-atlas-cli/blob/9724aaa0c78eeeee4810a8af04ebc47905ca2104/internal/cli/plugin/update.go#L177
- `zipslip_poc_test.go` (included in this directory) — full working PoC, an in-package Go test driving the real, unmodified `extractArchive` function
