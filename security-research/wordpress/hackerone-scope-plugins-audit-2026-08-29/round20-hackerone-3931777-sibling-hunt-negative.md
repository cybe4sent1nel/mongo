# Round 20: sibling hunt off disclosed HackerOne #3931777 (arbitrary file deletion via
# `finalize_item()` poisoning `_wp_attachment_metadata`/`_wp_attachment_backup_sizes`) —
# thorough search across WP core and all four in-scope plugins, honest negative result

Prompted by the just-disclosed public report #3931777 (jakubk, resolved, Critical 9.9, fixed in
WordPress core and Gutenberg for 7.1). Task: use that report's exact bug *shape* — a path-confinement
check whose "trusted" boundary is derived from the same attacker-controlled value it's supposed to
constrain — as a search pattern, and hunt exhaustively for (a) whether the fix is actually complete,
(b) any other core code path that reopens the same primitive, and (c) the same shape of bug anywhere in
the four in-scope plugins. Verified against live-fetched current `WordPress/wordpress-develop` trunk
(pulled fresh this round, commit `d30211ee31`) and `WordPress/gutenberg` trunk (pulled fresh, commit
`81b67be370`), not a stale local snapshot.

**Result up front: the disclosed bug's root sink is still structurally fragile, but every path that
could feed it an untrusted value is now closed. No live sibling found in core, and none found in any
of the four in-scope plugins after checking every file-deletion call site in each.**

## 1. Re-verifying the fix is real, and understanding exactly what it does and doesn't cover

`wp_delete_attachment_files()` (`wp-includes/post.php`, current trunk) — the `$backup_sizes` branch the
report identified — is **unchanged**:

```php
if ( is_array( $backup_sizes ) ) {
    $del_dir = path_join( $uploadpath['basedir'], dirname( $meta['file'] ) );   // still attacker-shaped

    foreach ( $backup_sizes as $size ) {
        $del_file = path_join( dirname( $meta['file'] ), $size['file'] );      // still attacker-shaped
        ...
        if ( ! wp_delete_file_from_directory( $del_file, $del_dir ) ) { ... }
    }
}
```

Every other branch of the same function (`thumb`, `sizes`, `original_image`, `source_image`,
`animated_video*`, and the final main-file delete) derives its confinement directory from `$file`
(the trusted `get_attached_file()` result passed in as a parameter) — confirmed by re-reading the full
function. **WordPress did not harden this sink.** What it did instead — and did thoroughly — is close off
the only way this branch's inputs (`$meta['file']`, `$meta['sizes'][*]['file']`) could ever contain an
attacker-chosen string in the first place.

### The actual fix: provenance-validated allowlist in `finalize_item()`

Current `class-wp-rest-attachments-controller.php` (both core trunk and Gutenberg trunk) adds:

- `sideload_item()` now writes every filename it *itself produces* (via `wp_basename()` of the real,
  server-saved sideload path — never the client's own string) into a new
  `META_KEY_SIDELOAD_FILE_NAME` post-meta row as provenance.
- `finalize_item()` now calls `validate_sub_size_provenance( $attachment_id, $sub_sizes )` before writing
  anything: every `file`/`original_image` value in the request must appear in
  `get_sideloaded_file_names()` — the union of (a) filenames this attachment's own prior sideloads
  actually produced, (b) the attachment's own `_wp_attached_file` (in both relative and basename form),
  and (c) names already present in the attachment's own, previously-validated metadata. Anything else is
  rejected with `rest_invalid_sub_size_file` before it ever reaches `wp_update_attachment_metadata()`.

Reproduced the original PoC's poisoning step (`sub_sizes: [{"file": "wp-config.php", ...}]`) mentally
against this check: `wp-config.php` is not a name any real sideload for that attachment could have
produced (sideload paths are always inside the uploads directory, under that attachment's own
subdirectory), so `validate_sub_size_provenance()` rejects it. Confirmed by code reading this closes the
*entire* reported chain, including the `wp_ajax_image_editor()` laundering step — that step only ever
copies from `$meta['sizes']`, which by the time it's stored has already passed this same check.

### Why this still isn't defense in depth — a real observation, not a live bug

Because the fix is entirely at one entry point rather than at the sink, the underlying invariant
`wp_delete_attachment_files()` needs (`$meta['file']` is always trustworthy) is being upheld by
*discipline at the call site*, not by anything in the sink itself. If any future code path — a new REST
route, a new AJAX action, an XML-RPC method, or a plugin — ever calls `wp_update_attachment_metadata()`
with a `file`/`sizes[*].file` value it didn't itself generate, the exact same primitive reopens
immediately, silently, with no additional signal. That is a legitimate hardening recommendation
(harden the sink per the original report's Recommendation #2, which explicitly wasn't required to close
the reported bug but was suggested "regardless"). It is not, on its own, a demonstrated vulnerability,
and I am not presenting it as one — the search below is the actual answer to "is there a live path today."

## 2. Full inventory of every current write-site of the two meta keys in WP core — all checked, all closed

Grepped `wp-includes` and `wp-admin` for every `wp_update_attachment_metadata(` call and every direct
reference to `'_wp_attachment_metadata'` / `'_wp_attachment_backup_sizes'`:

| Call site | What it passes | Safe? |
|---|---|---|
| `class-wp-rest-attachments-controller.php` (`finalize_item()`) | Provenance-validated, per above | Yes |
| `class-wp-xmlrpc-server.php:6632` | `wp_generate_attachment_metadata( $id, $upload['file'] )` | Yes — server regenerates from the real uploaded file |
| `class-wp-customize-manager.php:1376-1377` | `wp_generate_attachment_metadata( $id, $attached_file )` | Yes — same |
| `class-wp-site-icon.php:230` | Read-side `get_post_metadata` filter only, no write | N/A |
| `class-custom-background.php:551` | `wp_generate_attachment_metadata( $id, $file )` | Yes |
| `class-custom-image-header.php:881` | `wp_generate_attachment_metadata( $id, $file )` | Yes |
| `class-custom-image-header.php:1376` (`insert_attachment()`) | `wp_generate_attachment_metadata( $id, $cropped )`, then only `attachment_parent` (an int) is merged in before the `wp_header_image_attachment_metadata` filter (theme/plugin-controlled, not a remote-attacker input) | Yes |
| `image-edit.php` (`wp_save_image()`, backup_sizes write) | Copies `$meta['sizes'][$size]` — already-validated data by the time it's stored | Yes, conditional on the above |
| `post.php` / `media.php` (regular attachment save/generate paths) | `wp_generate_attachment_metadata()` | Yes |

Every single write path either regenerates metadata straight from a real, server-controlled file
(`wp_generate_attachment_metadata()` — itself checked: filenames it emits pass through
`sanitize_file_name()`, which strips `/` and `\` outright and collapses any run of two or more dots to
one, closing traversal at the filename-generation layer too), or goes through the new provenance
allowlist. No gap found.

## 3. All four in-scope plugins — every file-deletion call site checked individually

```
$ grep -rn "unlink(\|wp_delete_file(\|rmdir(\|wp_delete_file_from_directory(" (each plugin, tests excluded)
```

**Classic Editor** — zero matches. The plugin does not delete files at all.

**SQLite Database Integration** — zero matches. No file-deletion code exists in this plugin.

**Create Block Theme** — every match checked:

- `theme-media.php:395,407` and `theme-zip.php:95,100,316,326` — all `@unlink()` calls target
  `download_url()`'s own return value, a uniquely-named temp file **WordPress itself creates**
  server-side; never an attacker-chosen path.
- `theme-utils.php:158` (`replace_screenshot()`) — deletes `wp_get_theme()->get_screenshot('relative')`.
  Read WP core's `WP_Theme::get_screenshot()` directly: it returns *only* one of six hardcoded literals
  (`screenshot.png|gif|jpg|jpeg|webp|avif`), chosen by which one actually exists on disk — never derived
  from any external input at all. Not exploitable by construction.
- `theme-fonts.php:394` (`remove_deactivated_font_assets()`) — the closest-shaped candidate: builds
  `$file_path = get_stylesheet_directory() . '/assets/fonts/' . basename( $font_src )` and unlinks it.
  Traced `$font_src`'s origin fully: it comes from the *current theme's own, already-persisted*
  `theme.json` (`CBT_Theme_JSON_Resolver::get_theme_file_contents()`), not a live request body, so even
  reaching this code requires font data to have been written to theme.json by an earlier, separately-
  gated step. More importantly, `basename( $font_src )` is applied *before* concatenation — unlike the
  disclosed bug, which had no path-stripping step at all and instead relied on a (broken) after-the-fact
  containment check, this code structurally cannot construct a path outside `/assets/fonts/` regardless
  of what `$font_src` contains: `basename('../../../wp-config.php')` returns the literal string
  `wp-config.php`, and the resulting delete target is `{theme}/assets/fonts/wp-config.php` — nowhere
  near the real `wp-config.php`. Confirmed safe by construction, not merely by the current caller's
  input being trusted.
- `resolver_additions.php:167` — same `download_url()`-temp-file-cleanup shape as above. Safe.

**Secure Custom Fields** — every match checked:

- `local-json.php:334,344` (`delete_allowed_file()`) — already hardened with the *correct* pattern: an
  independently-built allowlist (`get_multisite_allowed_write_paths()`), each candidate directory
  resolved via its own `realpath()` and confirmed inside the uploads base directory (explicitly
  excluding the multisite cross-tenant `sites/` subdirectory — a deliberate, specific hardening
  decision), rather than a boundary derived from the file being deleted. Docblocked `@since SCF 6.9.3`,
  i.e. this is itself the product of a prior hardening pass, not incidental.
- `api-helpers.php:2521` — deletes a file only ever equal to `$file['file']` from the *current* user's
  own just-completed `wp_handle_upload()` result, immediately after a Ghostscript/PostScript-content
  check rejects it. Never an attacker-chosen path unrelated to the current upload.

## Conclusion

This was a genuinely wide search — every write-site of the two vulnerable meta keys in current core, and
every file-deletion call in all four in-scope plugins, individually traced to its data source rather than
pattern-matched superficially. The honest result is negative: the disclosed vulnerability's fix holds up
under scrutiny (via allowlisting at the entry point, not sink hardening, which is worth flagging as a
standing recommendation but is not itself exploitable today), and no plugin in scope has an analogous
unconfined deletion primitive. Not fabricating a finding to match the pattern where none was found.
