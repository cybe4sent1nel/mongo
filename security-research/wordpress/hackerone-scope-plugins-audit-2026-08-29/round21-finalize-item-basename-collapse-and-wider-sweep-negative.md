# Round 21: adversarial re-read of the #3931777 *fix itself*, plus a wider sweep of
# every other media-editing code path that touches the same fields — one genuine new
# logic quirk found and run to ground, everything else confirmed sound

Following up on Round 20 at the user's explicit request to dig deeper and widen the area, rather
than re-checking the same call sites: this round assumes the fix from #3931777 might itself have
a gap, and separately checks every *other* place in core (and Create Block Theme) that reads or
writes the same attachment-metadata fields, which Round 20 did not individually walk through.
Verified against the same freshly-pulled `WordPress/wordpress-develop` trunk as Round 20 (commit
`d30211ee31`).

**Result up front: one real, previously-undocumented logic quirk found and fully traced — it does
not cross the uploads directory boundary and does not reach reportable severity. Every other path
checked this round (`edit_media_item()`, the three `image-edit.php` AJAX functions, and Create
Block Theme's font/media/zip download pipeline) is sound.**

## 1. Adversarially re-reading the fix: does `finalize_item()`'s own allowlist have a gap?

`validate_sub_size_provenance()` (`class-wp-rest-attachments-controller.php:3087`) checks every
submitted `sub_size['file']` / `sub_size['original_image']` with a **strict** `in_array( ..., true )`
against `get_sideloaded_file_names()`'s allowlist. That allowlist
([`:3138`](https://github.com/WordPress/wordpress-develop/blob/d30211ee316ed5d41d3d1531e395440fa9f2ce6b/src/wp-includes/rest-api/endpoints/class-wp-rest-attachments-controller.php#L3138))
is built from three sources: the sideload-provenance meta rows, the attachment's own
`_wp_attached_file` (**in both its full relative-path form and its bare `wp_basename()` form**), and
every filename already stored in the attachment's own metadata (**also in both forms**). Since every
entry is a value WordPress itself already generated, `in_array(..., true)` being a strict exact-match
means an attacker cannot smuggle a `../`-laden string past this check — closing the traversal vector
outright. Confirmed no bypass exists for getting an arbitrary string past this specific check.

## 2. The real quirk: `finalize_item()` can collapse `$meta['file']` to a bare basename

`finalize_item()`'s `'original'`/`'scaled'` branch
([`:3336`](https://github.com/WordPress/wordpress-develop/blob/d30211ee316ed5d41d3d1531e395440fa9f2ce6b/src/wp-includes/rest-api/endpoints/class-wp-rest-attachments-controller.php#L3336))
does `$metadata['file'] = $sub_size['file'];` directly — this is the **top-level** `_wp_attachment_metadata['file']`
field, the same one `wp_delete_attachment_files()`'s fragile `backup_sizes` branch keys its directory
confinement off (`dirname( $meta['file'] )`, `wp-includes/post.php:7028`). Because the allowlist
includes bare-basename forms (`wp_basename( $attached_file )`, `wp_basename( $name )` for every
already-stored size), a client can legitimately submit a `sub_size` whose `file` value **is one of
those basenames** — a string with no `/` in it at all. `$metadata['file']` then becomes e.g.
`"photo-edited.jpg"` instead of `"2026/08/photo-edited.jpg"`.

Traced the consequence all the way through:

- `dirname( "photo-edited.jpg" )` evaluates to `"."`.
- In the still-fragile branch, `$del_dir` becomes `path_join( $uploadpath['basedir'], '.' )` — the
  **uploads base directory itself**, not a specific year/month subfolder.
- This *widens* (never narrows or escapes) the directory the confinement check will accept — still
  fully contained inside the uploads tree, never outside it.
- The only other input to that branch, `$backup_sizes`, is **never written by `finalize_item()` at
  all** — it's populated exclusively by the legacy `wp-admin/includes/image-edit.php` AJAX crop/rotate
  flow (`wp_save_image()`), which (re-verified below) only ever stores bare-basename values it derived
  from `get_attached_file()` or from already-validated `$meta['sizes']` — never from unvalidated
  request input. So even with `$del_dir` widened to the uploads root, the only filenames that branch
  will ever try to delete there are ones a previous, independently-safe code path already put in
  `_wp_attachment_backup_sizes`.

Net effect: this is a real, demonstrable logic quirk (`$meta['file']` can end up path-less when it's
normally expected to carry a subdirectory), but it does not produce an out-of-uploads-directory write
or deletion primitive, and reaching even the narrow within-uploads-root effect requires a second,
independently-safe data source to already contain a coincidentally-matching entry. **Not filing this as
a finding** — documenting it here because it's a genuine, previously-unnoted quirk in the fixed code,
not because it clears the Medium severity floor.

## 3. `edit_media_item()` (`POST /wp/v2/media/<id>/edit` — the REST-native crop/rotate/flip endpoint)

Not covered in Round 20 (which focused on `finalize_item()`/`sideload_item()`). Read in full
([`:1086`](https://github.com/WordPress/wordpress-develop/blob/d30211ee316ed5d41d3d1531e395440fa9f2ce6b/src/wp-includes/rest-api/endpoints/class-wp-rest-attachments-controller.php#L1086)).
Confirmed safe by construction: every edit (`flip`/`rotate`/`crop`) is applied to an in-memory
`WP_Image_Editor` instance and saved to a **brand-new** path built from `wp_unique_filename()` in the
uploads directory (`:1273`), then `wp_insert_attachment()` and `wp_generate_attachment_metadata()` are
called against that same server-generated path. No client-supplied filename or metadata field ever
reaches a filesystem path in this function.

## 4. Re-verifying the legacy `wp-admin/includes/image-edit.php` AJAX paths in full (not just grepped)

Round 20 didn't read these three functions end-to-end; done here:

- **`wp_save_image()`** (`:920`): every `$backup_sizes[$tag]['file']` written is either `$basename`
  (from `pathinfo( get_attached_file( $post_id ), PATHINFO_BASENAME )` — trusted) or a direct copy of
  `$meta['sizes'][$size]` (already-validated, per Round 20). Confirmed no request field flows into a
  `$backup_sizes` file value here.
- **`wp_restore_image()`** (`:815`): reads `_wp_attachment_backup_sizes` (never client-writable — see
  Round 20 §2) and writes it back via `path_join( $parts['dirname'], $data['file'] )`, where
  `$parts['dirname']` comes from `get_attached_file()` and `$data['file']` from the trusted backup-sizes
  entry above. `wp_delete_file()` calls in this function (`:841`, `:878`) only fire when the
  non-default `IMAGE_EDIT_OVERWRITE` constant is defined, and even then only ever target `$file` (the
  attachment's own current attached file) or `path_join( $parts['dirname'], $meta['sizes'][...]['file'] )`
  — same trusted-directory pattern as the safe branches in `wp_delete_attachment_files()`.
- **`stream_preview_image()`** (`:775`): streams image bytes to the browser via `wp_stream_image()`
  from `_load_image_to_edit_path()` — a read, not a write or delete, and the path itself is the
  attachment's own trusted attached-file path.

## 5. Create Block Theme's font/media/zip download pipeline — confirmed already comprehensively hardened

Went past Round 20's `unlink()`-only grep this time and read `copy_font_assets_to_theme()`
(`theme-fonts.php:255`) and its siblings in `theme-media.php`/`theme-zip.php` in full, since
`theme-fonts.php` carries visible, recent hardening comments (`is_allowed_font_url()`,
`is_allowed_font_file()` magic-byte checks). `git log` confirms this is a single commit,
[`da693bf` "Validate downloaded theme assets against extension and MIME allowlists (#852)"](https://github.com/WordPress/create-block-theme/commit/da693bf2b),
that hardened `theme-media.php`, `theme-fonts.php`, and `theme-zip.php` **together, in the same pass** —
exactly the "maintainer just hardened one instance" signal this audit relies on to hunt for a missed
sibling, except here all known download-and-write call sites received the treatment at once (confirmed
by grepping every `download_url(`/`copy(`/`file_put_contents(` call in the plugin — listed in full,
no additional unhardened download site found). Separately: every route that reaches this code
requires `edit_theme_options` or `edit_themes` (checked via `permission_callback` in
`class-create-block-theme-api.php`) — capabilities WordPress's own security model already treats as
functionally equivalent to full code-execution trust (an `edit_themes` holder can edit theme PHP files
directly), so even a hypothetical gap here would not cross a meaningful privilege boundary the way the
original #3931777 report's `upload_files`-gated endpoint did.

Also found one pre-existing, non-security logic quirk while reading `copy_font_assets_to_theme()`: the
"is this font hosted on this same site" check (`str_contains( $font_src, $font_dir['url'] )`, `:297`)
is a substring test, not an anchored prefix check, so a crafted URL could contain the site's font-dir
URL as a substring while pointing elsewhere. Traced the consequence: it does not enable traversal or
cross-site file access, because the resulting `$local_source` is always
`$font_dir['path'] . '/' . basename( wp_parse_url( $font_src, PHP_URL_PATH ) )` — confined to the
site's own trusted font directory regardless of what tricked the substring check, and still gated by
`is_allowed_font_file()`'s magic-byte check. Not reportable; noted for completeness only.

## Conclusion

This round deliberately did not repeat Round 20's ground. It adversarially re-read the disclosed bug's
*own fix* for a gap (found none exploitable — the allowlist's strict `in_array` closes the traversal
vector even though it produces the basename-collapse quirk documented in §2), and swept every other
attachment-editing code path in core plus Create Block Theme's asset-download pipeline that Round 20
didn't individually walk through. The honest result is still negative for a reportable (Medium+)
finding: one real quirk was found and is documented above for the record, but it's fully traced and
does not escape the uploads directory or cross a privilege boundary. Not fabricating a finding to
satisfy the search — if a different subsystem or a different plugin should be the next target, that's
a direction call worth making explicitly rather than continuing to re-scan the same media-metadata
surface a fourth time.
