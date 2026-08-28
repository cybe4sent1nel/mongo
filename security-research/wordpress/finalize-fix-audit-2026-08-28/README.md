# WordPress 7.1.0 / Gutenberg v23.8.0: does the `finalize_item()` fix hold, and does a fresh sibling exist?

Follow-up requested after HackerOne #3931771 (stored XSS via `get_media_item()`) and #3931777
(arbitrary file deletion via `wp_delete_attachment_files()`), both fixed for WordPress 7.1 /
Gutenberg. Task: clone the latest release that ships the fix and hunt for fresh bugs of the same
shape.

**Status: the fix itself holds up under a real bypass-hunting pass — no exploitable gap found in
it, and (unlike the PowerShell CAB finding earlier in this engagement) no backport gap between
core and the Gutenberg plugin either. What I do have is one concrete, evidenced architectural
finding worth flagging to the maintainers: the fix closes the bug at a single choke point rather
than defense-in-depth, and the two original sinks are still live and unescaped/unconfined
underneath it.**

Targets cloned fresh for this pass:
- `WordPress/wordpress-develop`, tag `7.1.0` (`daaca56d3d`, 2026-08-19) — the tag the disclosure
  comments say ships the fix.
- `WordPress/gutenberg`, tag `v23.8.0` (`ae8b34d78e`, 2026-08-19) — latest non-RC release.

## 1. The actual fix: `1c3261dca3` "REST API: Bind finalize sub-size file names to their sideload."

This is a substantially larger patch than the reports' own recommendations asked for. Instead of
(or in addition to) `esc_url()`-escaping the read side and `wp_basename()`-checking each field at
write time, WordPress rebuilt the whole trust model for `finalize_item()`:

- `sideload_item()` now records every file name it actually produces (always server-generated via
  `wp_unique_filename()` → `sanitize_file_name()`, never the raw client string) under a new
  `_wp_sideloaded_file` post meta row, scoped to that attachment.
- `sideload_item()` is also pinned to the attachment's own upload subdirectory via an `upload_dir`
  filter (`get_attachment_upload_subdir()`, which explicitly rejects a `..` component), so a
  produced name always resolves inside the directory it's later read against.
- `finalize_item()` now runs `validate_sub_size_provenance()` **before any metadata write**, over
  every `sub_size['file']` and `sub_size['original_image']` in the whole request — not just the
  ones headed for the `sizes` array. A value is accepted only if it is: a name a prior sideload
  actually recorded for this attachment, the attachment's own `_wp_attached_file` (relative or
  basename form), or a name already present in the attachment's own stored metadata. Anything else
  returns `rest_invalid_sub_size_file` (400) before any metadata is touched.

I checked this for the obvious gaps a change this size invites, and didn't find one:

- **Every branch is covered, not just the common one.** The original bug (both reports) was that
  `'file'` got written raw for the `'original'`/`'scaled'` sizes (`$metadata['file'] = ...`) and
  for the regular-sizes `else` branch (`$metadata['sizes'][$image_size]['file'] = ...`).
  `validate_sub_size_provenance()` iterates the *entire* `$sub_sizes` array up front, so it covers
  all of `'original'`/`'scaled'`, `IMAGE_SIZE_SOURCE_ORIGINAL`, `'animated_video'`,
  `'animated_video_poster'`, and the regular/array-grouped branches identically — there's no branch
  where a `file` or `original_image` value reaches `wp_update_attachment_metadata()` unchecked.
- **`sideload_item()`'s own route args take no `file`/`original_image` parameter at all** — `id`,
  `image_size`, `convert_format` are the only inputs; every recorded provenance name is computed
  server-side from the uploaded file's actual saved path. There's no way to get an attacker-chosen
  string into the allowlist in the first place.
- **`sanitize_file_name()` genuinely strips the characters both exploits needed.** Confirmed the
  current implementation (`wp-includes/formatting.php`) hard-codes `'`, `"`, `<`, `>`, `/`, `\` in
  its `$special_chars` strip list — the XSS report's `'` attribute break-out and the deletion
  report's path-traversal/absolute-path payloads both depend on characters this function removes
  before a name can ever be recorded as sideload provenance.
- **No parallel `original_image`-only bypass.** For the `'original'`/`'scaled'` branch,
  `sub_size_data['original_image']` is set server-side to `wp_basename($attached_file)` inside
  `sideload_item()`, not read from the request at all — and even so, it's still covered by the same
  provenance check when it's finally written in `finalize_item()`.
- **The "laundering" step from report #2 (poisoning `_wp_attachment_backup_sizes` via
  `wp_ajax_image_editor()`) is untouched by this patch and still copies `$meta['sizes'][$size]`
  verbatim** — but that's now moot rather than reopened, because `$meta['sizes'][$size]['file']`
  can no longer contain anything but a sanitized name by the time that code runs. Confirmed via
  `git diff 7.0.2..7.1.0 -- src/wp-admin/includes/image-edit.php`: the only changes there are
  unrelated null-safety fixes, not a security patch.
- **No sibling unvalidated write path.** Grepped every `wp_update_attachment_metadata()` call site
  in `src/` (24 of them): the rest are either `wp_generate_attachment_metadata()` fed a
  server-generated path (ordinary upload, XML-RPC `wp_newMediaObject`, Customizer background/header
  cropping, site-icon cropping) or the `edit_media_item()` server-side crop/rotate/flip route, whose
  output file is produced by `WP_Image_Editor::save()` internally — none of them take a client-named
  file string the way `finalize_item()` used to.

## 2. Sibling check: did the Gutenberg plugin get the same fix, or does it have a PowerShell-style backport gap?

Given what the PowerShell CAB-traversal thread in this engagement turned up (a real security fix
present on one release branch and silently absent from the very next one), this was the first
thing worth checking here rather than assuming a changelog line means the fix actually shipped
everywhere it needs to.

Checked properly, the same way: found the actual commit, not just an inferred diff.

- `f377cd0210` "Backport core fixes for finalize route (#81465)" in the `gutenberg` repo carries the
  identical `validate_sub_size_provenance()` / `META_KEY_SIDELOAD_FILE_NAME` /
  `get_sideloaded_file_names()` machinery — confirmed by grepping the tagged file content directly
  rather than trusting the diff.
- `git merge-base --is-ancestor f377cd0210 v23.8.0` → **is an ancestor.** The latest stable
  Gutenberg release genuinely ships the fix; this is not a repeat of the PowerShell pattern.

Conclusion: unlike the PowerShell CAB finding, there's no cross-branch gap to report here. Worth
recording as a clean result precisely because the check was made in earnest, not skipped.

## 3. The one real finding: the fix is a single choke point, not defense-in-depth

Neither of the two original sinks was actually hardened. Checked both directly against the 7.1.0
tag content, not the diff (a diff can look clean while the vulnerable line simply never appears in
it):

- `wp-admin/includes/media.php`, `get_media_item()` — the exact line from report #3931771 is
  **still there, character for character, unescaped**, in 7.1.0:
  ```php
  <p><a href='$attachment_url' target='_blank'><img class='thumbnail' src='$thumb_url' alt='' /></a></p>
  ```
  No `esc_url()`, no `esc_attr()`. Report #3931771's fix recommendation #1 (`esc_url()` on this
  line, and on the `edit_form_image_editor()` twins at :3179/:3229) was **not applied**. (Contrast:
  `wp_prepare_attachment_for_js()`, the modern grid's own JS-data path, *did* get a broad
  `esc_url_raw()` pass this same release — confirmed via `git diff 7.0.2..7.1.0 --
  src/wp-includes/media.php` — so the team clearly did output-harden the code path they were already
  touching for other reasons. They just didn't touch this one.)
- `wp-includes/post.php`, `wp_delete_attachment_files()` — the `$backup_sizes` branch still derives
  its confinement directory from `$meta['file']` instead of `get_attached_file()` the way every
  other branch in the same function does. Report #3931777's fix recommendation #2 was **not
  applied** either; `git log --oneline 7.0.2..7.1.0 -- src/wp-includes/post.php` shows real activity
  in this file this release (`c0155cd2be`, normalizing `sizes` typing) but nothing touching the
  `$backup_sizes`/confinement-directory logic itself.

Both sinks are exploitable today, exactly as originally reported, by the exact same PoC steps in
both HackerOne reports — the only thing standing between an Author and either bug is that
`finalize_item()` is now the sole gate on what can reach `_wp_attachment_metadata['file']` /
`['sizes'][*]['file']`. That gate is well-built (see §1) and I could not get past it. But it is one
function's discipline holding up two structurally-unrelated vulnerable sinks, not two sinks that
were themselves fixed. Any future code path that writes an unsanitized string into that metadata
shape — a plugin's `wp_generate_attachment_metadata` filter, a themes/import feature, a future REST
endpoint reusing the same metadata shape without reusing `validate_sub_size_provenance()` — reopens
both original bugs immediately, with zero additional changes needed on the sink side. This is the
same class of observation as the `DeserializationOptions.DeserializeScriptBlocks` dead-flag
landmine found earlier in the PowerShell audit: not a live bug today, but a single point of future
failure worth naming explicitly rather than leaving implicit.

## Honest limits / what wasn't chased further

- This is a source-level review only — no live install was stood up for this WordPress pass (unlike
  the two original HackerOne reports, which had full local-lab PoCs). Everything above is verified
  against the actual tagged source (`git show <tag>:<path>`, not diff inspection alone), the same
  discipline used for the PowerShell CAB finding, but it stops short of an executed HTTP PoC.
- Did not audit `mime_type`/`mime-type` metadata values for a separate, narrower XSS (they're
  schema-typed as plain strings with no enum restriction and are stored the same way `file` was) —
  flagged as worth a quick follow-up but not chased this round; unlike `file`, I did not find
  anywhere `sizes[*]['mime-type']` is echoed into HTML unescaped in a quick grep, but that grep was
  not exhaustive.
- Did not audit the Font Library REST controllers (`WP_REST_Font_Faces_Controller`) for an
  analogous unsanitized-filename pattern — same general shape of feature (client uploads a file,
  server records metadata about it) but gated by `edit_theme_options`, an admin-level capability
  rather than the Author-level `upload_files` that made the original two reports interesting, so
  lower priority and not started.
- Did not attempt to build/run either codebase; this was static/source-level analysis only, per the
  standing constraints of this engagement.
