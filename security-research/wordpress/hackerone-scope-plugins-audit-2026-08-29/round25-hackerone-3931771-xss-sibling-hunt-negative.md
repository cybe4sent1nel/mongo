# Round 25: sibling hunt off disclosed HackerOne #3931771 (stored XSS via unescaped
# sub-size filename breaking out of `src='...'` in `get_media_item()` /
# `edit_form_image_editor()`) — write-side fix confirmed complete; the escaping bug
# the discloser flagged as "pre-existing, should be fixed independently" is
# confirmed still present in the sink, but not independently reachable

Prompted by the second disclosed report in the same pair as #3931777 (Round 20): #3931771, Critical
9.0, stored XSS. Same root-cause write primitive (`finalize_item()` storing `sub_sizes[].file`
verbatim), a completely different sink (`<img src='...'>` in the legacy media popup and, per the
discloser's own addendum, the "Edit Media" screen too). The discloser explicitly asked that the two
reports be read together because "a single unsanitised metadata write reached two entirely different
sinks, needing two entirely different fixes" — which makes this exactly the right second half of the
sibling hunt started in Round 20: same write primitive, second sink, second fix to verify.

**Result up front: the write-side fix (`validate_sub_size_provenance()`, the same commit that closed
#3931777) also closes this chain — confirmed by direct code reading, not assumed. The output-escaping
bug the discloser flagged as independently pre-existing is confirmed still literally present and
unescaped in current trunk. It is not exploitable today because no reachable write path remains in
core or in any of the four in-scope plugins — checked directly, not inferred.**

## 1. Confirming the fix commit and that it covers this report too

The disclosure cites core changesets 62616 and 63200. Resolved both against this session's
freshly-pulled `WordPress/wordpress-develop` clone via their `git-svn-id` trailers:
r62616 is an unrelated HEIC/HEIF-upload feature commit (`80c5bd2f88`) with no security content —
included in the disclosure's citation list but not itself a fix. **r63200 is `3767a6c06a`, "REST
API: Bind finalize sub-size file names to their sideload"** — the exact commit Round 20 already
identified and traced as `validate_sub_size_provenance()`/`get_sideloaded_file_names()`, i.e. the
same fix that closed #3931777. Confirmed `3767a6c06a` is an ancestor of current trunk (`d30211ee31`),
and that its 7.1-branch cherry-pick (`1c3261dca3`, r63203) exists too — so this is not a
trunk-only, unreleased mitigation.

Confirmed directly in the current source that both `metadata['sizes'][...] = array(...)` write
sites inside `finalize_item()` (currently at `class-wp-rest-attachments-controller.php:3305` and
`:3389`) execute only after `validate_sub_size_provenance( $attachment_id, $sub_sizes )` has
already run and returned successfully — the same strict-allowlist gate documented in Round 20/21.
The exact PoC payload from this report
(`a.jpg' /><svg onload='document.title="XSS-EXECUTED-"+document.domain'></svg><b x='`) is not a
value any prior sideload for the attachment could have produced, is not the attachment's own
`_wp_attached_file`, and is not already present in its stored metadata — so
`get_sideloaded_file_names()`'s allowlist would not contain it, and `validate_sub_size_provenance()`
would reject the `finalize` request with `rest_invalid_sub_size_file` before this code is ever
reached. The write path this report depends on is closed.

## 2. The escaping bug itself: confirmed still present, exactly as the discloser said

Checked all three cited sinks directly against current trunk — they are **unchanged**, matching
the discloser's own framing that this is "a plain output-escaping bug ... that pre-dates the new
endpoint and should be fixed independently of it":

- `wp-admin/includes/media.php:1726` (was `:1716`/`:1717` at disclosure time; line numbers have
  since shifted from unrelated edits, content is identical):
  ```php
  <p><a href='$attachment_url' target='_blank'><img class='thumbnail' src='$thumb_url' alt='' /></a></p>
  ```
  No `esc_url()`, no `esc_attr()` — exactly as reported.
- `wp-admin/includes/media.php:3189` and `:3239` (the discloser's addendum sink,
  `edit_form_image_editor()`, reachable from the ordinary `post.php?post=<id>&action=edit` screen):
  ```php
  <img class="thumbnail" src="<?php echo set_url_scheme( $thumb_url[0] ); ?>" style="max-width:100%" alt="" />
  ```
  `set_url_scheme()` only normalizes the URL scheme — it performs no HTML escaping, exactly as the
  discloser noted ("it provides no escaping"). Both occurrences (image branch and non-image-branch
  twin) are still present.

Neither of the discloser's two recommended fixes for this specific defect
(`esc_url()` at these three lines; `wp_basename()` inside `image_get_intermediate_size()` as a
second layer) has been applied. WordPress fixed the *reachability* of this bug, not the bug itself
— the same "fix at the call site, not the invariant" pattern already flagged as a standing
observation in Round 20/21 for the sibling report's sink (`wp_delete_attachment_files()`). This is
now confirmed a second time, independently, in a completely different function.

## 3. Hunting for any other write path that would make the still-unescaped sink live again

Since the sink itself is confirmed unfixed, the only thing standing between here and a live,
reportable stored-XSS-in-wp-admin is whether *any* code path — in core or in the four in-scope
plugins — can still get an attacker-shaped string into `_wp_attachment_metadata['sizes'][*]['file']`
(or `['file']`, or `['original_image']`) other than through the now-gated `finalize_item()`. This
reuses and extends Round 20's full write-site inventory of the two attachment-metadata keys:

- Every other core write site (`class-wp-xmlrpc-server.php`, `class-wp-customize-manager.php`,
  `class-custom-background.php`, `class-custom-image-header.php`, the regular upload path,
  `image-edit.php`'s `wp_save_image()`) calls `wp_generate_attachment_metadata()` or otherwise
  derives its filenames from `wp_unique_filename()`, which runs every candidate name through
  `sanitize_file_name()` — confirmed directly against `wp-includes/formatting.php:2035` that its
  `$special_chars` strip list includes `'`, `"`, `<`, `>` explicitly, so none of these paths can
  ever produce a filename capable of breaking out of a quoted HTML attribute in the first place.
  This is the original, decades-old mitigation the discloser's own prior-art section refers to
  (HackerOne #139245) — still intact and still the reason no *other* upload-shaped vector reopens
  this.
- Re-checked all four in-scope plugins for any direct `wp_update_attachment_metadata(`,
  `_wp_attachment_metadata`, or `wp_generate_attachment_metadata(` reference: Classic Editor,
  Create Block Theme, and SQLite Database Integration have none at all. Secure Custom Fields has
  exactly one call site (`includes/api/api-helpers.php:2537`), and it regenerates metadata via
  `wp_generate_attachment_metadata( $id, $file )` from a real server-side file path — the same safe,
  sanitized pattern as core's own regeneration calls, not a raw client string.
- Checked for a chunked/resumable-upload feature (a plausible place for a *second* "new feature,
  same oversight" instance, matching the shape of the original bug) — none exists in
  `wp-admin/includes/ajax-actions.php`, the REST attachments controller, or `wp-includes/media.php`.

## Conclusion

This closes out the pair the discloser asked to have read together. The write-side fix for
#3931777 independently and completely closes #3931771's chain too, confirmed by reading the actual
gate rather than assuming it from the sibling report. The specific defect the discloser flagged as
separately worth fixing — the unescaped `src='...'`/`src="..."` output in
`wp-admin/includes/media.php` — is confirmed still present verbatim in current trunk and is a real,
legitimate hardening gap, but it is not a live, reportable vulnerability today because no reachable
write path into the value it renders currently exists, in core or in any of the four in-scope
plugins. Not fabricating a live finding out of a real but currently-inert defect; if a future
WordPress feature or a future plugin update ever reopens a raw write to these metadata fields, this
sink reopens immediately with it — worth remembering as the first place to check if that ever
happens, but not something to report as a vulnerability on its own today.
