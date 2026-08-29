# Round 15: deep-dive on SCF's newest hardening commits (front-end form grants,
# gallery-attachment visibility) + Create Block Theme / Akismet re-checks — negative,
# but genuinely new ground covered

**Trigger for this round**: continued instruction to keep hunting for a fresh RCE/High/
Critical bug, "whatever method." This round tried a technique not yet used this audit:
since `secure-custom-fields` is checked out as a real git clone, read its own commit
history for the *most recent* security-titled commits — the newest, least-battle-tested
code — rather than continuing to grep broadly. Also closed out two smaller leads
(Create Block Theme's theme-creation file-write path, Akismet's AJAX handlers).

## Method: audit the freshest commits, not just grep the tree

`git log` on the SCF clone shows several explicitly security-titled recent commits:
`a1fedc8 Harden front-end form submissions (#532)`, `7b08cac Defensive hardening
improvements for 6.9.5 (#534)`, `b520d2c Defensive hardening improvements for 6.9.3
(#528)`, `2214ee6 Harden user-contributed choice saving and WooCommerce order saves
(#491)`. Round 8 already checked the 6.9.3 commit (options-page field scoping). This
round checked the two newest: `a1fedc8` and `7b08cac`.

## `a1fedc8` — front-end form submission authorization rewrite: genuinely solid

This is a 579-line rewrite of `includes/forms/form-front.php` (`acf_form()`'s save
path — the mechanism sites use for guest/logged-in front-end content submission), plus
2,090 lines of new dedicated authorization tests. Read the entire current file and
traced the full submission-authorization chain end to end, specifically hunting for the
round-6 bug shape (a fix that closes the path it was written for but misses a sibling).

The design: every `acf_form()` render emits a `_acf_form_meta[]` token — base64 JSON +
`hash_hmac('sha256', ..., wp_salt('nonce'))` — binding together the exact rendered form
value's SHA-256 (`form_anchor`), a per-request random `render_id` (`wp_generate_uuid4()`),
a target `post_id`, an issuance timestamp, and the **exact set of field keys that form
actually rendered** (`allowed_field_keys`). On submission, `verify_form_meta()`
independently HMAC-verifies every submitted token, requires one whose `form_anchor`
matches the SHA-256 of the actually-submitted `_acf_form` value, cross-checks the target
post ID three ways (`hash_equals` against the meta token, the resolved form config, and
the raw submitted `_acf_post_id`), and only then unions `allowed_field_keys` from that
primary token with any *sibling* tokens sharing the same destination
(`form_meta_destinations_match()`) before intersecting `$_POST['acf']` against that set
(`restrict_submitted_field_keys()`) — closing exactly the "submit an extra `acf[field_key]`
the rendered form never included" injection this whole mechanism exists to prevent.

Specifically checked, and found closed:
- **Cross-render mixing**: could an attacker combine one page's `_acf_form` value with a
  *different* page's `_acf_form_meta[]` token (e.g., to borrow a higher-privilege form's
  `allowed_field_keys`)? No — `render_id` is a fresh UUIDv4 per request and is checked
  with `hash_equals`, and `form_anchor` ties each meta token to the SHA-256 of one exact
  `_acf_form` byte string; mixing components from two different renders fails both checks.
- **Ad-hoc (non-registered) forms**: `_acf_form` here is `acf_encrypt(wp_json_encode($args))`
  — an attacker would need to forge ciphertext AND separately forge an HMAC-SHA256 (a
  *different* key, `wp_salt('nonce')`) binding to that exact ciphertext's hash. Two
  independent secrets stand between an attacker and a forged grant, not one.
- **The AJAX-only validation path** (`validate_save_post_authority()`, gating live-typing
  field-validation feedback) uses a deliberately looser check (`$verify_form_configuration
  = false`, skipping the `new_post` fingerprint check) — but traced this to have zero save
  side effects: `ajax_validate_save_post()` → `acf_validate_save_post()` only ever calls
  validators, never `acf_save_post()`/`wp_insert_post()`/`wp_update_post()`. The looser
  check only affects what error message an AJAX validation call gets back, not what can be
  persisted.

No gap found. This reads as a genuinely careful, complete redesign — worth the deep read
given it's exactly the same bug *shape* (broken access control on a save path) as the
audit's one confirmed finding, but it holds.

## `7b08cac` — the same commit that contains round 6's already-reported bidirectional fix

This commit's `includes/acf-bidirectional-functions.php`/`class-acf-rest-api.php`/
`Datastore/REST_Save.php` changes are the exact 6.9.5 "REST updates now reject
bidirectional field writes..." fix round 6 already found to be incomplete (REST-only,
not the default save path) — re-confirmed by reading the diff, not a new finding.

The same commit **also** hardens `includes/fields/class-acf-field-gallery.php`'s
`ajax_get_attachment()` — registered on both `wp_ajax_acf/fields/gallery/get_attachment`
**and `wp_ajax_nopriv_...`** (fully unauthenticated), this previously had **no visibility
check at all** before rendering full attachment metadata (title, caption, description,
alt text, full-size URL) for any attachment ID — an unauthenticated IDOR letting anyone
who obtains a valid `gallery`-scoped nonce (obtainable from any page where a gallery field
renders for guests, e.g. a front-end form) enumerate private/unattached media. The diff
adds a proper visibility gate: allow if the attachment (or, for `inherit`-status
attachments, its parent) `is_post_publicly_viewable()`, or the current user holds
`read_post` on the attachment directly, or holds `read_post` on the inherited parent.

Traced the boolean logic and the two sibling AJAX handlers registered alongside it for
the same "fixed one, missed a sibling" pattern:
- **`ajax_update_attachment()`** (also `nopriv`-registered, but performs a *write*):
  already has its own `current_user_can( 'edit_post', $id )` check per attachment
  *before* applying any change — this was never affected by the read-side gap, and
  remains correctly gated.
- **`ajax_get_sort_order()`** (also `nopriv`-registered): has no per-attachment
  capability check, but only ever returns a *reordering* of an ID list the caller
  already supplied (`get_posts( ['post__in' => $args['ids'], 'fields' => 'ids'] )`),
  not any attachment content — the caller learns only whether each ID they already
  guessed exists as an attachment (and its relative post_date/post_title ordering vs.
  the other guessed IDs), not the metadata `get_attachment` used to leak pre-fix. A real
  but minor existence-oracle characteristic, not a fresh disclosure bug and not the
  shape being hunted for this round (not RCE/XSS/privesc).

Re-verified the new `ajax_get_attachment()` gate's own boolean logic directly (not just
read it): DENY requires all three of *not publicly viewable* AND *not readable by the
attachment's own ID* AND *(same post as its own visibility target, or not readable via
the parent)* — equivalently, ALLOW on any of public / directly readable / readable via a
legitimately-inherited parent. This matches WP core's own standard attachment-visibility
pattern; no bypass found.

No new bug. Confirms round 6 remains the audit's only fresh finding, and separately
confirms the *other* fix bundled in the same commit (gallery AJAX IDOR) is complete.

## Create Block Theme — theme-creation file-write path, checked fresh

Traced `CBT_Theme_Create::create_child_theme()`/`create_blank_theme()`/
`clone_current_theme()` (`includes/create-theme/theme-create.php`), which all build a
new theme directory as `get_theme_root() . DIRECTORY_SEPARATOR . $theme['slug']` and
`file_put_contents()` several files under it (`readme.txt`, `style.css`, `theme.json`,
`screenshot.png`) — a plausible path-traversal-to-arbitrary-file-write candidate if
`$theme['slug']` were attacker-controlled and unsanitized. It isn't:
`CBT_Theme_REST_API::sanitize_theme_data()` derives it as
`sanitize_title( $theme['name'] )` — WP core's slug sanitizer, which strips `/`, `.`,
and every other traversal-relevant character. All three REST routes that reach these
methods are additionally gated behind `can_modify_theme()`
(`current_user_can( 'edit_themes' ) && wp_is_file_mod_allowed(...)`) — Administrator-only
on single-site, super-admin-only on multisite, and respects `DISALLOW_FILE_EDIT`/
`DISALLOW_FILE_MODS`. No path traversal, no privilege gap.

## Akismet — the three `wp_ajax_*` handlers, checked fresh (none `nopriv`)

`recheck_queue()`: nonce (`wp_verify_nonce(..., 'akismet_check_for_spam')`) **and**
`current_user_can( 'moderate_comments' )`, both required. `remove_comment_author_url()`/
`add_comment_author_url()`: `check_admin_referer()` **and**
`current_user_can( 'edit_comment', $comment_id )`, both required, plus `esc_url()` on the
stored value. All three correctly gated; no `wp_ajax_nopriv_*` variant registered for any
of them (unlike the SCF gallery handlers above, these were never reachable pre-auth).

## What this is not

Not RCE, not IDOR, not privilege escalation — a genuinely deep audit of the newest code
in the plugin most likely to have one (since it already had one, once), that came back
negative. The gallery-attachment IDOR this round found in the commit history was real
but is already fixed in the currently-installed version; recorded here as due-diligence
context (confirming the *current* state is sound) rather than as a live finding.

## Standing findings for this audit, unchanged by this round

- Round 6: **CONFIRMED** — SCF bidirectional-field broken access control (reported).
- Round 11: **CONFIRMED** — WP Core REST API unauthenticated argument-validation crash /
  DoS (CWE-248/CWE-20), Medium severity; round 13 confirmed no write-path impact.
- Rounds 12, 14, 15: negative — no fresh XSS/RCE/privesc/SSRF/object-injection/IDOR bug
  found via seven additional distinct hunting methods across rounds 12-15.
