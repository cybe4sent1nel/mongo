# Round 8: Classic Editor / Create Block Theme / Secure Custom Fields re-audit

Re-swept the three plugins by name, focused on areas the earlier rounds hadn't reached yet
rather than re-reading what was already closed. One genuinely new area (SCF Options Pages) got
real depth because it looked, at first read, like it could be the same "changelog-documented
fix that's narrower than it reads" shape as the confirmed bidirectional bug (round 6) — it turned
out not to be. Also closed out Create Block Theme's one remaining plausible lead (font-download
SSRF) and did a fresh line-by-line re-check of Classic Editor's request-handling code.

## Secure Custom Fields — Options Pages: a real fix, checked for the same shape of gap as round 6, found complete

This is the area the README's "not exhaustively covered" note flagged (`pro/` — Options Pages)
and it turned out to be worth the depth: `pro/options-page.php` and
`pro/admin/admin-options-page.php` are two-line shims (`acf_include(...)`) that load the real
implementation from `includes/class-acf-options-page.php` and
`includes/admin/class-acf-admin-options-page.php` — i.e. Options Pages are core SCF
functionality, not a stubbed/license-gated pro feature, and hadn't been read yet.

**The mechanism**: `acf_options_page` lets a developer register one or more admin-menu "Options
Pages" (`acf_add_options_page()`), each with its own `capability` requirement (default
`edit_posts`) and its own `post_id` (**default `'options'` for every page that doesn't
explicitly set one** — this is the detail that makes the next part matter: multiple options
pages, unless a developer deliberately gives each a distinct `post_id`, all read/write field
values against the *same* underlying storage location).

**The fix this round went looking behind**: `acf_admin_options_page::admin_load()`
(`includes/admin/class-acf-admin-options-page.php:83`) — the handler for the classic options-page
form POST — now calls `filter_options_page_field_values()` before the save, which restricts the
submitted `$_POST['acf']` array to only the field keys belonging to field groups actually assigned
(via the "Options Page" location rule) to *this* page's `menu_slug`
(`get_options_page_allowed_field_keys()` / `get_options_page_field_groups()`, both marked
`@since SCF 6.9.3`). Before this existed, any options page's save form would have accepted **any**
submitted `acf[field_key] = value` pair and written it straight into the shared `post_id='options'`
storage via `acf_save_post()` — meaning a user with access to a low-capability options page (e.g.
`capability => 'edit_posts'`) could, by hand-crafting extra form fields into their POST body,
write values into fields that are logically owned by a *different*, higher-privilege options page
(e.g. `capability => 'manage_options'`) that happens to share the same default `post_id`. That's
the same shape of bug as the confirmed round-6 finding — a legitimate write on an object you own
reaching into data you shouldn't be able to touch — so this got the same treatment: check whether
the fix is actually complete, or only covers one path of several.

**Checked for the round-6 shape (a fix applied to one entrypoint, not the shared primitive)**:

- **Is there a second write path to options-page field data that bypasses
  `filter_options_page_field_values()`?** Checked SCF's REST API (`includes/rest-api/`) for any
  options-page-specific route — there isn't one; SCF's `acf` REST field attaches only to WP core's
  own post-type/taxonomy/user/comment REST endpoints, never to the arbitrary `options` pseudo-post.
  Checked the AI Abilities layer (`src/AI/Abilities/`) for a field-*value* write ability alongside
  the field-*group*-schema ones already reviewed in round 4 — there is none (`PostType.php`,
  `Taxonomy.php`, `FieldGroup.php` only touch schema, never field data). Checked whether Gutenberg's
  `meta-box-loader` save path (the mechanism the round-6 bug actually lives in) applies to options
  pages at all — it doesn't: options pages are rendered on a plugin-owned `admin.php?page=slug`
  screen, not `post.php?post=X&action=edit`, so the block-editor meta-box save mechanism never
  engages here. `admin_load()` really is the only reachable save entrypoint for options-page data.
- **Is the page-level capability gate itself sound?** `admin_menu()`
  (`class-acf-admin-options-page.php:47`) registers each page via WP core's own
  `add_menu_page()`/`add_submenu_page()`, passing `$page['capability']` as the menu's required
  capability — WP core enforces this at the HTTP page-load level (before any plugin code, including
  `admin_load()`, ever runs) for every page independently. So a user without a given page's
  capability can't reach that page's `admin_load()` hook at all, regardless of what URL/slug they
  target directly — this isn't a "fix a gap and hope no one hits the other entrypoint" situation,
  it's a single unified gate in front of the one save path that exists.
- **Does the "Options Page == All" location-rule wildcard reintroduce the gap?** A field group can
  be scoped to "Options Page: All" (`ACF_Location::compare_to_rule()` treats rule value `'all'` as
  matching every options page). Confirmed this is evaluated per-page correctly — such a field group
  is legitimately included in `get_options_page_allowed_field_groups()` for *every* page's
  allow-list, which is the intended semantic (a shared field group really is meant to be
  writable from any page assigned to it), not a bypass of the per-page restriction.
- **Is `post_id` itself attacker-influenceable?** `admin_load()` calls
  `acf_get_valid_post_id( $this->page['post_id'] )` — `$this->page['post_id']` here is the value
  from the options page's own static registration array (developer-set at `acf_add_options_page()`
  call time), never read from `$_GET`/`$_POST`. No request-controlled override of which storage
  location a save targets.

**Conclusion: the 6.9.3 fix is complete for the only save path that exists.** This is the second
negative result this audit has found by deliberately checking a changelog-documented fix for the
"only patched at one specific entrypoint" pattern that the round-6 bug actually was (the first
being the 6.9.3 read-permission check, round 6's addendum) — worth the depth given the pattern's
now shown up as a real bug once already in this same plugin family, but this one holds.

## Create Block Theme — font-download SSRF lead, closed (relies on WP core's own protection, correctly)

`CBT_Theme_Fonts::is_allowed_font_url()` (`includes/create-theme/theme-fonts.php:125`) is a pure
file-*extension* allowlist/denylist (rejects dangerous multi-extension polyglots like
`evil.php.woff2`, requires the final extension to be a real font type) — it does **not** validate
the URL's host or IP at all, which on first read looks like a missing SSRF control: nothing here
stops a `src` pointing at `http://169.254.169.254/...` or an internal `10.x`/`192.168.x` address
from reaching `download_url( $font_src )` (`copy_font_assets_to_theme()`, line 311).

Traced where the actual network fetch happens: `download_url()` is a WordPress **core** function
(`wp-admin/includes/file.php`), and it calls `wp_safe_remote_get()` — not `wp_remote_get()` — for
the fetch. `wp_safe_remote_get()` is core's own SSRF-hardened variant: it sets
`reject_unsafe_urls => true`, which routes the request through `wp_http_validate_url()` and the
`http_request_host_is_external` filter chain, rejecting private/reserved/loopback IP ranges by
default before the request is ever sent. CBT's URL validation only needed to handle the
file-type/extension concern (which it does, and does carefully, per round 3's prior review of the
matching magic-byte check) because the network-safety concern is already handled one layer down,
by core, using the API specifically designed for "fetch a URL a lower-privileged actor supplied."
This is the correct division of responsibility, not a gap — closing this lead.

(Not re-litigating: any residual DNS-rebinding TOCTOU window in `wp_http_validate_url()` — resolve
at validation time, connect to a possibly-different IP a moment later — is a known, long-standing
characteristic of that WP core mechanism generally, not something specific to or introduced by
this plugin, and isn't a fresh, plugin-specific finding.)

Also confirmed (grep, not just this one call site): Create Block Theme has no zip-*extraction*
code path anywhere in the plugin (`cbt-zip-archive.php` and `theme-zip.php` only ever *write*
entries into a `ZipArchive` for the `/export` route; there is no `ZipArchive::extractTo()` or
equivalent import/unzip feature at all). Zip-slip via a theme-import feature isn't a reachable bug
class here because the feature it would require doesn't exist.

## Classic Editor — fresh line-by-line re-check, still clean; one nonce detail worth recording as a non-issue

Re-read `classic-editor.php` in full again with fresh eyes (per this round's request naming it
explicitly), specifically re-tracing every `$_POST`/`$_GET`/`$_REQUEST` read against its
surrounding capability/nonce check rather than trusting the round-1 "entirely settings glue, no
sinks" conclusion. One detail worth recording rather than silently passing over:
`save_user_settings( $user_id )` (line 390) verifies a nonce whose action string is the static
`'allow-user-settings'` — **not** scoped to the specific `$user_id` being edited (unlike, say,
`'allow-user-settings-' . $user_id`), so the same nonce value would technically pass
`wp_verify_nonce()` regardless of which user's profile page it was issued on. On its own that
would be a real gap (nonce reuse across profile-edit contexts). It isn't one here, because the very
next check is a real authorization check, not just a second nonce check:

```php
if ( $user_id !== get_current_user_id() && ! current_user_can( 'edit_user', $user_id ) ) {
    return;
}
```

— this independently re-verifies, against the *target* `$user_id`, that the acting user is either
editing their own profile or holds `edit_user` on that specific target, regardless of what the
nonce did or didn't encode. The nonce here is doing CSRF-protection duty only; the actual
authorization decision is made correctly and separately. No privilege escalation. The
`manage_network_options`-gated network-settings save path (line 533) was re-checked the same way
and is straightforwardly correct (capability check present, admin-only, no target-user ambiguity
since it's a site-wide network setting).

## Round summary

No new bug in any of the three plugins this round. Two genuine "check the fix, not just the
feature" investigations (SCF Options Pages' 6.9.3 field-scoping fix; the Classic Editor nonce
action naming) both resolved as sound. Create Block Theme's font-download path relies correctly on
WP core's own SSRF hardening rather than reinventing it. The confirmed finding for this audit
remains round 6's SCF bidirectional-field broken access control.
