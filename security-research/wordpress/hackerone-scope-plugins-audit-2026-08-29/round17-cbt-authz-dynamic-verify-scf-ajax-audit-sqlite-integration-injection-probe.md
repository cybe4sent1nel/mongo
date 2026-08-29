# Round 17: dynamic REST authz verification (CBT), full ACF_Ajax capability
# audit (SCF), and adversarial SQL-escaping probe of the SQLite Database
# Integration query translator — mostly negative, one low-severity IDOR-ish
# info leak found and confirmed

Per the standing correction from the previous round: **no DoS/crash findings are being pursued
here.** This round explicitly targets RCE, SQLi, XSS, auth bypass, privilege escalation, and
IDOR/broken access control only, using a mix of dynamic (real HTTP, real low-privilege sessions)
and static analysis — favoring dynamic verification wherever a prior round had only read code and
trusted it.

## Setup

Created two real, low-privilege WordPress accounts on the throwaway install (`sec_research_editor`,
role `editor`; `sec_research_subscriber`, role `subscriber`), logged each in via a real
`wp-login.php` POST (not Application Passwords — still HTTPS-gated on this plain-HTTP dev server),
and scraped each session's live REST nonce from `wp-admin/profile.php`'s `wp.apiFetch.nonceMiddleware`
inline script — the same cookie+nonce technique built in round 13, now extended to genuinely
low-privilege roles instead of just Author vs Admin.

## Part 1: Create Block Theme's REST routes — dynamic authz verification (negative)

All ten `create-block-theme/v1` routes gate on `CBT_Theme_API::can_modify_theme()` →
`current_user_can( 'edit_themes' ) && wp_is_file_mod_allowed(...)`. Round 15 verified this by
reading the source; this round verified it by actually calling every route as Editor and
Subscriber against an Administrator baseline:

```
POST /export             admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /update              admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /save                admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /theme-settings      admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /clone               admin 500*  editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /create-variation    admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /create-blank        admin 500*  editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /create-child        admin 500*  editor 403 rest_forbidden   subscriber 403 rest_forbidden
GET  /font-families       admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
POST /reset-theme         admin 200   editor 403 rest_forbidden   subscriber 403 rest_forbidden
```
(*500s for admin are `theme_already_exists` — expected, a theme by that slug already existed from
a prior test run; the permission gate itself passed for admin in all ten cases.)

Clean 403 for both lower-privilege roles on every route, every time. No privilege escalation here.

## Part 2: Create Block Theme's file-write/upload hardening — re-examined for gaps (negative)

Re-read `CBT_Theme_Media`/`CBT_Theme_Fonts`'s URL/extension allowlists and magic-byte verification,
and `CBT_Theme_Patterns::strip_php_tags()`'s PHP-tag stripping, specifically hunting for a bypass
the plugin's own extensive test suite (`test-theme-fonts.php`, `test-theme-media.php`,
`test-theme-patterns.php` — all of which contain deliberate `evil.php.txt`/`<?php ... ?>` payloads
verifying these exact defenses) doesn't already cover:

- **Extension allowlist**: denylist checks every dot-separated segment of the lowercased basename
  against a dangerous-extension list (`php`, `phtml`, `phar`, `html`, `cgi`, `js`, etc.) *before*
  checking the final extension against an allowlist — correctly closes the `evil.php.jpg` polyglot
  class. Tried to find a segment-based bypass (alternate dangerous extensions not on the list,
  e.g. `.pht`, `.shtml`, `.cer`, `.asa`) — the list is long enough that no realistic Apache-handler
  bypass extension was missing that would matter on a stock config.
- **Magic-byte verification**: keyed strictly off the *URL's* extension (not the final download
  target after any redirect) and checked against real format signatures — an attacker fully
  controls the URL from the start, so redirecting through a "safe" extension to disguise a
  dangerous one buys nothing they didn't already have by just requesting the dangerous extension
  directly (which the pre-download allowlist already blocks).
- **`strip_php_tags()`**: a blanket `preg_replace('/<\?/', '', $content)` before any trusted
  `<?php ... ?>` markers are injected — traced the call order in both `pattern_from_wp_block()` and
  `CBT_Theme_Templates::prepare_template_for_export()` and confirmed sanitize-then-inject ordering
  holds in both pipelines (this was exactly the ordering the class's own doc comment calls out as
  the thing that must never be reversed).
- **`escape_text_for_pattern()`'s `addslashes()`-based PHP-code generation**: traced the exact
  backslash-quote breakout payload the plugin's own test suite uses
  (`chr(92) . '\'); file_put_contents(...); //'`) character-by-character through PHP's single-quote
  string lexing rules — the leading backslash gets doubled by `addslashes()`, the following quote
  gets escaped, and because the rest of the payload contains no further unescaped quote, the whole
  thing stays trapped inside the string literal argument to `esc_attr_e()` rather than breaking out
  into live PHP. Confirms the negative the test itself asserts, by hand rather than by trusting the
  test result.

No gap found. This plugin's newest-hardened surface (file upload + PHP-tag injection) holds up
under adversarial reading a second time.

## Part 3: SCF's `ACF_Ajax` base class and every subclass — capability-check audit

`ACF_Ajax::verify_request()` (the base class every ACF ajax handler either uses as-is or overrides)
only checks nonce validity by default — **it does not check any capability**. That makes every
subclass's own `verify_request()`/`get_response()` override the single point of truth for whether
an ajax action needs more than "is logged in" (or, for `$public = true` actions, no login at all).
Read every subclass in `includes/ajax/`:

| Class | Action | Capability check |
|---|---|---|
| `ACF_Ajax_User_Setting` | `acf/ajax/user_setting` | `acf_current_user_can_admin()` in `get_response()` — correct |
| `ACF_Ajax_Local_JSON_Diff` | `acf/ajax/local_json_diff` | `acf_current_user_can_admin()` in `get_response()` — correct |
| `ACF_Ajax_Upgrade` | `acf/ajax/upgrade` | `current_user_can(acf_get_setting('capability'))` + `is_super_admin()` for cross-site upgrades — correct |
| `ACF_Ajax_Query_Users` | `acf/ajax/query_users` | field-key-bound nonce (ties the request to a specific field the requester must already have legitimate access to render) + `acf_current_user_can_admin()` when `conditional_logic` is set; search-column restriction for non-`edit_users` roles — correct |
| `ACF_Ajax_Check_Screen` | `acf/ajax/check_screen` | admin-context nonce only — informational (returns which fields/screen apply), no data mutation or disclosure beyond what the requester's own edit screen already shows them |
| `class-acf-field-gallery.php` → `ajax_get_attachment` | `acf/fields/gallery/get_attachment` | field-key-bound nonce + `current_user_can('read_post', ...)` on the attachment/its parent — correct (this is round 6/7b08cac's fix, reconfirmed) |
| `class-acf-field-gallery.php` → `ajax_update_attachment` | `acf/fields/gallery/update_attachment` | field-key-bound nonce + **per-attachment-ID** `current_user_can('edit_post', $id)` inside the loop — correct |
| `class-acf-field-gallery.php` → `ajax_get_sort_order` | `acf/fields/gallery/get_sort_order` | field-key-bound nonce only — **no per-ID capability check** (see below) |
| `admin-field-group.php` → `ajax_render_field_settings`/`ajax_render_location_rule`/`ajax_move_field` | field-group editor UI | `acf_current_user_can_admin()` (or `wp_verify_nonce($args['nonce'],'acf_nonce')` + the same admin check for `ajax_move_field`) — correct |

## Finding: `ACF_Field_Gallery::ajax_get_sort_order()` has no per-attachment access check (minor IDOR)

`includes/fields/class-acf-field-gallery.php`, `ajax_get_sort_order()`:

```php
if ( ! acf_verify_ajax( $args['nonce'], $args['field_key'], true, 'gallery' ) ) {
    wp_send_json_error();
}
...
$ids = get_posts( array(
    'post_type'   => 'attachment',
    'numberposts' => -1,
    'post_status' => 'any',        // <-- includes private/inherited-from-any-post attachments
    'post__in'    => $args['ids'], // <-- fully attacker-controlled, no ownership check
    'order'       => $order,
    'orderby'     => $args['sort'],
    'fields'      => 'ids',
) );
if ( ! empty( $ids ) ) {
    wp_send_json_success( $ids );
}
```

Unlike its two siblings in the same file (`ajax_get_attachment` checks `read_post` per attachment,
`ajax_update_attachment` checks `edit_post` per attachment ID before touching it), this one only
requires *a* valid field-key-bound nonce for *some* gallery field the requester has legitimate
access to (e.g. a gallery field on their own draft post) — it does not scope the query to
attachments belonging to that field's post, or check read access on the requested IDs at all.
`post_status => 'any'` means it will match attachments regardless of the visibility of whatever
post they're attached to.

**Update: reproduced over real HTTP later this same round — see
`round18-CONFIRMED-scf-gallery-sort-order-idor.md`.** Built the missing fixture (a real gallery
field via `acf_import_field_group()`, an Administrator-owned `private` post with a real attachment,
and a genuine Contributor session), and confirmed a Contributor's own, legitimately-obtained nonce
for their own gallery field is accepted to query sort-order/existence data for an attachment
belonging to the Administrator's `private` post — with a negative control showing the sibling
`ajax_get_attachment()` correctly denies the identical request/session. Confirmed as **Low severity**
(no content/PII disclosed — only attachment-ID existence and relative ordering) but genuinely
reproducible IDOR / missing authorization (CWE-639/CWE-862). Full detail, root cause, and PoC in
round 18.

## Part 4: SQLite Database Integration — adversarial probe of the MySQL→SQLite query translator

This plugin (WP_SQLite_Driver / `WP_MySQL_On_SQLite`) is architecturally the most interesting
in-scope surface: it re-implements a real MySQL grammar lexer/parser and translates every query
into SQLite syntax before execution. Shims like this have a well-known historical bug class: MySQL
string literals support backslash-escapes (`\'`, `\\`, `\0`, ...) by default; standard SQLite string
literals do not — only doubled quotes (`''`) escape a quote. A translator that re-serializes an
already-escaped MySQL string into SQLite text *without first fully decoding it to its semantic
value* can let a value that was safely escaped for MySQL break out of its SQLite string and inject
arbitrary SQL (or, worse, let a value wpdb considered already-safe become live SQL after
translation).

Wrote a standalone PHP harness (`tooling/sqlite_injection_probe.php`) instantiating
`WP_MySQL_On_SQLite` directly (it's a self-contained `PDO` subclass — no full WordPress bootstrap
needed) against a throwaway SQLite file, and round-tripped several adversarial payloads through
real `->query()` calls, inspecting both the returned rows and whether a canary `secret` column value
could be exfiltrated via an injected `UNION SELECT`:

```
'x\' OR '1'='1'                                  -> parse exception (rejected, not injected)
'nomatch\' UNION SELECT secret FROM probe -- '   -> 0 rows (treated as one inert string value,
                                                     canary secret NOT exfiltrated)
'a''b\'c'  (mixed '' and \' escaping)             -> parsed cleanly as one string, no error
id = 1; DROP TABLE probe                          -> "Multi-query is not supported." (rejected)
final state check                                 -> canary row/secret still intact, unmodified
```

Root cause read: `translate_string_literal()` (`class-wp-mysql-on-sqlite.php:4518`) takes the
lexer's already-fully-decoded token value (`$token->get_value()` — the lexer, not this function,
is what turns `\'`/`''`/`\\`/etc. into the literal characters they represent) and re-quotes that
*decoded* value for SQLite via `$this->connection->quote()`, which delegates to SQLite's own PDO
`quote()` (correct doubled-quote SQLite escaping). Because re-quoting happens on the
semantically-decoded value rather than on the original escaped text, the MySQL/SQLite
escaping-convention mismatch never gets a chance to matter — this is the architecturally correct
way to build this kind of shim, and the adversarial probe backs that up empirically rather than
just by reading the function once.

This is a genuinely large codebase (~53k lines across the parser/lexer/translator packages) with
its own dedicated parser test suites; this round's probe covered the single highest-value
hypothesis (the classic escaping-mismatch injection class) and came back negative. It was not an
exhaustive audit of the translator — identifier quoting (table/column names in DDL), the
`ESCAPE '\\'` LIKE-clause translation, and the native-extension code path (`mysql/native/*`, used
when a compiled lexer/parser extension is loaded) were not covered this round and remain open
territory for a future pass if this plugin stays a priority.

## Honest summary

No new in-scope, reportable finding this round. Two genuinely useful outputs:
1. A **dynamically re-verified negative** on Create Block Theme's REST authorization boundary and
   its file-upload/PHP-injection hardening (previously only static-read in round 15) — now backed
   by real low-privilege HTTP sessions and a hand-traced escaping proof, not just source reading.
2. One **real but low-severity IDOR-class gap** (`ajax_get_sort_order`'s missing per-attachment
   check) — documented plainly, including the honest caveat that HTTP-level reproduction is still
   pending a suitable test fixture, and that the actual information disclosed is narrow (existence +
   ordering only).

Also ran a targeted, dynamically-verified negative against SQLite Database Integration's query
translator for the single most historically-relevant SQLi bug class for this kind of shim
(MySQL/SQLite string-escaping mismatch) — came back clean, with the mechanism (decode-then-requote)
identified and confirmed by direct adversarial testing rather than by trusting a single code read.

Round 6 (SCF bidirectional-field broken access control) remains the audit's one confirmed,
in-scope, reportable finding after 17 rounds.
