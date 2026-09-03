# WordPress 7.1 core — low-privilege / pre-auth stored-XSS & RCE hunt (2026-09-03)

**Ask:** find a stored-XSS or RCE bug that does **not** require the attacker to hold
Editor or Administrator — Subscriber, Contributor, Author, or fully unauthenticated only.
**Target:** WordPress 7.1 core, live lab (localhost:8371, PHP 8.4.19), plus a second
lab (7.0.4, localhost:8372) used as a control where noted.
**Result: no new bug found this round.** Recorded in full because the negative
space is what stops the next pass re-covering it, and because one genuine (but
out-of-scope) bug turned up along the way.

This is a continuation of the same 7.1 audit as `interactivity-bind-xss-2026-09-02`
(HackerOne #3989843, closed duplicate), `comments-update-authz-2026-09-02`,
`fresh-audit-round2-2026-09-02`, `blocks-mxss-audit-2026-09-03`, and
`rce-surface-audit-2026-09-03` — all already delivered. This round specifically
re-checked the attacker-privilege ceiling (nothing above Author) and pushed into
surfaces those rounds didn't reach.

## Method

Two techniques, both empirical:

1. **Live fuzzing** against the running 7.1 install with real Contributor/Author
   sessions and a headless-Chromium execution oracle, same as prior rounds.
2. **Changelog diffing** — a full WordPress SVN→git mirror (`wpaudit/wpgit`) was
   used to read every trunk commit dated after 7.1's tag (2026-08-19) through the
   present. A fix that landed *after* the 7.1 tag describes a bug that is still
   live in the shipped release being tested — this is a much higher-signal way to
   find real, already-triaged-by-upstream issues than blind fuzzing. 95 commits in
   that window were read in full; anything security-adjacent is discussed below.
   (A fix whose `$wp_version` string still reads `7.1-betaN` landed *before* the
   stable tag and is therefore already present in the shipped 7.1 — three
   candidates were ruled out this way in minutes rather than by fuzzing.)

## Confirmed-live bug found, but out of scope

**`wp.getPost`/`wp.getPosts`/`wp.getUser`/`wp.getUsers`/`wp.getProfile`/
`wp.getTaxonomy`/`wp.getTaxonomies`/`wp.getPostType`/`wp.getPostTypes`/
`wp.getRevisions` (XML-RPC) fatal on a non-array `$fields` argument.**

Fixed upstream in `e068210` ("XML-RPC: Require the `$fields` argument to be an
array", trac #65983), landed 2026-08-28 — after the 7.1 tag, so it is still
present in the shipped release. Each of the ten methods passes the client's
optional 5th (or 4th) XML-RPC argument straight to `in_array( $field, $fields )`
in a `_prepare_*()` helper; a string there throws an uncaught `TypeError` on
PHP 8. **Not reported**, for two independent reasons: it requires a valid
XML-RPC login (these methods call `$this->login()` before reaching the
`$fields` check, so it needs real credentials, not pre-auth), and its only
effect is one request returning a 500 instead of a controlled error — no
injection, no code execution, no state change. The program's policy excludes
both "Application Errors on pages" and DoS explicitly, so it wasn't submitted.

## Fresh leads chased this round, all closed as negative

### `WP_HTML_Tag_Processor::set_modifiable_text()` — RCDATA escaping gap, not exploitable in a browser

Trunk commit `25b99e9a6` ("HTML API: Escape syntax characters in RCDATA",
2026-09-01, after the 7.1 tag) tightens `set_modifiable_text()` for `TITLE`/
`TEXTAREA` elements: the shipped 7.1 code only escapes the literal `</tag`
closing sequence, not `<`/`>`/`&` generally. Confirmed the pre-fix code is what
ships in 7.1 (`class-wp-html-tag-processor.php:4161-4169`). This looked
promising — but per the commit's own rationale it exists for *non-browser*
downstream parsers (PHP's `DOMDocument`, named explicitly), not for real
browsers: RCDATA tokenization in an actual browser only watches for the
closing-tag sequence, which the shipped code already escapes, so `<script>`
text sitting inside a properly-terminated `<textarea>`/`<title>` is inert
regardless. No core code path was found calling `set_modifiable_text()` on a
`TITLE`/`TEXTAREA` element with request-influenced content in the first place
(the only current callers target `STYLE`/`SCRIPT`), and no core use of
`DOMDocument` re-parses WordPress's own generated block/post HTML (the four
core `DOMDocument` call sites are oEmbed XML parsing, SimplePie, the Text
widget, and XMP/`.htaccess`-adjacent admin utilities — none re-parse this
output). Concluded not exploitable; not reported.

### `escape_javascript_script_contents()` — the `<script>` breakout guard, fuzzed and held

The function backing `wp_get_inline_script_tag()`/`wp_print_inline_script_tag()`
(used everywhere `wp_add_inline_script()`/localized data reaches the page) was
fuzzed directly with 17 payloads: case variations of `</script`/`<script`,
every HTML5-recognized end-tag delimiter (space/tab/FF/CR/`/`/`>`), a
no-trailing-content edge case, a NUL-byte split, a fullwidth-Unicode
lookalike `s`, and a JSON-embedded closer. Every genuine closing sequence was
correctly neutralized via the `s`-style rewrite; every non-match (`</scriptx>`,
the NUL-split, the Unicode lookalike) is also correctly *not* a real closing
tag to an HTML5 tokenizer, so leaving it alone is correct. `poc/t_script_escape.php`
is the harness and its recorded output. No bypass.

### oEmbed sandboxed-iframe + `wp-embed.js` postMessage handshake

Re-derived from scratch (not assumed from the prior RCE-surface round, which
only checked the oEmbed *fetch* path for `unserialize`, not this rendering
path): a Contributor-authored auto-embed URL that fails discovery-provider
matching gets its returned HTML run through `wp_kses()` with an allowlist of
only `a[href]`, `blockquote`, and `iframe[src,width,height,frameborder,
marginwidth,marginheight,scrolling,title]`, then forced into a
`sandbox="allow-scripts"` (no `allow-same-origin`) iframe. Checked whether the
"trusted provider — skip sanitization" branch in `wp_filter_oembed_result()`
can be made to disagree with which URL was actually *fetched* (it can't: both
checks run the same regex table against the same URL, so a match always means
both branches agree). Checked `wp-embed.js`'s `receiveEmbedMessage`: it binds
strictly on `e.source === iframe.contentWindow` (unspoofable), clamps `height`
numerically, and for `'link'` messages requires `http/https` scheme **and**
`targetURL.host === sourceURL.host` — since the attacker's own iframe content
is already on their own host, this only ever lets them navigate the victim's
top window to a URL on their *own* domain, which they didn't need this
mechanism to achieve. No bypass.

### Comment author URL (`comment_author_url`)

`esc_url( $url, ['http','https'] )` is applied at `get_comment_author_url()`
before the value is `sprintf`'d raw into `href="%1$s"` in
`get_comment_author_link()` — no intervening `esc_attr`. Looked exactly like
the classic attribute-breakout shape. Not exploitable: `esc_url()`'s character
allowlist (`preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\x80-\xff]|i', ...)`)
strips `"`, `<`, and `>` outright, and further HTML-encodes `&` and `'` for
display context. No payload can survive to break the attribute.

### Attachment `alt_text` — storage-sanitization inconsistency, but every render path re-escapes

Traced every place `_wp_attachment_image_alt` is written. The REST API path
(`WP_REST_Attachments_Controller::update_item()`, `class-wp-rest-attachments-
controller.php:990-991`) stores `$request['alt_text']` with **no explicit**
`sanitize_text_field()` call — unlike three sibling call sites in the same
file/related admin code that do call it. Verified live as an **Author**
(reachable without Editor/Admin): `PUT /wp/v2/media/{id}` with
`alt_text` containing `<script>alert(1)</script>" onmouseover=alert(2) x="`
strips the `<script>` tag (via the REST *schema's own*
`arg_options.sanitize_callback => sanitize_text_field`, which runs before the
controller method executes — the missing explicit call is redundant, not a
gap) but the **literal double-quote survives untouched into the database**,
because `sanitize_text_field()` strips tags, not quotes.

Traced every consumer of that meta key across core (`wp_get_attachment_image()`,
`wp_prepare_attachment_for_js()`, `cover.php`, `media-text.php`, the classic
attachment-details admin screen, the XML-RPC media response, custom-header/
custom-logo/site-icon alt): **every single one** independently escapes at
output — `array_map('esc_attr', $attr)` in `wp_get_attachment_image()`,
`WP_HTML_Tag_Processor::set_attribute()`'s built-in encoding in the block
render callbacks, `esc_attr()` in the classic admin textarea, and
underscore.js's own `_.escape()` (confirmed its `escapeMap` includes `"` →
`&quot;`) behind the `{{ }}` — not `{{{ }}}` — delimiter WordPress's
`wp.template()` is configured to use in every Backbone/media-modal template
that interpolates `attachment.alt`. Live-verified end to end
(`poc/t_alt_text_authz.py`): the stored quote comes back as `alt="&quot; onmouseover=alert(2) x=&quot;"` — inert. Worth
noting as a code-quality gap (defense-in-depth: sanitize on save *and* escape
on output, not just one), not as a vulnerability.

### `wp_block` (reusable block) creation — Author reaches it, kses holds

Confirmed live: a **Contributor** cannot create a `wp_block` post via REST
(403 `rest_cannot_create`), but an **Author** can. Content containing
`<img src=x onerror=alert(1)>` had `onerror` stripped on save exactly as for
ordinary post content — same `content_save_pre` kses pipeline, no separate or
weaker path for the reusable-block post type.

### `wp_restore_post_revision()` — restoring an Editor's revision doesn't smuggle unfiltered HTML

Hypothesis: if an Editor (who has `unfiltered_html`) touches a Contributor's
pending post, creating a revision with raw HTML, could the original
Contributor then use "restore this revision" to reintroduce content they could
never have saved themselves? No — `wp_restore_post_revision()` calls
`wp_update_post()`, which runs `content_save_pre` under the *restoring* user's
own capabilities. A Contributor's own kses restrictions apply regardless of
which revision's content is being restored. Also moot in practice: the REST
revisions controller only exposes GET/DELETE (gated on `edit_post`/
`delete_post` on the specific post), no restore route at all.

### `wp_get_layout_style()` (Group/Columns block layout support) — CSS injection attempt, blocked

Trunk commit `62006de35` ("Block Supports: guard against non-string attribute
values to avoid fatal errors", after the 7.1 tag) adds `is_string`/`is_numeric`
type guards around `layout` attribute values (`contentSize`, `wideSize`,
`minimumColumnWidth`, `columnCount`, etc.) before they're concatenated into CSS
declaration strings — its own rationale is "prevents fatals from hand-edited,
imported, or AI-generated" content, not the visual editor. Worth checking
independently: are those *string* values (which a Contributor can set on a
Group/Columns block through ordinary block markup — no HTML tags in a JSON
attribute value, so `filter_block_kses`'s `wp_kses` pass doesn't touch it, per
the methodology fact from `blocks-mxss-audit-2026-09-03`) validated for
CSS-injection safety before landing in the page's `<style>`? Traced the sink:
`wp_get_layout_style()` → `wp_style_engine_get_stylesheet_from_css_rules()` →
`WP_Style_Engine_CSS_Declarations::add_declaration()` (only guards the
*property* name via `sanitize_key()`, and now also guards the value's *type*
— confirmed no content validation at this layer) → but
`get_declarations_string()`'s `filter_declaration()` runs the **whole**
`"property:value"` string through `safecss_filter_attr()` before it is ever
emitted. Live-tested as a **Contributor**: a Group block with
`"contentSize":"10px} .injectedMARK{background:url(https://evil.example/x)}/*"`
saves untouched (no HTML tags, so kses doesn't strip it) but the marker is
**absent everywhere** on the real published page — `safecss_filter_attr()`'s
final gate (bans `} ( & = \` and `/*`, per `fresh-audit-round2-2026-09-02`)
drops the whole malformed declaration rather than emitting any of it. The
type-guard commit is orthogonal to this — CSS-injection safety here was
already fully owned by `safecss_filter_attr()` regardless of the fatal-error
bug.

### New 7.1 REST surfaces — checked for low-priv write access, all clean

* **Abilities API** (`wp-abilities/v1/abilities/*/run`) — permission is fully
  delegated per-ability to that ability's own `check_permissions()`. Core
  registers exactly three abilities, all read-only: `core/get-site-info`
  (`manage_options`), `core/get-user-info` (any logged-in user, but reads only
  `wp_get_current_user()` — no cross-user leak), `core/get-environment-info`.
  Nothing stores attacker data.
* **Icons / Icon Collections REST controllers** — both `GET`-only; icons are
  registered by PHP code (`wp_register_icon()`), not user-submitted. (A real
  icon-content-sanitization bug, `e75cda3`, was found in git history but its
  `$wp_version` marker shows it landed in `7.1-beta2`, i.e. already fixed
  before the stable 7.1 tag — verified the fix line is present in the shipped
  install.)
* **View Config REST controller** (`class-wp-rest-view-config-controller.php`,
  new, 846 lines) — `GET`-only, server-generated admin-screen configuration.
* **Connectors API** (`wp-includes/connectors.php`, since 7.0) — pure PHP-side
  registry (`wp_register_connector()`), no REST route registered anywhere in
  core; unreachable by any HTTP request regardless of privilege.
* **Client-side media processing / `/sideload` + `/finalize`** (new in 7.1,
  gated on `upload_files` — Author reaches it, Contributor doesn't) — this is
  the exact surface behind two already-fixed, already-reported bugs
  (HackerOne #3931777 / #3931771, referenced directly in the shipped code's
  own doc comments). Re-ran the prior negative-result bypass suite
  (`t_finalize.py`, live as Author) — the provenance allowlist
  (`validate_sub_size_provenance()`) still rejects every traversal/absolute-
  path/case/whitespace/array-type variant. Went further this round on angles
  the prior pass didn't try: the `width`/`height` sub-size fields are
  `type: integer, minimum: 1` in the REST schema (rejected pre-controller, no
  type-confusion route to an unescaped CSS/`sizes=""` attribute); the
  `mime_type` field's schema pattern (`^image/.*`) is loose enough to accept
  arbitrary trailing bytes, but the only consumer of the stored `mime-type`
  sub-size value is a straight rename into a JSON response field, never HTML
  or a PHP mime-type-comparison sink; `sideload_item()`'s two upload paths
  (`$_FILES` and raw-body) both terminate in WordPress's own long-standing
  `wp_handle_upload()`/`wp_handle_sideload()`, i.e. `wp_check_filetype_and_ext()`
  magic-byte validation, unchanged by any of this — no SVG/type-spoofing gap
  introduced by the new client-side-processing code.

## Net

No new low-privilege or pre-auth stored-XSS/RCE this round. The alt_text
storage-sanitization inconsistency and the RCDATA escaping gap are worth a
maintainer's attention as defense-in-depth (belt-and-suspenders) issues, but
neither is independently exploitable — reporting either as-is would be a false
positive under this program's "validated in a real running instance" rule, so
neither was submitted.

## Files

| file | what it is |
|---|---|
| `poc/t_script_escape.php` | fuzzes `wp_get_inline_script_tag()` against 17 `</script`-breakout payloads — all neutralized |
| `poc/t_alt_text_authz.py` | live Author-role REST `alt_text` injection attempt through to `wp_get_attachment_image()` output — confirms the quote is escaped |

## Lab

Same as prior rounds: WordPress 7.1 (localhost:8371) and 7.0.4 control
(localhost:8372), PHP 8.4.19, MariaDB, stock Twenty Twenty-Five, users
`admin`/`editor`/`author`/`contributor`/`subscriber`. Additionally this round:
a full WordPress SVN→git mirror at `wpaudit/wpgit` (branches back to 1.5,
tags through 7.1) used for changelog diffing between the 7.1 release tag and
current trunk.
