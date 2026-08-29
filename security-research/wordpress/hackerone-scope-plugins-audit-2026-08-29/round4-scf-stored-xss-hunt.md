# Round 4: focused stored-XSS hunt in Secure Custom Fields

Direct response to "go look for stored XSS there in Secure Custom Fields." Picked the
most XSS-shaped surfaces in the plugin — the ones where a lower-privileged user's input
becomes HTML rendered to someone else later — and traced each one to its actual sink.
Five candidates, five defended. Documenting the trace for each rather than just the
negative result, since the *reason* each is closed is different and worth having on
record before the next pass.

## Candidate 1: oEmbed field, discovery-mode HTML echoed unescaped

`acf_field_oembed::render_field()` (admin preview) and `format_value()` (front-end
`the_field()`/`get_field()` output) both call the plugin's own `wp_oembed_get()` wrapper
around WP core's `wp_oembed_get()`, and both echo the result with **no HTML escaping** —
the field type declares `'escaping_html' => true`, meaning ACF trusts whatever comes back
as already-safe markup. A Contributor (has `edit_posts`, not `unfiltered_html`) can set an
oEmbed field's value to a URL they control, implementing a fake oEmbed provider that
returns `{"type":"rich","html":"<script>...</script>"}`. When that URL isn't on WP's
hardcoded sanctioned-provider list, `wp_oembed_get()` runs in **discovery mode** — fetches
the page, follows the discovered oEmbed endpoint, and would embed the returned HTML
verbatim into the response. Two separate SCF code paths reach this with no permission
gate: `render_field()` server-renders it the instant a *higher-privileged* user simply
*opens* the post-edit screen (no click needed), and `format_value()` puts it on the public
front end for any visitor. Looked like a strong, privilege-crossing candidate.

**Traced to ground and closed**: WP core defends this exact case by design. `data2html()`
in `class-wp-oembed.php` returns provider HTML raw for `rich`/`video` types, but that
result passes through the `oembed_dataparse` filter, where `wp_filter_oembed_result()` is
registered **unconditionally** in `default-filters.php` (confirmed:
`add_filter('oembed_dataparse', 'wp_filter_oembed_result', 10, 3)`). For any URL not on
the sanctioned-provider list — exactly the discovery case above — that function runs the
HTML through `wp_kses()` with a hard allowlist (`a[href]`, `blockquote`, and `iframe` with
only `src/width/height/frameborder/...`), keeps only a `<blockquote>`+`<iframe>` pair, and
forces `sandbox="allow-scripts" security="restricted"` onto the iframe regardless of what
the attacker's provider sent. A sandboxed iframe without `allow-same-origin` executes in an
opaque origin — no access to the parent document, no cookies, no DOM. `<script>` tags,
event-handler attributes, anything outside that allowlist: stripped before SCF's code ever
sees the string. This is a WP-core hardening from 4.4 specifically built for this scenario,
not something SCF opted into or could disable by accident. Closed — SCF's missing
escaping here doesn't matter because core never lets unsafe HTML reach it.

## Candidate 2: icon_picker field, URL/data-URI tab

Field description literally invites `"The URL to the icon you'd like to use, or svg as
Data URI"` — `format_value()` for `return_format=string` returns `$value['value']`
verbatim, no validation on scheme or content, saved by anyone who can edit the field
(Contributor+).

**Closed on inspection**: `icon_picker` does not declare `'escaping_html' => true` (only
`url` and `oembed` do, confirmed by grep across every field-type file). That means ACF's
own `get_field($escape_html=true)`/`the_field()` path — which is what themes calling
`the_field()` actually hit — runs the returned string through `acf_esc_html()` before
output. A raw `javascript:` URI or inline SVG markup gets HTML-entity-escaped as plain
text, not executed. A theme that instead calls `get_field($escape_html=false)` explicitly,
or drops the raw string straight into an unescaped `href`/`src` itself, would still be
exposed — but that's a theme-integration choice ACF's own API surface warns against
(`_doing_it_wrong()` fires if you ask for escaped HTML without formatting), not a defect in
SCF's default behavior.

## Candidate 3: comment-form ACF fields (`includes/forms/form-comment.php`)

This is the one that looked most promising going in: it's a genuinely **public,
unauthenticated** input surface — SCF can attach field groups to the `comment` location
rule, rendering extra fields inside `wp_comment_form()` for anonymous commenters, saved on
the `comment_post` hook with `save_comment()`.

**Traced and closed**: `save_comment()` runs `$_POST['acf'] = wp_kses_post_deep($_POST['acf'])`
*unconditionally*, before `acf_validate_save_post()`/`acf_save_post()` ever run — for every
submitter regardless of role, including a fully anonymous commenter. This is actually
*more* conservative than the standard post-save path (which only forces `wp_kses_post_deep`
for users lacking `unfiltered_html`); here it applies even to a logged-in admin's own
comment submission. `wp_kses_post_deep` is `map_deep($data, 'wp_kses_post')`, which
correctly recurses into repeater/flexible-content nested arrays, not just top-level scalars
— checked this specifically since a shallow sanitizer here would've been the finding.
No bypass found.

## Candidate 4: Gallery field — attachment title/caption/alt/description round-trip

`ajax_get_attachment` (the sidebar shown when clicking an image in the gallery UI) is
registered on both `wp_ajax_*` and `wp_ajax_nopriv_*` — worth double-checking it isn't a
pre-auth info/render oracle. It isn't: the handler re-checks `is_post_publicly_viewable()`
/`current_user_can('read_post', ...)` on the actual attachment (and its parent, for
inherited attachments) before rendering anything, so the nopriv registration is just
plumbing for "read" access already used by public-facing frontend forms — not read access
that hasn't been checked. `render_attachment()`'s own output (the thing that ends up in
`.$side.html(html)` client-side, i.e. server-rendered admin HTML from data another user
could have set) is consistently `esc_html()`/`esc_attr()`/`esc_url()`'d field by field;
title/caption/alt/description are passed as `value` into `acf_render_field_wrap()`'s
text/textarea renderers, which esc_attr/esc_textarea internally. `ajax_update_attachment()`
(saving edits) writes `post_title`/`post_excerpt`/`post_content` through `wp_update_post()`,
which is WP core's own `sanitize_post()` kses path, keyed off the *saving* user's
`unfiltered_html` capability — standard, correct behavior, not something SCF reimplements
(and reimplementing it would be the riskier move).

## Candidate 5: WYSIWYG / message fields (fields explicitly allowed to hold HTML)

Re-checked (this was covered at a high level in round 1, revisited here specifically for
the comment-form and REST paths, not just the normal post-save path already verified).
`acf_save_post()`'s unconditional `wp_kses_post_deep()` for non-`unfiltered_html` users
covers the normal post-edit-screen save. `class-acf-rest-api.php` and `form-front.php`
both reference `unfiltered_html`/`wp_kses_post` directly (grepped, not just inferred) —
consistent coverage across all three save entry points (admin post save, REST, front-end
form), not just the one path already audited in round 1.

## Conclusion

Five real candidates, chosen specifically because they're the shapes of bug that produce
stored XSS (lower-priv input, HTML-trusting field type, unauthenticated write surface,
client-side `.html()` sink, fields that intentionally hold markup) — and five different,
specific reasons each is closed: WP-core's own oEmbed sandboxing (not SCF's doing, but it
covers SCF's gap), ACF's default escaping wrapper, an unconditional (even
over-conservative) kses on the one public write path, consistently-escaped admin render
output, and triple-checked kses coverage on every save entry point for HTML-permitting
field types. No exploitable stored XSS found in SCF this round.

Checked two more before stopping this round:

- **Admin-column rendering** (`admin-internal-post-type-list.php`,
  `admin_table_columns_html()`/`render_admin_table_column()`): this is only wired up for
  SCF's own internal post-type list tables (field groups, post types, taxonomies —
  admin-authored content), and the base `render_admin_table_column()` is an empty stub.
  SCF's free/core-adopted tier doesn't have the "show a custom field's value as a post-list
  column" feature at all — nothing here for a lower-priv user's field *value* to reach.
- **Google Map field**: `render_field()`'s server-side output (lat/lng/zoom/address) is
  entirely `esc_attr()`'d, including into the hidden input via `acf_hidden_input()`. The
  only unescaped-looking path is the client-side map/info-window content, which is
  populated from either the geocoded/autocomplete result (Google's own formatted string,
  not attacker-authored) or Google's Geocoding API response for a freeform search string —
  a third-party-API integration point, not something SCF's own code fails to sanitize.
  Deprioritized rather than fully chased given the third-party dependency.

Still an honest "haven't found it yet," not "it doesn't exist" — the four in-scope
plugins are large, and CVE-2026-16623 (round 3/verification doc) proved this program does
have real, fresh bugs to find when the right lens is used.
