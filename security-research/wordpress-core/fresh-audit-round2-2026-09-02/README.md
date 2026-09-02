# WordPress 7.1 — second fresh-bug audit round (post-duplicate)

Context: the Interactivity API `data-wp-bind--href` stored-XSS chain (report #3989843) was closed
as a **duplicate** — the URL-binding path is already under internal remediation. This round
looked for a *distinct* high/critical bug elsewhere in the new 7.1 surface. **None found this
round.** Everything examined is properly guarded. Recorded so the ground isn't re-covered.

## Checked and clean

* **`core/accordion`, `core/accordion-item` render callbacks** (new in 6.9/7.1). All attribute
  output is booleans (`autoclose`, `openByDefault`) or server-generated `wp_unique_id()` values,
  written via `WP_HTML_Tag_Processor::set_attribute()` (escaped). No unescaped sink.
* **`core/tabs`** — same shape, interactive wrapper only.
* **Block bindings** (`wp-includes/block-bindings/`, `WP_Block::process_block_bindings()` /
  `replace_html()`). The `core/post-meta` source enforces public-viewability, `read_post`,
  `is_protected_meta`, and `show_in_rest` before returning a value. The writer escapes: `html`/
  `rich-text` sources pass through `wp_kses_post()`, `attribute` sources through the URI-aware
  `set_attribute()`. No unescaped path, no protected-meta leak.
* **`WP_REST_Terms_Controller` create-vs-update** — unlike the comments controller, update uses
  `current_user_can( 'edit_term', $term->term_id )` (per-term), so the create/update asymmetry
  that broke comments is absent here.
* **`safecss_filter_attr()`** (materially expanded in 7.1: SVG `url()` for
  `clip-path`/`fill`/`marker*`/`mask`/`stroke`, a `preg_match_all` gradient stripper, a recursive
  transform/basic-shape function stripper). The final gate still bans `\ ( & = }` and `/*` after
  stripping. Even a hypothetical bypass yields only CSS injection (no script execution in modern
  browsers), so this is at most Medium and was not pursued to a working bypass.
* **`core/breadcrumbs` `separator` attribute** → `--separator` custom property
  (`breadcrumbs.php:188`). Contained: `addcslashes($sep, '\\"')` blocks CSS-string breakout, and
  `get_block_wrapper_attributes()` HTML-escapes the style value. `<`/`>`/`"` cannot break the
  attribute; the label path already splits `esc_html()` vs `wp_kses_post()` on `allow_html`.
* **All dynamic block render callbacks** swept for `echo`/interpolation of `$attributes[...]`
  without an escaping wrapper — every candidate uses `esc_*`, `set_attribute`,
  `get_block_wrapper_attributes`, `wp_kses_post`, `absint`, or a boolean cast.

## A false lead I caught in live verification (recorded so it isn't chased again)

**Hypothesis:** the server-side `data_wp_style_processor()`
(`class-wp-interactivity-api.php:1299-1327`) applies `data-wp-style--<prop>` via
`set_attribute('style', …)` with **no `safecss_filter_attr()`** anywhere in `interactivity-api/`
(confirmed: `grep safecss_filter_attr interactivity-api/` → nothing). Feeding a fragment straight
to `wp_interactivity_process_directives()` in wp-cli *did* apply `behavior:url(...)` and
`width:expression(...)` verbatim — values `safecss_filter_attr()` strips to empty — which looked
like a distinct server-side Contributor CSS-injection bypassing safecss.

**Why it is NOT a distinct bug (proven live):** on a real front-end page, server-side directive
processing only runs on the rendered output of the **root interactive block**
(`WP_Block::render()` gates on `supports['interactivity']`). A Contributor's `data-wp-interactive`
island inside post content is *not* under that block (e.g. `core/navigation`), so the server
never processes it. Live test (`poc/t_style_css.py`, Contributor→Editor-publish→anon): the
published element carries the raw `data-wp-style--*` attributes with **no `style=` applied
server-side**. The style is only ever applied **client-side**, by the same Interactivity runtime
that applies `data-wp-bind--*` — i.e. the exact client-runtime disagreement already reported and
duplicated. The wp-cli result was an artifact of calling the processor directly on a fragment.

Lesson kept: directive processing is root-interactive-block-scoped on the server but
whole-page on the client; a wp-cli `eval` of the processor over-reports server-side reach.

## Net

No new high/critical WordPress core bug this round. The new 7.1 block/binding/CSS surface is
consistently guarded, and the one promising server-side lead collapsed into the already-duplicated
client-runtime issue under live testing.

## Round-2 continued — user-controlled-data-to-frontend stored-XSS sweep (all live-tested, all clean)

The recurring stored-XSS class is "a field a low-priv user controls, rendered on the front end
without escaping." Every core sink of this shape was tested live (Contributor privilege, real
REST writes, stored value read from the DB via wp-cli):

* **Note-mention `<span class>`** (`_wp_kses_allow_note_mention_span` / `_wp_kses_sanitize_note_mention_classes`,
  new in 7.0/7.1). `pre_comment_content` runs `wp_filter_kses` (pri 10) then the class sanitizer
  (pri 11). Ran the *real* filter chain (`kses_remove_filters(); kses_init_filters()` as an
  anonymous, no-`unfiltered_html` user) over 18 payloads — event handlers, `style`, unquoted
  attrs, slash tricks, bogus-comment breakout, null bytes, attr-before-class, uppercase. kses
  strips every non-`class` attribute from `span`; the sanitizer then strips every non-mention
  class token. Nothing dangerous survived. **Methodology note:** a first run with
  `wp_set_current_user(0)` but *without* re-initialising the kses filters made everything look
  like it survived — the filters attach at `init` by capability and are not re-added by changing
  the current user mid-request. The clean result only appears once `kses_init_filters()` is
  called. A wp-cli `apply_filters('pre_comment_content', …)` without that step over-reports.
* **`post-author-biography`** (`post-author-biography.php:37`) concatenates
  `get_the_author_meta('description')` **raw** (no `esc_html`, no output kses). Safe only because
  the value is kses-filtered on *save*: 10 payloads through `POST /wp/v2/users/me` `description`
  — `<script>`, `<img onerror>`, `<svg onload>`, `javascript:` href, `ontoggle`, inline `<style>`
  — all stripped to inert text in storage (`<style>*{expression()}</style>` survives only as the
  plain text `*{…}`, not a style element).
* **`post-author-name`** (`post-author-name.php`) outputs `get_the_author_meta('display_name')`
  **raw** (`%2$s`/`%3$s`). Safe because `display_name` is triple-sanitised on save:
  `sanitize_text_field` on the REST `name` field, then `pre_user_display_name` =
  `sanitize_text_field` + `wp_filter_kses` + `_wp_specialchars` at priority 30 (HTML-encodes
  `<>&"'`). Stored value is already encoded.

## Next.js 16.3.4 — same session, additional live negatives

* **Metadata reflection XSS.** A dynamic page reflecting `searchParams` into `title`,
  `description`, `openGraph`, `alternates.canonical` and `other`. Injected
  `</title><script>` and `"><script>`: every reflection is HTML-escaped in `<head>`
  (`&lt;/title&gt;…`) and written as `<` in the inline `__next_f.push` flight payload, so
  neither the `<title>`/attribute context nor the inline `<script>` can be broken out of. Clean.
* **Server Action CSRF** (`action-handler.ts` + `csrf-protection.ts`). The `origin`↔`host`
  comparison uses `new URL(origin).host` and blocks a mismatch. `isCsrfOriginAllowed` only
  matters when `serverActions.allowedOrigins` is configured (default `[]` blocks everything), and
  `matchWildcardDomain` correctly refuses `*.com` / bare `**` and anchors segments right-to-left.
  No default-config bypass. The no-`origin`-header allowance is not browser-reachable (browsers
  force `Origin` on cross-site POST; a handcrafted request carries no victim credentials).
