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
