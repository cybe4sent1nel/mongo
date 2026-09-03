# WordPress 7.1 core — block attribute sinks + mXSS sweep (2026-09-03)

Continuation of the low-privilege stored-XSS hunt against WordPress 7.1 core
(the surface that produced the Interactivity-directive finding, HackerOne
#3989843, closed as duplicate). This round targeted two fresh angles with
**live, empirical** verification on the running lab (localhost:8371, real
Contributor account, real kses save pipeline, real `the_content` render, and a
headless Chromium execution oracle). **No new vulnerability found. All negative.**

The value here is the empirical record so this ground is not re-covered, plus a
reusable methodology fact about `filter_block_kses`.

## Threat model

Contributor role: can author block content, **lacks `unfiltered_html`**, so all
saved content passes `wp_kses` (static HTML) and `filter_block_kses` (block
attribute JSON). The question each test answers: can a Contributor store a block
or markup that yields script execution when a victim views the post?

## 1. Block render callbacks — every attribute context is escaped

Swept all 92 `wp-includes/blocks/*.php` render callbacks for a free-form string
attribute reaching an HTML **attribute** context without `esc_attr` /
`set_attribute` / `get_block_wrapper_attributes`. None found. Specific
near-misses traced to ground:

| block | line | why safe |
|---|---|---|
| `breadcrumbs` | 188 | `--separator` CSS custom property via `get_block_wrapper_attributes` → `esc_attr`; CSS-only, no modern-browser XSS. |
| `icon` (new 7.1) | 82 | `wp_get_icon()` is **registry-gated** — an unregistered `icon` name returns `''`; `aria-label` set via `set_attribute`. |
| `playlist` / `playlist-track` (new 7.1) | — | track title/artist/album via `wp_strip_all_tags`, URLs via `esc_url`, waveform attrs via `esc_attr`, context via `wp_json_encode`. |
| `post-terms` | 41/46 | raw `prefix`/`suffix` concatenation is wrapped in `wp_kses_post()` at 52/54 before use. |
| `post-navigation-link` | 98/100 | `arrow` into `class=""` is whitelisted by `isset( $arrow_map[ $attributes['arrow'] ] )` (only `none`/`arrow`/`chevron`). |
| `cover` | 183 | background-image URL is `esc_url`'d then `set_attribute`'d. |
| `rss` | 58 | `$link` `esc_url`, `$title` `esc_html`, `rel` `esc_attr`. |
| `post-featured-image` | 109 | style string goes through `set_attribute` (CSS-only). |

### `post-navigation-link` `label` — deepest trace, still safe

`render_block_core_post_navigation_link` passes `$attributes['label']` **raw**
(no `esc_html`) as the link text to `get_next_post_link($format, $link)`, and
`get_adjacent_post_link` (link-template.php:2366-2371) drops that text between
`<a>` and `</a>` with only `%title`/`%date`/`%link` substitution — a genuine raw
sink. The `wp_kses_post()` calls at 71/77/86 only guard the `showTitle` branches;
the default `showTitle=false` + custom `label` path bypasses them.

**Why it is not exploitable:** `label` is a string block attribute, so on save
`filter_block_kses` runs `wp_kses_post` on its value (even inside the block
delimiter JSON — verified: an `onerror` payload is stripped to `<img src="x">`
before storage). And the label lands in HTML **content** context (anchor text),
where `wp_kses_post` output is safe. Live test `poc/t_navlabel3.php` confirms:
stored label `<img src="x">` (handler stripped), rendered
`<a … rel="next"><img decoding="async" src="x"></a>` — inert.

## 2. Methodology fact — `filter_block_kses` passes tag-free breakout strings

`filter_block_kses` sanitizes block **string attributes** by running
`wp_kses` — which strips disallowed **tags/attributes**. A value containing
**no HTML tag**, e.g. `x" onmouseover=alert(1) data-y="`, passes it **unchanged**
(verified live: `wp_kses_post()` returns it byte-for-byte; stored as
`x" onmouseover=alert(1) y="`). Therefore the only way a block
attribute becomes stored XSS is a block that emits such a value into an HTML
**attribute** context *without* `esc_attr`. Section 1 shows no core block does.
The universal wrapper is also safe: `get_block_wrapper_attributes(['class'=>'x"…'])`
returns `class="x&quot; …"` and a malicious `className` is `&quot;`-escaped
(`poc/t_classname.php`). And `WP_HTML_Tag_Processor::set_attribute`
(class-wp-html-tag-processor.php:4647-4665) escapes URI attrs via `esc_url` and
everything else via `< > & " '` → entities, with a name-validity gate rejecting
`"'>&</ =` and control chars — no attribute-name or value breakout.

## 3. mXSS battery — 36 payloads, kses output + full `the_content`, real Chromium

kses can produce a string that is safe under kses's own parser but that a
**browser** re-parses into script (foreign-content / integration-point / entity
context confusion — the DOMPurify-bypass family). Tested empirically:

- **Round 1** (`poc/mxss_kses.php`, 20 payloads): `<style>` swaps, `<title>` /
  `<textarea>` / `<xmp>` / `<template>` / `<noscript>` / `<noembed>` breaks,
  comment mXSS, `<math><mtext><table><mglyph>`, `<svg><foreignObject>`,
  attribute/entity breakouts, `expression()`, `@import javascript:`,
  `<base href=javascript:>`, `<link rel=stylesheet href=javascript:>`,
  `<form action=javascript:>`, `iframe srcdoc`.
- **Round 2** (`poc/mxss2.php`, 16 payloads): MathML/SVG **integration points** —
  `annotation-xml encoding=text/html`, `<svg><desc>`/`<title>`, `<mi>`/`<ms>`,
  `<svg><script>`, `xlink:href=javascript:`, entity/hex-encoded `onerror`,
  control-char / NUL attribute-name splits, CDATA-in-style, `<mglyph>`,
  `<img/src=x/onerror=…>`.

Each payload was run through the **real Contributor `wp_kses_post`**, and Round 1
additionally through the **full `apply_filters('the_content', …)`** pipeline
(`wpautop`, `wptexturize`, `do_blocks`, `wp_filter_content_tags`) to catch
transform-introduced mXSS. Every resulting string was loaded in **headless
Chromium** (`poc/mxss_run.cjs`) with `alert` hooked and `mouseover/click/focus/
load/error` dispatched to every node.

**Result: all 36 inert.** kses's tag allowlist drops `svg`, `script`,
`annotation-xml`, `foreignobject`, `mglyph`, `desc` outright, and strips every
event handler from allowed tags; the browser confirmed no resurrection through
the MathML tags kses does keep (`math`/`mtext`/`mi`/`ms`/`table`).

## Conclusion

WordPress 7.1 core's low-privilege **server-side** stored-XSS surface — block
render callbacks, block-attribute kses, the universal HTML-API escaper, and the
`the_content` transform chain — is sound against this session's tests. The one
real hole in this area remains the previously-reported **client-side
Interactivity directive** application (HackerOne #3989843, duplicate). No fresh
server-side stored XSS and no RCE were found this round.

### Reproduce

```
wp eval-file poc/t_navlabel3.php   --allow-root   # label sink neutralized by filter_block_kses
wp eval-file poc/t_classname.php   --allow-root   # className / wrapper escaping
wp eval-file poc/mxss_kses.php     --allow-root > mxss_out.json
wp eval-file poc/mxss2.php         --allow-root > mxss2_out.json
node poc/mxss_run.cjs                             # Chromium execution oracle -> all "inert"
```
