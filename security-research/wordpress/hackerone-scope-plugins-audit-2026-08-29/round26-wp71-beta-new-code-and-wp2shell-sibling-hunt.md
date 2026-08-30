# Round 26: auditing WordPress 7.1's genuinely new code, plus a sibling hunt off the
# disclosed 7.1-beta "wp2shell" pre-auth RCE chain (CVE-2026-63030 + CVE-2026-60137)

Directed to go deeper into WordPress core specifically around the 7.1 beta/release cycle. Two
angles, both against a real `7.1.0` tag checked out fresh from `WordPress/wordpress-develop`
(`daaca56d3d`), diffed against the last 7.0.x release (`7.0.4`) to isolate what's actually new:

1. **Every genuinely new PHP file introduced in 7.1** (`git diff --diff-filter=A 7.0.4 7.1.0`) —
   the highest-probability location for a fresh bug, since it's unreviewed by years of the usual
   WordPress core scrutiny.
2. **A sibling hunt off the publicly disclosed "wp2shell" chain** (CVE-2026-63030 REST API
   batch-route confusion + CVE-2026-60137 SQL injection in `WP_Query`'s `author__not_in`), which
   the 7.1 *beta* releases were confirmed vulnerable to before beta2 shipped the fix — exactly the
   kind of "beta-only, since-patched" issue the request pointed at, and a perfect search pattern
   given how precisely its root cause is documented.

**Result up front: no fresh Medium+ finding in either direction. The new 7.1 code is
unusually well-escaped by comparison to code audited earlier in this session, and the wp2shell
fix's exact bug shape ("sanitize only inside an `is_array()` check, cast-and-implode raw otherwise")
does not reproduce anywhere else in `WP_Query`, `WP_User_Query`, `WP_Term_Query`, or
`WP_Comment_Query` after a full, deliberate sweep of every `__in`/`__not_in`-style parameter.**

## 1. New-in-7.1 files audited

`git diff --diff-filter=A 7.0.4 7.1.0 -- src/` (excluding JS/CSS/block.json/images) surfaces 14 new
PHP files. Read and traced data flow in the highest-value ones:

- **`class-wp-rest-view-config-controller.php`** (846 lines) and its data source
  `class-wp-view-config-data.php` — new `GET /wp/v2/view-config` endpoint. Read-only, returns
  layout/column *configuration* (widths, sort fields, form field arrangement), never real entity
  data. `get_required_capability()`'s fallback to `edit_posts` for any unrecognized `kind` is a
  deliberate, documented design choice (a baseline floor for third-party-registered kinds via the
  `get_entity_view_config_{$kind}_{$name}` filter), not a validation bypass — the values returned
  are inert UI schema, not sensitive data.
- **`class-wp-rest-icon-collections-controller.php`** and `class-wp-icon-collections-registry.php`
  — new `GET /wp/v2/icon-collections` endpoint. Also read-only, and only returns
  `slug`/`label`/`description` metadata for **server-registered** collections — no client input
  ever reaches an output sink here.
- **New blocks**: `playlist.php`, `playlist-track.php`, `tabs.php`, `tab-list.php`,
  `tab-panel.php`. Read every render callback in full. All consistently escape correctly:
  `esc_url()` on every URL, `esc_attr()`/`esc_html()`/`wp_strip_all_tags()` on every text value, and
  — notably — every place that injects a *directive attribute* (`data-wp-context`,
  `data-wp-interactive`, etc.) does so via `WP_HTML_Tag_Processor::set_attribute()`, which HTML-attribute-encodes
  its value automatically, rather than raw string concatenation. `playlist.php` even has an explicit
  comment explaining *why* it uses `wp_strip_all_tags()` instead of `esc_html()` for values destined
  for `wp_interactivity_state()`'s JSON encoding (to avoid double-encoding) — this is code written
  with real escaping-context awareness, in clear contrast to the historically-fragile
  `wp-admin/includes/media.php` sinks found in Round 25.
- **`json-schema.php`** — a schema-*shape* transformation utility (draft-04 keyword filtering) that
  never touches actual request/response values, only schema metadata developers define. Not a data
  sink.
- **`class-wp-filter-sentinel.php`** — a single-line marker class with no logic, inert.

### A fragile-but-not-exploitable pattern found in a new shared helper

`wp_get_tooltip_helper()` (`wp-includes/general-template.php`, new in 7.1, backing the new
`wp_get_tooltip()`/`wp_get_toggletip()` functions used by `wp-login.php`'s new "Remember Me" help
text) builds its markup by **concatenating `$button` directly into an `sprintf()` format string**
rather than passing it as a positional argument — confirmed by the default button template itself
containing literal `%3$s`/`%4$s` placeholders that the *outer* `sprintf()` call fills in. This means
any literal `%` character inside a caller-supplied `$args['button']` override could be
misinterpreted as a stray format specifier by PHP's `sprintf()`. Traced the actual risk two ways:
(1) `$args['button']` is documented as developer-supplied "existing markup," not attacker/request
input, and no 7.1 call site passes anything but a hardcoded string; (2) even in the worst case where
a stray `%` caused an unexpected substitution, every value that could land in an unintended spot
(`esc_attr($classes)`, `esc_attr($id)`, `esc_attr($label)`, `esc_attr($icon)`, `esc_html($content)`)
is already fully escaped before reaching `sprintf()`, so a misplacement produces a rendering glitch
or a PHP `ValueError` (a crash — explicitly out of scope), never unescaped markup. A real
code-quality fragility, not a live vulnerability.

## 2. Sibling hunt off the disclosed wp2shell chain (CVE-2026-63030 / CVE-2026-60137)

Public writeups (WordPress/wordpress-develop security advisories
[GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q)
and
[GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf))
confirm 7.1's *beta* releases were vulnerable until beta2 shipped fixes for both halves of an
unauthenticated pre-auth RCE chain: a REST API `/wp-json/batch/v1` route-confusion bug that let a
sub-request reach `WP_Query` without going through the normal REST argument-schema validation
(bypassing the type enforcement that would otherwise force `author__not_in` to an array of
integers), combined with a genuine SQL injection in `WP_Query::get_posts()`'s handling of that
now-unvalidated `author__not_in` value.

### The exact root cause, read directly from the fix commits

Located the fix commits via `git log -S` on the affected files
(`74d37a344c`/`97b5a75246` "Query: Force `author__not_in` values to be integers"; `85015b84fb`/
`fa72c12879` "REST API: sub-requests must always use dispatch."; `c8bdf1fa12`/`1000ed1649` "REST
API: Ensure errors in batch requests propogate."). The `WP_Query` bug's exact shape:

```php
// BEFORE (vulnerable):
if ( ! empty( $query_vars['author__not_in'] ) ) {
	if ( is_array( $query_vars['author__not_in'] ) ) {
		$query_vars['author__not_in'] = array_unique( array_map( 'absint', $query_vars['author__not_in'] ) );
		sort( $query_vars['author__not_in'] );
	}
	$author__not_in = implode( ',', (array) $query_vars['author__not_in'] );   // <-- (array) cast, no absint()
	$where         .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
```

The `absint()` sanitization only ran **inside** the `is_array()` branch. When
`author__not_in` arrived as a non-array (a raw string), the fallback used `(array) $value` — which
for a scalar just wraps it in a single-element array (`(array) "x" === array( 'x' )`) — and
implodes that directly into the query, injecting the raw string verbatim. The REST route-confusion
bug is what let an attacker actually deliver a non-array `author__not_in` value to this code path,
bypassing the REST schema's own `type: array` enforcement for the parameter.

Confirmed both fixes are present in the current `7.1.0`/trunk source by direct code reading (not
assumed from the advisory): `WP_Query::get_posts()` now uses `wp_parse_id_list()` — which normalizes
*any* input shape to a validated integer list regardless of type — and
`WP_REST_Server::serve_batch_request_v1()` now explicitly calls
`$single_request->has_valid_params()` and `$single_request->sanitize_params()` for every sub-request
before dispatch, closing the schema-bypass side of the chain.

### Systematic sibling search: does the same "is_array()-gated sanitize, raw-cast fallback" pattern
### exist anywhere else?

Grepped every `implode(` call building a WHERE/ORDER-BY/JOIN fragment across `class-wp-query.php`,
`class-wp-meta-query.php`, `class-wp-tax-query.php`, `class-wp-date-query.php`,
`class-wp-comment-query.php`, `class-wp-user-query.php`, and `class-wp-term-query.php`, and traced
the sanitization discipline of every one individually rather than pattern-matching superficially:

- `post__in`, `post__not_in`, `post_parent__in`, `post_parent__not_in`, `author__in`,
  `category__in`/`__not_in`/`__and`, `tag__in`/`__not_in`, `tag_slug__in`/`__and`, `comment__in`/
  `__not_in`, `parent__in`/`__not_in` (comments), `post_author__in`/`__not_in` (comments),
  `nicename__in`/`__not_in`, `login__in`/`__not_in` (users), `term_taxonomy_id`, `object_ids`
  (terms) — every one of these applies `array_map( 'absint' | 'intval' | 'esc_sql' |
  'sanitize_title_for_query', ... )` **unconditionally** at (or immediately before) the point the
  value is imploded into SQL, never gated behind an `is_array()` check with an unsafe fallback.
  Since `array_map()` itself throws a `TypeError` on a non-array second argument in PHP 8, a
  non-array value reaching any of these either gets safely sanitized or crashes outright — neither
  outcome reproduces the injection. `post_name__in`'s WHERE-clause branch is additionally guarded by
  `is_array( $query_vars['post_name__in'] )` at the `if` itself, with no unguarded `else` that uses
  the raw value — so a non-array value there is silently skipped rather than unsafely used.
- `comment__in` in `WP_Comment_Query` (a second occurrence at `:1230`) and every `__in`/`__not_in`
  key in that class route through `wp_parse_id_list()` directly — the same safe, type-agnostic
  normalizer the `author__not_in` fix adopted, applied consistently from the start.
- `WP_Term_Query`'s `term_taxonomy_id` and `object_ids` (the two candidates that looked
  unsanitized at first grep, since their `array_map('intval', ...)` calls sit a few lines above
  the `implode()` rather than inline) are unconditionally sanitized immediately beforehand
  (`if ( '' === $args[...] ) { $args[...] = array(); } else { $args[...] = array_map( 'intval', (array) $args[...] ); }`)
  — applied regardless of the original type, unlike the vulnerable `author__not_in` pattern.

No sibling found. The `author__not_in` bug appears to have been a genuine one-off inconsistency in
how that specific parameter was written, not a repeated pattern across the surrounding, structurally
similar code — everywhere else already used the safe, unconditional-sanitization idiom.

### Checking the REST batch dispatch fix holds up

Read `WP_REST_Server::serve_batch_request_v1()` in full on current trunk. Confirmed each sub-request
goes through `match_request_to_handler()`, an explicit `allow_batch` capability-flag check per
route, `has_valid_params()`, and `sanitize_params()` — all before `respond_to_request()` actually
dispatches it. This is a materially more thorough validation sequence than a route-confusion bug
would survive; no gap found in the current implementation.

## Conclusion

This was a genuinely different kind of pass than earlier rounds: instead of picking one file and
reading deep, it used (a) "what's brand new in this release" and (b) "a precisely-documented
disclosed bug's exact code shape" as two independent, systematic search patterns across the whole
of WordPress core's query-building layer. Both came back negative for a fresh, live Medium+ finding.
The new 7.1 code reviewed is consistently and correctly escaped; the wp2shell fix is complete and
its specific anti-pattern does not recur elsewhere. Not fabricating a finding to match the premise
that one must exist — if there's a specific area of the 7.1 diff (the 1042 changed files include much
more than what was covered here) the user wants prioritized next, that's a reasonable and honest
next step, rather than continuing to re-scan the surface already covered in this and prior rounds.
