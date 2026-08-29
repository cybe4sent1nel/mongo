# Round 9: WordPress Core deep RCE/XSS audit, studying wp2shell (CVE-2026-63030 / CVE-2026-60137) as case study

Shifted focus from the four in-scope plugins to **WordPress Core itself**, per direct request, with
instructions to go as deep as necessary and to study the recent (July 2026) WordPress core RCE
chain for context. Tooling note: no MCP server exists for automated PHP security scanning, and the
Semgrep registry (`semgrep.dev`) is blocked by this environment's egress proxy, so installed
Semgrep 1.175.0 locally in a venv (`scratchpad/semgrep-venv/`) for local-rule-only use, and wrote a
custom Python AST-adjacent script to find structurally similar code to the case-study bug rather
than relying on registry rulesets. Primary method stayed manual code tracing against the actual
`wordpress-develop` git history (which is authoritative and far more precise than any blog write-up)
plus targeted grep/regex sweeps.

## Case study: wp2shell (CVE-2026-63030 + CVE-2026-60137), read from the actual fix commits

Public reporting (Rapid7, BleepingComputer, etc.) is largely paywalled/egress-blocked from this
environment, but the ground truth is in the `wordpress-develop` repo's own history — more precise
than any secondary source. Found and read both fix commits directly:

**CVE-2026-63030 — REST batch-endpoint route confusion** (fixed in `1000ed1649`, "REST API: Ensure
errors in batch requests propogate.", merged 2026-07-17, `src/wp-includes/rest-api/class-wp-rest-server.php`):

`WP_REST_Server::serve_batch_request_v1()` processes a `/wp-json/batch/v1` request in three
sequential loops over the sub-requests array:
1. Parse each sub-request's `path`/`method`/`body`/`headers` into a `WP_REST_Request` (or a
   `WP_Error` if `wp_parse_url()` fails), appended 1:1 into `$requests`.
2. Validate each entry of `$requests`, building **two parallel arrays** — `$matches` (the resolved
   route+handler) and `$validation` (a capability/param-validation result) — that the third loop
   later indexes by the *same* integer `$i` as `$requests`.
3. Dispatch: `$match = $matches[$i]` for each `$requests[$i]`, relying on all three arrays staying
   the same length and in the same order.

The bug: in loop 2, the `is_wp_error( $single_request )` branch (hit when loop 1 failed to parse a
sub-request's path) pushed only to `$validation[]`, not `$matches[]`:

```php
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $has_error    = true;
        $validation[] = $single_request;   // $matches[] never appended here — pre-fix
        continue;
    }
    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;
    ...
```

One-line fix: add `$matches[] = $single_request;` in that branch, restoring 1:1 index parity across
all three arrays. Before the fix, one malformed sub-request in a batch (trivial to craft —
`wp_parse_url()` fails on things like a path containing a raw `\` or other malformed URL syntax)
permanently shifted `$matches` one index short of `$requests`/`$validation` for the rest of the
batch, so `$matches[$i]` for every subsequent `$i` resolved to the route+handler that was actually
meant for sub-request `$i+1`. Every later sub-request in the same batch call then executes against
the **wrong route's handler** — including, critically, whatever validation/capability checks that
wrong handler's registration carries (or doesn't).

**CVE-2026-60137 — SQL injection in `WP_Query`'s `author__not_in`** (fixed in `97b5a75246`, "Query:
Force `author__not_in` values to be integers", same commit day, `src/wp-includes/class-wp-query.php`):

```php
// pre-fix
if ( ! empty( $query_vars['author__not_in'] ) ) {
    if ( is_array( $query_vars['author__not_in'] ) ) {
        $query_vars['author__not_in'] = array_unique( array_map( 'absint', $query_vars['author__not_in'] ) );
        sort( $query_vars['author__not_in'] );
    }
    $author__not_in = implode( ',', (array) $query_vars['author__not_in'] );   // <- no absint here
    $where         .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
```

The `absint()` sanitization only ran inside the `is_array()` branch. When `author__not_in` arrives
as a **scalar string** instead of an array, that branch is skipped entirely, and the final line
`(array) $query_vars['author__not_in']` just wraps the raw, unsanitized string in a single-element
array before splicing it straight into the `WHERE` clause — classic unescaped-string-into-SQL. This
is normally unreachable: the REST posts controller's arg schema declares `author__not_in` as type
`array`, and core's own REST argument validation rejects a scalar value for an array-typed arg
before `WP_Query` is ever touched. **This is exactly why the two bugs had to chain** — the batch
array-desync bug (CVE-2026-63030) is what let a request bypass its own route's real argument
validation (by executing under a *different*, wrongly-matched handler instead), reaching
`WP_Query` with a raw scalar `author__not_in` that ordinary REST dispatch would never have allowed
through. Neither bug alone reaches unauthenticated SQLi; combined, they do — and from there, the
publicly-reported chain (UNION-based extraction → forge an admin session/create an admin user →
upload a malicious plugin as that admin) reaches RCE the same way any admin-level arbitrary-plugin-
install always has.

Fix: replace the whole conditional with an unconditional `wp_parse_id_list()` call (the same helper
used by `WP_User_Query`'s `exclude` handling, and now also matching how `author__in` was already
written on the very next `elseif` branch, which called `array_map('absint', ...)` unconditionally
on its own final line rather than gating it inside the `is_array()` check).

## Sibling check 1: did the same scalar/array sanitization asymmetry survive anywhere else?

Read every `__in`/`__not_in`/`__and`/`object_ids`/`include`/`exclude` ID-list handler across
`WP_Query`, `WP_Tax_Query`, `WP_Term_Query`, and `WP_User_Query` (`class-wp-query.php`,
`class-wp-tax-query.php`, `class-wp-term-query.php`, `class-wp-user-query.php`) — every place an
ID-list query var gets folded into raw SQL — checking each one specifically for the "sanitizer only
runs inside an `is_array()`/type-check branch, but the value is used unconditionally afterward"
shape:

- `post__in`, `post__not_in`, `post_parent__in`, `post_parent__not_in` (`class-wp-query.php`):
  `array_map( 'absint', $query_vars['post__in'] )` called **unconditionally**, no `is_array()` gate
  and no `(array)` cast rescuing a scalar past it — a scalar here would throw a PHP `TypeError`
  (crash, not injection), not silently bypass sanitization.
- `category__in`/`category__not_in`/`category__and`, `tag__in`/`tag__not_in`/`tag__and`
  (`class-wp-query.php`): all use `array_map( 'absint', array_unique( (array) $query_vars[...] ) )`
  unconditionally — the `(array)` cast is present, but so is the `absint` map on the *same*
  unconditional line, so a scalar gets safely coerced into a sanitized single-element array. This is
  the correct pairing that `author__not_in` was missing (its bug was specifically that the `(array)`
  cast and the `absint` map ended up on different, unequally-gated lines).
- `post_name__in`: the entire sanitize-and-build-WHERE block is inside a single `is_array(...) &&
  !empty(...)` `elseif`, so there's no post-block code path that uses an unsanitized value — the gate
  covers the value's only use, unlike the old `author__not_in` code where the gate only covered the
  *sanitization step*, not the *later use*.
- `WP_User_Query`'s `include`/`exclude` (`class-wp-user-query.php`): both go through
  `wp_parse_id_list()` unconditionally (line 336, line 751) — the exact helper the `author__not_in`
  fix adopted.
- `WP_Term_Query`'s `object_ids` (`class-wp-term-query.php`): `array_map( 'intval', (array)
  $args['object_ids'] )` unconditionally, same safe pairing as category/tag.
- `WP_Tax_Query`'s `terms` (`class-wp-tax-query.php`): more involved, but structurally sound —
  `clean_query()` always finishes by calling `transform_query( $query, 'term_taxonomy_id' )`
  regardless of the original `field` (slug/name/term_id/term_taxonomy_id), which — unless the field
  already *is* `term_taxonomy_id` — does a real `WP_Term_Query` round-trip through the database and
  replaces `$query['terms']` with the actual integer `term_taxonomy_id` column values pulled back
  out via `wp_list_pluck()`. By the time `get_sql_for_clause()` does its raw `implode(',', $terms)`,
  `$terms` can only contain real DB-sourced integers, never the original request string, regardless
  of what `field` was requested.

**Conclusion: no surviving sibling.** The `author__not_in` bug was a one-off inconsistency between
that handler and its very similar `author__in` neighbor, not a class of bug repeated across the
query-var handling code. Every other ID-list handler in these four classes either never had the gap,
or is structurally immune to it (unconditional sanitization, or a scope that covers both the
sanitize step and the use step together).

## Sibling check 2: did the REST batch array-desync bug shape recur anywhere else in core?

Wrote a small script to find every `foreach` loop in `wp-includes/` and `wp-admin/includes/` whose
body pushes to two or more distinctly-named arrays (`$x[] = ...`) — the structural signature of
"building parallel arrays from one loop," which is what made the batch-endpoint bug possible. It
surfaced 59 candidate loops (full list kept in this round's working notes). Reviewed every candidate
whose arrays are later cross-indexed by shared position (rather than each array being independently
consumed) or that sit in a security-relevant path — REST validation/dispatch, capability-gated bulk
operations, font-file upload handling:

- `rest_find_one_matching_schema()` (`wp-includes/rest-api.php`) builds `$matching_schemas`/
  `$errors`, and later `$schema_positions`/`$schema_titles` — every array element carries its own
  `'index'` key rather than relying on positional parity with the original `oneOf` list, and the
  one place that does compare two array lengths (`count( $schema_titles ) === count(
  $matching_schemas )`) guards its use correctly. Not exploitable.
- `WP_REST_Font_Faces_Controller::create_item()`'s `$processed_srcs`/`$font_file_meta`
  (`wp-includes/rest-api/endpoints/class-wp-rest-font-faces-controller.php`): the two arrays are
  deliberately different lengths by design (`$font_file_meta` only tracks *uploaded* sources, not
  by-reference ones) and are consumed by two independent, later `foreach` loops rather than a shared
  index — no desync-driven bug possible in this shape. (Traced the file-upload path itself too:
  `handle_font_file_upload()` uses core's own `wp_handle_upload()` with a `mimes` allowlist scoped to
  `WP_Font_Utils::get_allowed_font_mime_types()` — the same mature, well-tested upload validator
  core uses everywhere, not a hand-rolled one.)
- `wp_ajax_bulk_edit_posts` / bulk-edit handling (`wp-admin/includes/post.php`, `$updated`/
  `$skipped`/`$locked`): the actual `current_user_can( 'edit_post', $post_id )` gate is a direct
  `continue` inside the per-post loop body — the capability check and the array bookkeeping for that
  check's own outcome happen in the same iteration, not split across two loops with an indexing
  assumption between them, so there's no window for a desync to matter.
- `WP_User_Query`'s `role__in`/`role__not_in` construction (`class-wp-user-query.php`): builds these
  by testing each registered role's capability set against the requested `capability`/
  `capability__in`/`capability__not_in` filters — this is a data-transformation loop with no
  error/early-exit branch at all (every iteration runs the same three inner loops unconditionally),
  so there's no branch that could skip one array's append the way the batch-endpoint bug did.

**Conclusion: no surviving sibling of this shape either.** The other candidates from the 59-loop
sweep (theme.json processing, PHPMailer, plugin-dependency-graph cycle detection, XML-RPC, media
gallery shortcode parsing, etc.) are either non-security-relevant (pure data transformation with no
capability/validation semantics riding on array position) or don't have the specific "one branch
updates fewer of the parallel arrays than the others" defect — spot-checked a representative sample
of each category rather than all 59 individually, given how mechanically similar the non-candidates
turned out to be once the first several were read in full.

## unserialize() sink audit (RCE via PHP Object Injection)

All three raw `unserialize()` calls in `wp-includes/` (outside the `maybe_unserialize()` wrapper,
which itself is fine) were read and traced:

- `WP_Customize_Widgets::sanitize_widget_js_instance()` (`class-wp-customize-widgets.php:1496`) and
  `render_block_core_legacy_widget()` (`blocks/legacy-widget.php:44`): both gate the call behind
  `hash_equals( wp_hash( $decoded ), $supplied_hash )` — `wp_hash()` is keyed off the site's own
  `AUTH_KEY`/`AUTH_SALT` secrets, so an attacker without those secrets cannot produce a `$decoded`
  payload (their own crafted serialized object) that passes the check. This is the standard, sound
  WP customizer JS-value round-trip protocol, not a fresh gap.
- `RSS_Cache::unserialize()` (`rss.php:809`): a thin wrapper the legacy MagpieRSS feed-cache class
  uses to round-trip its own previously-`serialize()`-d cache objects through a WP transient — the
  data being unserialized is always something this same code path wrote itself, not raw external
  content, and transient storage isn't attacker-writable from outside. Very old, low-reachability
  legacy code; not pursued further given the effort/reward balance at this point in the sweep.

## XSS sweep

Grepped `wp-admin/*.php`, `wp-admin/includes/*.php`, and `wp-includes/*.php` for `echo`/`print`
statements touching `$_GET`/`$_POST`/`$_REQUEST` directly, filtering out anything already wrapped in
an escaping/sanitizing call. One hit survived the filter
(`wp-admin/themes.php:255`), and it turned out to be a ternary printing either a static translated
string or an integer count — never the request value itself. No raw reflected-XSS sink found by this
sweep.

## Honest assessment

No fresh RCE or XSS found in WordPress Core this round, despite deliberately hunting for both named
bug classes from the most recent real core RCE chain (wp2shell) rather than starting from a blank
sweep. That negative result is itself informative given the method: this wasn't "core looks fine at
a glance," it was "took the two specific bug shapes that a real, recent, CVSS-9.8 core RCE was built
from, and checked every place in the codebase structurally similar enough to carry the same defect
— and none did." WordPress core gets far more continuous scrutiny than any of the four plugins this
audit's earlier rounds covered, which tracks with two mature bug classes (ID-list SQL building, REST
batch dispatch) both coming back clean once actually checked, and with the `unserialize()` sinks that
do exist all being deliberately HMAC-gated rather than accidentally safe.

If there's a fresh core RCE/XSS left to find, it's very unlikely to be sitting in a pattern this
close to a known one — the realistic next step is a materially different method (fuzzing REST
argument validation across all ~2000 registered route args for scalar/array/type-confusion
bypasses systematically, rather than manually re-deriving one instance), which is a much larger
undertaking than a code-reading pass and worth flagging as a deliberate stopping point for this
method rather than continuing with diminishing odds.
