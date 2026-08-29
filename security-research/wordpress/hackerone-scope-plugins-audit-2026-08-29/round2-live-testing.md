# Round 2: live testing + the newer/less-audited code paths

Follow-up to `README.md` in this directory, in response to "don't stop until you find fresh live
bugs from the mentioned classes" (SQLi/RCE/stored XSS). This round switched from pure source
reading to actually running the code — live-installed two of the four plugins on the throwaway
WordPress 7.1 instance and built a standalone test harness for the SQLite translator — and dug
into the newest, most complex, least-previously-covered code in each plugin. Still no exploitable
SQLi/RCE/stored-XSS confirmed. Documenting exactly what was ruled out and how, so the next round
doesn't re-walk the same ground.

## Live setup

- Installed Secure Custom Fields and Create Block Theme into
  `~/wp-site/wordpress/wp-content/plugins/` (the same live WP 7.1 instance used for the
  `finalize_item()` and VaultPress empirical rounds). SCF needed `composer install --no-dev`
  (pulls `justinrainbow/json-schema` — this succeeded despite the sandbox's usual GitHub-auth
  block, by falling back to a source clone). Both activated cleanly, no fatal errors.
- Logged in as the admin test account and activated both via the real `wp-admin/plugins.php` flow
  (not a DB flag flip), matching this session's established "test the real flow, not a shortcut"
  practice.
- For the SQLite Database Integration package, built a standalone harness
  (`/tmp/sqlite-fuzz/*.php`, not committed — throwaway) around
  `packages/mysql-on-sqlite/tests/tools/dump-sqlite-query.php`'s pattern: instantiate
  `WP_MySQL_On_SQLite` directly against an in-memory SQLite DB and inspect
  `get_last_sqlite_queries()` for the actual translated SQL text, with no WordPress bootstrap
  needed. This is a fast, direct way to test the translator's output on crafted input.

## SQLite Database Integration: LIKE-escape translation — correct

Hypothesis worth taking seriously: MySQL's `LIKE` defaults to backslash as its escape character;
SQLite's `LIKE` has **no** default escape character at all (needs an explicit `ESCAPE '\'`
clause). If the translator forgot to add that clause, every `$wpdb->esc_like()`-escaped pattern
used throughout WordPress core and plugins (`\%`, `\_` meant as literal percent/underscore) would
silently degrade to normal SQLite wildcard behavior once translated — turning an intended
exact-match query into a broader wildcard match. That's a real, previously-known bug class in
MySQL-compatibility shims.

Tested directly: created a real table, inserted `'foo_bar'` (literal underscore) and `'fooXbar'`,
then ran the MySQL query `... LIKE 'foo\\_bar'` (the `esc_like()` shape) through the translator.

```
OUT: SELECT * FROM `wp_options` WHERE `option_name` LIKE 'foo\_bar' ESCAPE '\'
```

The `ESCAPE '\'` clause is correctly appended. Ruled out.

## SQLite Database Integration: SAVEPOINT-name identifier handling — correct

`ROLLBACK TO SAVEPOINT <name>` / `SAVEPOINT <name>` / `RELEASE SAVEPOINT <name>` are three of the
few places the translator's own class reconstructs a query with `sprintf()` around a variable
(`$savepoint_name`) instead of a parameter placeholder — worth checking whether that variable was
still safely quoted. Traced it: `$savepoint_name = $this->translate( ... 'identifier' ... )`,
which always routes through `translate_pure_identifier()` (backtick-quotes, doubles internal
backticks) before the `sprintf()` ever sees it — so it's already a fully-quoted SQLite identifier
by the time it's concatenated. Not a bug.

## SQLite Database Integration: a real (but non-security) parser defect, investigated and downgraded

Found empirically: a syntactically valid MySQL string literal built from adjacent-literal
concatenation with an escaped quote (`'a\''b'`, which MySQL parses as `'a\''` . `'b'` = `a'b`)
makes `WP_Parser::parse()` emit ~12 PHP warnings (`Undefined array key`, `Attempt to read property
"id" on null`) before ultimately throwing `Failed to parse the MySQL query.` — a valid query gets
rejected, which is a real functional defect. Checked whether this scales into a DoS: repeated the
pattern 1×/2×/4×/8× in one query and measured warning count and elapsed time — both stayed flat
(~12 warnings, ~2ms) regardless of repetition count, so it's a fixed one-time parser hiccup, not an
amplification/resource-exhaustion vector. It also fails safe (a caught exception, not a
misinterpreted query), so it isn't a SQLi angle either. Downgraded from "possible finding" to
"real robustness bug, not a security bug" — noting the negative result honestly rather than
padding it into something it isn't.

## Create Block Theme: nothing new past round 1's conclusion (not re-litigated in depth this round)

Live-installed to have it available; didn't find a new angle beyond round 1's slug/path-traversal
analysis. All theme-header text fields (`description`, `author`, `author_uri`, `tags_custom`,
etc.) go through `sanitize_text_field()`/`sanitize_textarea_field()`, which strip HTML tags
entirely — closes off `<script>`-tag stored XSS via those fields regardless of where they're later
echoed. They do **not** strip quote characters, so an attribute-breakout payload (`" onmouseover=
"..`) could theoretically still survive into an unescaped `href`/`src` attribute somewhere — but
every route that accepts these fields requires `edit_themes` (admin-only), so at most this is
admin-attacking-themselves, not a privilege-crossing bug, and wasn't pursued further as a result.

## Secure Custom Fields: the front-end-form field-key grant system (SCF 6.8.5–6.9.4) — audited in depth, held up

This is the newest, most complex, most security-critical code in the plugin — an HMAC-based
mechanism (`verify_form_meta()` / `decode_form_meta_token()` / `restrict_submitted_field_keys()`
in `includes/forms/form-front.php`) that restricts which ACF field keys a front-end `acf_form()`
submission is allowed to write, added specifically to close off "submit extra field keys the form
never rendered" attacks. Being new and this security-sensitive, it was the best candidate this
round for a fresh logic bug — audited it token-by-token:

- Tokens are `base64(json).hmac_sha256(json, wp_salt('nonce'))`, verified with `hash_equals()`
  (constant-time) before the JSON is ever decoded — no unauthenticated-then-decode pattern.
- The decoded metadata's key set is checked for an **exact** match (`array_keys($meta) !==
  $expected_keys`) plus a type check on every field, rejecting extra or missing keys outright —
  no silently-ignored-field surprises.
- Binds `blog_id`, a per-render `render_id`, a `form_anchor` (hash of the exact submitted `_acf_form`
  bytes), and `target_post_id` — all compared with `hash_equals()`. A token minted for one render/
  target can't be replayed against a different one.
- Freshness: `issued_at` checked against a TTL (`DAY_IN_SECONDS` default) with a 1-minute
  clock-skew allowance in the forward direction — bounded replay window, not indefinite.
- For `new_post`-target forms, a separate HMAC (`get_new_post_fingerprint()`) binds the *entire*
  new-post settings array (author, status, taxonomy, "post password" included) into the grant, with
  an explicit comment noting this is specifically to stop the post-password field from being an
  offline-guessable low-entropy target — a level of care that suggests this code already went
  through a real threat-modeling pass.
- `restrict_submitted_field_keys()` applies the allowlist via `array_intersect_key()` on the
  **top-level** `$_POST['acf']` keys only (documented as intentional — nested container fields
  like Repeater/Group resolve their sub-field keys server-side). Checked whether that's actually
  safe by tracing Repeater's `update_value()`/`validate_value()`/`update_row()`: every one of them
  iterates `foreach ( $field['sub_fields'] as $sub_field )` — the server-side, DB-loaded list of
  that specific repeater's actual sub-fields — and only *reads* `$row[$sub_field['key']]` from the
  submission; it never iterates whatever keys the client happened to send. So smuggling an
  unrelated field's key into a nested position (`acf[allowed_repeater][0][some_other_fields_key]`)
  doesn't work — that key is simply never looked at, regardless of what's in the array. The
  top-level-only enforcement is safe *because* of how the container fields already consume their
  sub-values, not despite it.

No bypass found in this mechanism. This was the most promising specific lead of the round and it
held up under a genuinely adversarial read.

## Secure Custom Fields: WYSIWYG / raw-HTML field storage vs. `unfiltered_html` — held up

Checked the other classic ACF-adjacent bug class: does a WYSIWYG (or otherwise HTML-permissive)
field's value get sanitized at *save* time based on the submitting user's actual `unfiltered_html`
capability, the way core `post_content` does? Traced the full chain:

- `acf_save_post()` runs `$_POST['acf'] = wp_kses_post_deep( $_POST['acf'] )` unconditionally for
  any user without `unfiltered_html` (`acf_allow_unfiltered_html()` → `current_user_can(
  'unfiltered_html' )`, filterable but not defaulting open). `wp_kses_post_deep()` is
  `map_deep( $data, 'wp_kses_post' )` — genuinely recursive over arbitrarily nested repeater/
  flexible-content/clone structures, not just the top level.
- The front-end form path (`form-front.php`'s `enqueue_form()`) calls this same `acf_save_post()`
  — it isn't a side path that bypasses the filter.
- The one thing that *does* bypass ACF's own `wp_kses_post_deep()` call: `_post_title`/
  `_post_content` are extracted out of `$_POST['acf']` earlier, in `pre_save_post()` (hooked to
  `acf/pre_save_post`, which fires before `acf_save_post()`), and handed directly to
  `wp_insert_post()`/`wp_update_post()`. Checked whether that's actually a gap: it isn't — WP
  core's own `wp_insert_post()` independently applies the `content_save_pre` filter
  (`wp_filter_post_kses`, registered unconditionally in `default-filters.php`, itself gated on
  `current_user_can( 'unfiltered_html' )`) to `post_content` regardless of caller. ACF not
  double-filtering this one case just means it's relying on WP core's own equivalent protection,
  which is genuinely present.
- REST API writes go through a second, independent enforcement point
  (`class-acf-rest-api.php:331`: `acf_allow_unfiltered_html() ? $data : wp_kses_post_deep( $data
  )`), so this isn't a form-only protection.

No bypass found.

## Secure Custom Fields: `pro/` — mostly stub files; the one real file is safe by construction

`pro/` turned out to be almost entirely 2-line stub/include files (the actual Options-Pages/
Repeater/Flexible-Content logic already lives in `includes/`, already covered above) — Pro
features were merged into the free WordPress.org fork, and `pro/` is what's left of the old
directory split. The one file with real content,
`pro/blocks-auto-inline-editing.php` (262 lines, lets a user click directly into a rendered SCF
block preview and edit a field's value inline), is worth a specific mention because it looked
promising at a glance: it parses a block's *already-rendered HTML output* with `DOMDocument`, then
rewrites matched text nodes and sets several `data-acf-*` attributes from field data
(`$element->nodeValue = $field_value`, `$element->setAttribute( 'data-acf-placeholder',
$field_placeholder_text )`, etc.) — a raw-HTML-rewrite-from-field-data pattern is exactly the shape
that's usually worth checking for injection. It's safe by construction, though:
`DOMNode::nodeValue` and `DOMElement::setAttribute()` both treat their argument as plain text/
attribute-value content and entity-encode `<`, `>`, `&`, and quotes when the document is later
serialized via `saveHTML()` — there's no way to reach these two DOM APIs with a string and have it
produce new markup, unlike raw string concatenation into an HTML template. Confirmed this is the
mechanism actually used throughout (no `$html .= $field_value`-style concatenation anywhere in the
file) before ruling it out.

## What's still not covered (honest, specific, not a blanket disclaimer)

- **SCF's GEO/JSON-LD front-end output was checked in round 1 and confirmed safe** (`JSON_HEX_TAG`
  on `wp_json_encode()` blocks `</script>` breakout regardless of field content) — not re-opened
  this round.
- **The SQLite translator's ~7900-line `class-wp-mysql-on-sqlite.php`** — this round covered
  string-literal quoting, identifier quoting, LIKE-escape translation, and SAVEPOINT handling
  specifically because they were the highest-prior-probability spots for a dialect-mismatch bug.
  The remaining bulk of the file (JSON_* functions, window functions, date arithmetic, `INSERT ...
  ON DUPLICATE KEY UPDATE`, subquery flattening) is still unexamined.
- **Gutenberg** — only the core `serialize_block_attributes()`/comment-delimiter escaping was
  checked (confirmed already-hardened: `--`, `<`, `>`, `&` are all unicode-escaped before being
  embedded between `<!-- wp: ... -->`). The plugin itself is a much larger codebase (block-library
  PHP render callbacks, the REST block-renderer/patterns/templates controllers) that hasn't been
  opened at all.
- **WordPress Core beyond the already-audited `finalize_item()` fix and the block-comment-delimiter
  check** — comments, XML-RPC, and the customizer REST/AJAX surfaces haven't been looked at this
  round.

## Honest summary

Two rounds of real effort — source audit plus, this round, live installs and a standalone
translator-fuzzing harness — have not produced a confirmed SQLi/RCE/stored-XSS bug in any of the
four in-scope plugins. What this round adds over round 1 is depth on the *newest* and most
security-load-bearing code specifically (SCF's front-end-form HMAC grant system, the SQLite
translator's LIKE/identifier/savepoint handling) rather than breadth — and that code held up under
a genuinely adversarial read, not just a skim. The named "not yet covered" list above is where a
third round should go next, in roughly that priority order (SCF `pro/`, then the SQLite
translator's less-common functions, then Gutenberg proper) rather than re-checking what's already
been ruled out here.
