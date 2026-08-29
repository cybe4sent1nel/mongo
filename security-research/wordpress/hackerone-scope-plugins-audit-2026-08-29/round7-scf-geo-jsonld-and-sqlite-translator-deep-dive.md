# Round 7: chasing the two named leads from round 4/README — both close clean

Continuing the WordPress.org HackerOne program's four in-scope plugins (Classic Editor,
Create Block Theme, Secure Custom Fields, SQLite Database Integration — **not** Automattic's
program; VaultPress/Jetpack stays out of scope for this program per the scope correction in
`README.md`). This round specifically follows up the two leads the README flagged as "the
most promising unexplored" after round 4/5: SCF's GEO/JSON-LD structured-data output, and the
SQLite translator's less-common branches. Also did a fresh pass over Create Block Theme's REST
surface looking for a second, higher-severity finding alongside the confirmed bidirectional-BAC
bug (round 6). All closed clean — recorded here in full rather than silently, per this audit's
running practice of keeping negative results on the record.

## Lead 1: SCF's GEO/JSON-LD structured-data output — closed, correctly hardened

`src/AI/GEO/GEO.php::render_jsonld_script()` is the single shared sink for all JSON-LD output
(both post-level, `Outputs/Posts.php`, and block-level, `Outputs/Blocks.php`, funnel through
it). It builds the `<script type="application/ld+json">` tag as:

```php
echo "<script type=\"application/ld+json\">\n";
echo wp_json_encode( $jsonld_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_UNESCAPED_UNICODE );
echo "\n</script>\n";
```

The `$jsonld_data` array is built from raw ACF field values (`GEO::format_field_value_for_jsonld()`
deliberately does **not** HTML-escape field values — correct, since JSON-LD is not an HTML
context) via `GEO::process_fields()`, so any field mapped to a `schema_property` (e.g. a
Textarea/WYSIWYG field pointed at `description`) can inject arbitrary content into this JSON
structure. `JSON_UNESCAPED_SLASHES` alone would make a `</script>`-breakout trivial (the closing
tag needs no escaping to smuggle through a naively-encoded JSON string) — but `JSON_HEX_TAG` is
also set, and that flag converts **every** `<` and `>` in the encoded output to `<`/`>`
unconditionally, before any output reaches the page. That closes the only realistic escape route
from inside a `<script>` block: `</script>` in the source data becomes the six characters
`</script>` in the rendered HTML, which a browser's HTML parser cannot interpret as a
tag close. Confirmed by reading `render_jsonld_script()` in full — there is no second, less-careful
JSON-LD emission path; `Outputs/Posts.php` and `Outputs/Blocks.php` both call this one function,
never `echo`/`printf` the data themselves. The `<!-- SCF AI JSON-LD: ... -->` debug comments both
files also emit are separately checked: every value interpolated into them
(`$post_type`, `$block['name']`) goes through `esc_html()` first.

**Conclusion: not exploitable.** This is a case where JSON-encoding with `JSON_HEX_TAG` is the
correct and sufficient escaping discipline for a `<script type="application/ld+json">` sink, and
SCF applies it consistently across every code path that reaches this sink. No bug.

## Lead 2: SQLite Database Integration's translator, less-common branches — no bug found; documenting why this lead is now de-prioritized

Went through the remaining categories the round-4/5 pass didn't reach: `DATE_ADD`/`DATE_SUB`
interval arithmetic, `DATE_FORMAT`, the `LIKE`/`REGEXP` operator translation, and the
`ON DUPLICATE KEY UPDATE` → `ON CONFLICT DO UPDATE SET` rewrite (including the SQLite<3.35.0
legacy fallback path, which is the most structurally unusual code in the file — it re-executes a
failed query with a clause built from **parsed text out of SQLite's own error message**).

Every one of these, on inspection, follows the same discipline the round-4/5 pass already
verified for the string-literal/identifier core:

- **`DATE_ADD`/`DATE_SUB`** (`translate_runtime_function_call()`): builds
  `DATETIME(<date>, '<sign>' || <value> || ' <unit>')` via `sprintf()`. `<unit>` is spliced
  directly into the query text, unquoted — but it is the *translated* form of the interval's
  `unit` grammar production (`DAY`/`WEEK`/`MONTH`/etc.), a fixed enumerated token set the MySQL
  grammar itself constrains at parse time; there is no grammar position here that accepts
  arbitrary text. `<value>` is likewise the recursively-translated (i.e. already
  correctly-quoted-if-a-literal) form of the interval's numeric expression, the same pattern used
  everywhere else in the translator, not a raw string splice.
- **`DATE_FORMAT`**: does a `strtr()` substitution on the *translated* (already SQL-quoted) format
  string, then `sprintf()`s it into the query alongside the *translated* date expression. Both
  operands are recursively-translated SQL fragments, never raw request data.
- **`LIKE`/`REGEXP`**: `translate_like()` appends a literal `ESCAPE '\\'` and delegates to
  `translate_sequence()` for the operands (each side individually translated/quoted); `REGEXP`
  delegates to SQLite's `REGEXP` operator (backed by a UDF, not string-built SQL). No
  string-concatenation sink here at all — the `@TODO` comments in this method are about
  **behavioral** parity gaps (SQLite's ASCII-only case-insensitivity, unimplemented `ESCAPE '...'`
  clause support), not security.
- **`ON DUPLICATE KEY UPDATE` legacy fallback** (SQLite < 3.35.0 only): parses column names out
  of SQLite's own `UNIQUE constraint failed: table.col1, table.col2` exception text — the most
  "clever hack" code in the file, and the one place that looked most likely to have skipped the
  quoting discipline under the pressure of string-parsing logic. It doesn't: every parsed column
  name is passed through `quote_sqlite_identifier()` before being spliced back into the retried
  query. The column names themselves are also not attacker input in any direct sense — they come
  from the SQLite engine's own reflection of the (already-created, admin/installer-authored)
  table schema, not from request data.
- **JSON functions** (`JSON_*`): grepped for any MySQL `JSON_*` function translation — there
  isn't one. These functions simply aren't implemented by the translator (fall through to the
  `default` case in `translate_function_call()`, which just passes the syntax through
  untranslated, i.e. SQLite will error on them as unrecognized functions). Nothing to translate
  means nothing to get wrong here — this branch is empty, not risky.
- **Filesystem-adjacent MySQL functions**: grepped the whole translator file for `LOAD_FILE`,
  `OUTFILE`, and PHP's own `fopen`/`file_get_contents`/`file_put_contents`/`exec`/`shell_exec`/
  `system`/`passthru`/`proc_open` — none found outside the two legitimate `PDO::exec()` calls used
  to run the (already-built-safely) SQLite queries themselves. MySQL's file-read/file-write
  functions aren't implemented at all, so there's no path from a `LOAD_FILE()`-shaped query
  string to a real filesystem operation.

**Also found, out of scope for this program**: `packages/mysql-proxy/` is a real MySQL
wire-protocol server (`bin/wp-mysql-proxy.php`, a CLI entry point) that lets an actual `mysql`
client, MySQL Workbench, phpMyAdmin, etc. connect to the plugin's SQLite backing store as if it
were a MySQL server. Grepped the rest of the plugin for any reference to this package
(`MySQL_Proxy`, `mysql-proxy`, `wp-mysql-proxy`) — there is none. It is not wired into the
WordPress plugin's runtime in any way; a site running SQLite Database Integration never executes
this code unless an operator manually runs the CLI tool themselves as a separate, deliberate dev
process. Flagging its existence for the record (a MySQL-protocol implementation is exactly the
kind of thing worth an auth-handshake review on its own merits), but not chasing it as a
WordPress-plugin finding — a HackerOne WordPress.org triager would correctly close a bug in code
that never runs as part of the shipped plugin as Not Applicable / requires non-default,
attacker-can't-reach configuration.

**Also checked**: Create Block Theme's full REST route table (`class-create-block-theme-api.php`)
for a second, weaker-gated route alongside the already-reviewed `can_modify_theme()` (`edit_themes`
+ `wp_is_file_mod_allowed()`) checks. Found one route, `/font-families` (GET), gated on the
weaker `edit_theme_options` capability instead — but it's read-only (returns font family names/
URLs already present in the active theme's own `theme.json`/style variations, nothing
attacker-supplied, nothing sensitive beyond what the theme already exposes to any user with
Customizer-adjacent access) and `edit_theme_options` is itself an Editor-and-above capability, not
a low-privilege one. Not a meaningful finding on its own. `/update`'s screenshot-replacement path
(`rest_update_theme` → `CBT_Theme_Utils::replace_screenshot()`) was traced for a path-traversal/
SSRF angle (a `sanitize_text_field()`-only-sanitized `screenshot` value looked promising at a
glance) — closed: `copy_screenshot()` resolves the value through `attachment_url_to_postid()`
first, so it only ever operates on URLs of attachments *already in this site's own Media Library*,
not arbitrary URLs or paths. And this whole route requires `edit_themes` (admin-only) regardless.

## Honest assessment: diminishing returns on manual review of this translator

The SQLite translator (`class-wp-mysql-on-sqlite.php`, 7942 lines) has now had two passes
(round 4/5's core string/identifier-quoting review, this round's function/operator-translation
review) and both land on the same conclusion: this code is written with injection-safety as an
explicit, consistently-applied design constraint — every re-serialized value or identifier goes
through `quote_sqlite_value()`/`quote_sqlite_identifier()`, and every other operand is a
recursively-translated (therefore already-safe) SQL fragment, never a raw string splice from
request data. That is the correct pattern, applied correctly, everywhere this pass looked.

Continuing to manually grep-and-read the remaining branches (window functions, subquery
correlation handling, the ~3200-line information-schema builder's `ALTER TABLE`/index-rebuild
paths) is very unlikely to turn up a classic "forgot to quote" bug at this point — two passes
across the highest-risk parts (literal/identifier quoting, then function/operator translation)
came back clean both times, which is itself evidence this codebase had real security review
during development, not just luck. A third pass of the same kind (read more code, look for the
same pattern) has sharply diminishing odds of success. If this lead is worth pursuing further, the
right next tool is a **differential/fuzz-testing harness** — generate MySQL query variants
programmatically and diff this translator's SQLite execution results against a real MySQL
instance's — rather than more manual reading; that's a materially different (and materially
larger) effort than the code-reading passes done so far, so flagging it as a deliberate stopping
point for this method rather than continuing to read code with falling expected value.

## Round summary

No new SQLi/RCE/stored-XSS/broken-access-control bug found this round. The confirmed finding
remains round 6's SCF bidirectional-field broken access control (report drafted in
`HACKERONE-REPORT-scf-bidirectional-bac.md`, artifact published). Both round-4/5 "unexplored
lead" flags are now resolved as negatives, with reasoning recorded above rather than left open.
