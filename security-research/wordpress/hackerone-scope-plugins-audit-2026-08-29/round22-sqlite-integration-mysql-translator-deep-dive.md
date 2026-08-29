# Round 22: first deep dive into SQLite Database Integration's MySQL→SQLite query
# translator (`class-wp-mysql-on-sqlite.php`, 7,942 lines) — two already-patched
# near-miss SQL-injection-class bugs found and confirmed fixed in the current
# release; no live bypass found after adversarially re-testing both fixes

Per the user's request to widen scope rather than keep re-scanning the media-attachment surface,
this round targets **SQLite Database Integration** specifically — flagged in this audit's own
README as "not fully audited" — and picks the area most structurally likely to hide the kind of
bug being hunted for: the MySQL-to-SQLite query translator itself. A translator that must
re-serialize a parsed MySQL AST into SQLite syntax is exactly the shape of code where an
"escaping asymmetry" between what one code path assumes and what another code path (or the actual
downstream engine) does creates a SQL injection — structurally the same *class* of bug as the
disclosed #3931777 report (a security-relevant assumption silently violated by a code path that
doesn't hold up its end), just in a different subsystem. Verified against `abf0dac137c`, tag
`v3.0.1` — the current latest release (`HEAD` at clone time **is** `v3.0.1`, confirmed via
`git log v3.0.1..HEAD` returning zero commits, so there is no unreleased fix or unreleased bug to
account for either way).

**Result up front: found two genuine, serious escaping-consistency bugs in the exact bug class
being hunted for — both already fixed by the maintainer within the last several weeks, both
confirmed present in the current shipped release. No live, unpatched bypass found in either fix
after adversarially re-testing it. No third finding.**

## 1. Verifying the core quoting primitives are sound

`quote_sqlite_identifier()` → `WP_SQLite_Connection::quote_identifier()`
([`class-wp-sqlite-connection.php:271`](https://github.com/WordPress/sqlite-database-integration/blob/v3.0.1/packages/mysql-on-sqlite/src/sqlite/class-wp-sqlite-connection.php#L271))
wraps in backticks and doubles any embedded backtick — correct, and used consistently everywhere
the translator emits a table/column/index name (spot-checked ~40 call sites across the file).
`quote_sqlite_value()` → `WP_SQLite_Connection::quote()` delegates straight to PDO's native SQLite
`quote()`, which is safe by construction. `translate_string_literal()`
([`:4518`](https://github.com/WordPress/sqlite-database-integration/blob/v3.0.1/packages/mysql-on-sqlite/src/sqlite/class-wp-mysql-on-sqlite.php#L4518))
always routes the fully-decoded literal value through `quote_sqlite_value()` before it reaches the
output string — confirmed this holds regardless of what bytes the literal contains, since the
entire decoded value is wrapped as one PDO-quoted unit, not concatenated as raw text.

## 2. Near-miss #1 (fixed): `NO_BACKSLASH_ESCAPES` SQL mode broke the escaping contract between `$wpdb` and the driver

Found via `git log --grep=escap`, which surfaced
[`247ffea` "Improve string escaping (#466)"](https://github.com/WordPress/sqlite-database-integration/commit/247ffea57a61a3e2cecf8c42731dcd90b8e805f2)
(29 Jul 2026, included in v3.0.1). Before this fix,
`WP_SQLite_DB::_real_escape()` — the function every `$wpdb->prepare( '%s', ... )` call in
WordPress core and every plugin relies on — used plain PHP `addslashes()`:

```php
public function _real_escape( $data ) {
	if ( ! is_scalar( $data ) ) {
		return '';
	}
	$escaped = addslashes( $data );          // <-- before the fix
	return $this->add_placeholder_escape( $escaped );
}
```

The escaped text this produces is later **re-parsed** by the driver's own MySQL lexer
(`WP_MySQL_Lexer`) as part of the translation pipeline — so the escaping contract here isn't "is
this safe for *some* database," it's "will this driver's own parser, running under whatever SQL
mode is currently active, interpret these bytes as the same logical string `$wpdb` meant to
insert." The commit fixes this by making the driver's own connection — now exposing a
MySQL-compatible `PDO::quote()`
([`class-wp-mysql-on-sqlite.php:1012`](https://github.com/WordPress/sqlite-database-integration/blob/v3.0.1/packages/mysql-on-sqlite/src/sqlite/class-wp-mysql-on-sqlite.php#L1012))
implementing the exact mysqlnd/libmysqlclient escape table — the *sole* source of truth, and by
**rejecting `NO_BACKSLASH_ESCAPES` outright** with an explicit error rather than partially
supporting it:

```php
if ( in_array( 'NO_BACKSLASH_ESCAPES', $modes, true ) ) {
	throw $this->new_not_supported_exception( "SQL mode 'NO_BACKSLASH_ESCAPES'" );
}
```

**Why this mattered as a bug, not just a correctness nit:** in MySQL's default mode, escaping a
`'` as `\'` is correct because the lexer treats a backslash as an escape character. Under
`NO_BACKSLASH_ESCAPES`, MySQL's own grammar stops treating `\` as special — the *only* way to
escape a quote is to double it (`''`). Any escaping function that unconditionally assumes
backslash-escaping (as a hardcoded `addslashes()`-style implementation does) will, under that mode,
emit `\'` for a literal `'`+backslash sequence in the source data — and a downstream parser that
correctly honors `NO_BACKSLASH_ESCAPES` will read that backslash as an ordinary character and treat
the very next `'` as the string's real terminator. That is a textbook string-literal escape bypass:
whatever text the attacker placed after the now-prematurely-closed string is interpreted as SQL
syntax rather than string content. This is the same well-established bug *class* as the classic
`addslashes()`/multi-byte-charset MySQL injection bugs from the 2000s, here triggered by a SQL-mode
mismatch instead of a charset mismatch. Confirmed the fix is complete for the currently-supported
mode surface: `NO_BACKSLASH_ESCAPES` can no longer be entered at all (attempting it throws), so the
mismatch it created cannot arise anymore in the shipped release. Grepped the entire repository for
`addslashes(` post-fix — zero remaining occurrences, confirming no sibling fallback was left behind
in a second file.

## 3. Near-miss #2 (fixed): quoted identifiers were unescaped using string-literal rules

Found in the same `git log` sweep:
[`087e83f` "Add ANSI_QUOTES and SQL mode validation (#452)"](https://github.com/WordPress/sqlite-database-integration/commit/087e83f2cd76c4ba9f963688b27d6bc0a7dbf1f7)
(6 Aug 2026, also included in v3.0.1), whose own description states plainly: the driver "applied
string escaping to quoted identifiers." Read the before/after of `WP_MySQL_Token::get_value()`
([`class-wp-mysql-token.php:66`](https://github.com/WordPress/sqlite-database-integration/blob/v3.0.1/packages/mysql-on-sqlite/src/mysql/class-wp-mysql-token.php#L66)):
a backtick-quoted identifier (e.g. `` `my_col` ``) was, before the fix, unescaped through the same
"MySQL string literal" rule table used for `'...'`/`"..."` literals — meaning a column or table
name containing a literal backslash sequence that happened to match a recognized MySQL string
escape (`\n`, `\0`, `\%`, etc.) would have that sequence *silently transformed* while being decoded
into the identifier's real value, before that value gets re-quoted for SQLite. Since MySQL's actual
grammar defines backslash as **always literal, never an escape**, inside a quoted identifier
(only doubling the bounding quote character is special), the old code's decoded identifier value
could diverge from the identifier MySQL itself would have understood — the kind of "the safety
check parses this differently than the real engine will" gap I was specifically told to hunt for.
The fix makes identifier-unquoting a single, explicit branch that never touches backslashes:

```php
if (
	WP_MySQL_Lexer::BACK_TICK_QUOTED_ID === $this->id
	|| $this->sql_mode_no_backslash_escapes_enabled
) {
	return str_replace( $quote . $quote, $quote, $value );   // doubling only, no backslash rule
}
```

Traced how this interacts with the newly-added `ANSI_QUOTES` mode (where `"col"` is *also* a valid
identifier syntax, not just a string literal): the lexer's `read_quoted_text()` decides identifier
vs. literal **at tokenization time** and assigns the `BACK_TICK_QUOTED_ID` token type to a
double-quoted identifier under `ANSI_QUOTES` — so by the time `get_value()` runs, checking
`BACK_TICK_QUOTED_ID === $this->id` correctly captures both quoting styles uniformly. No
disambiguation gap found between the lexer's classification and the token's unquoting rule.

## 4. Adversarially re-testing both fixes for a remaining gap — none found

- Confirmed no other file in the repository still calls `addslashes(` (would indicate a second,
  unfixed instance of near-miss #1) — zero hits repo-wide outside of removed code.
- Confirmed the "native" Rust-backed lexer path (`mysql-on-sqlite/src/mysql/native/`) is a thin
  facade class (`class WP_MySQL_Lexer extends WP_MySQL_Native_Lexer {}`) whose actual
  implementation ships as a separately-compiled, optional PHP extension not present in this
  checkout — not the code path any normal WordPress install runs (it requires manually compiling
  a Rust-based PHP extension), so it isn't the practically relevant surface here even if it existed
  as a residual concern; the standard pure-PHP `WP_MySQL_Lexer`/`WP_MySQL_Token` classes that
  *did* receive both fixes above are what every real deployment uses.
- Confirmed `_real_escape()`'s new implementation strips exactly the two bounding quote characters
  `quote()` adds (`substr( $quoted, 1, -1 )`) with no off-by-one risk, since the only call site
  passes no `$type` argument, so the LOB/NATL prefix branches that would otherwise widen the
  quoted string never fire here — verified against the fix's own added test coverage
  (`test_quote_matches_mysql_escaping`, `test_quote_supports_parameter_types`).
- Checked `class-wp-sqlite-pdo-user-defined-functions.php` (the MySQL-function-as-SQLite-UDF
  layer — `REGEXP`, `CONCAT`, JSON functions, etc.) for any UDF that builds and executes a *second*
  dynamic SQL string from its own arguments (which would bypass the translator's escaping
  entirely) — zero `->query()`/`->exec()`/`->prepare()` calls in that file; UDFs receive real PHP
  values through SQLite's native callback mechanism, not text to be re-parsed, so this class of
  bug structurally cannot occur there.

## Conclusion

This is a different, deeper area than any prior round in this audit, and it surfaced real technical
substance: two genuine bugs in exactly the class being hunted for (a validation/escaping boundary
silently invalidated by an assumption a different code path or SQL mode doesn't honor), each
significant enough that the maintainer treated it as worth a dedicated fix commit within the past
month. Both are confirmed present in, and fixed by, the current `v3.0.1` release — there is no
live, reportable vulnerability here today. Continuing to search this exact file for a third instance
of the same pattern past this point would mean re-reading code already covered above rather than
genuinely covering new ground; the honest next step is a different subsystem (the
`class-wp-sqlite-information-schema-builder.php`/`-reconstructor.php` pair, which synthesize
`information_schema` views and weren't covered in this pass, or Secure Custom Fields's still-named
GEO/JSON-LD output lead from the README) rather than a fourth pass over this translator.
