# Round 5: SCF select2 title rendering, Classic Editor re-check, SQLite integration follow-up

Three fronts this round, as directed: finish the SCF relationship/post_object select2
lead from round 4, then move to Classic Editor and SQLite Database Integration.

## SCF: relationship/post_object select2 title rendering

Both fields feed attacker-reachable data (post titles, for posts the current user can
read) into select2 dropdown results — exactly the shape of bug that produces stored XSS
in an admin session. Traced both, since they use genuinely different mechanisms:

**`relationship` field** (`class-acf-field-relationship.php::get_post_title()`): escapes
server-side with `esc_html()` before anything else happens, then — only for the
`featured_image` display option — prepends a `<div class="thumbnail"><img ...></div>`
wrapper built from `acf_get_post_thumbnail()`. That thumbnail HTML is real, unescaped
concatenation, so traced it specifically: `acf_get_post_thumbnail()` builds
`'<img src="' . $data['url'] . '" alt="" />'` with **no `esc_url()`/`esc_attr()` on
`$data['url']`** — a genuine missing-escaping spot. Whether it's reachable depends on
whether `$data['url']` can ever contain a `"` or `<`. It comes from
`wp_get_attachment_image_src()` (the attachment's own uploaded-file URL) or
`wp_mime_type_icon()` (a built-in WP icon, trusted). Checked WP core's
`sanitize_file_name()` (`wp-includes/formatting.php`): its `$special_chars` strip list
explicitly includes `"`, `<`, and `>`, and every upload path runs through it via
`wp_unique_filename()`. So under the normal upload flow this can't carry an injectable
character — recording it as a **defense-in-depth gap worth fixing, not an independently
exploitable finding**: it only becomes a live bug if some other code path (a filter, a
different attachment-creation route that bypasses `sanitize_file_name()`) can get an
untrusted string into an attachment's stored URL.

**`post_object` field** (`class-acf-field-post_object.php::get_post_title()`): does the
opposite — explicitly `html_entity_decode()`s the title with a comment saying "unescape
for select2 output which handles the escaping," i.e. it deliberately defers to the
client. Traced the client side to confirm that's actually true rather than assuming it:
`_acf-select2.js`'s `Select2_4.initialize()` defaults `templateResult`/`escapeMarkup` to
`false`, and — critically — when they're falsy, `templateResult` is `delete`d (letting
select2's own built-in safe rendering run) and `escapeMarkup` is replaced with a real
escaping function (`acf.strEscape`, which HTML-entity-escapes `& < > " '`) before select2
is ever instantiated. Neither `_acf-field-post-object.php` nor `_acf-field-relationship.js`
override these defaults, so the "select2 handles the escaping" comment is accurate: the
raw, unescaped title is escaped exactly once, client-side, before insertion — not zero
times. (Relationship field's custom list-based UI, separately, is why it needs its own
server-side `esc_html()` — it isn't select2-rendered the same way.) No double-escaping
either, since post_object's `html_entity_decode()` exists specifically to undo any
double-application before the client's single escaping pass. Closed — the two fields use
different but each internally-consistent escaping strategies, and neither leaves a gap
under normal use.

## Classic Editor: fresh full-file pass

Round 1 called this clean; re-checked from scratch under the "write-then-execute" +
missing-escaping lens rather than trusting the earlier conclusion. The entire plugin is
one 1,064-line file (`classic-editor.php`) — small enough to grep exhaustively rather than
sample. Zero `file_put_contents`/`fwrite`/dynamic `include`/`require`/`eval`/`unserialize`/
`extract` calls anywhere in it — it only reads/writes options (`update_option`,
`get_option`) and toggles editor-choice UI. Every `echo`/inline-PHP output site in the
settings-page HTML is either a hardcoded `' checked'` literal gated by a boolean, or a
translated string via `_e()`/`__()`, or explicitly `esc_url()`'d (the one dynamic URL,
`$edit_url`). The one non-obvious `echo` (`clear: <?php echo $clear; ?>;` in a Safari-fix
inline `<style>` block) turned out to be a hardcoded `'left'`/`'right'` literal from
`is_rtl()`, not attacker-reachable. Reconfirmed clean — nothing to chase here; this
plugin's entire attack surface is "does a WP option get set to a value the plugin already
constrains to a fixed set of strings," and it does.

## SQLite Database Integration: identifier quoting + backslash-escape parity

Two more checks against the MySQL→SQLite translator, picking up from where round 2/3 left
off (LIKE-escape, SAVEPOINT quoting, `ON DUPLICATE KEY UPDATE`, `JSON_EXTRACT`/`JSON_SET`
already verified there).

**Identifier quoting** (`WP_Sqlite_Connection::quote_identifier()`): backtick-quotes with
doubled-backtick escaping (`'`' . str_replace('`', '``', $id) . '`'`), and deliberately
*not* SQLite's standard double-quote identifier syntax — the code comment cites SQLite's
own documented quirk that a misspelled double-quoted identifier silently falls back to
being treated as a string literal instead of erroring, which is exactly the kind of
footgun that produces this class of bug. Choosing backtick quoting instead avoids that
whole failure mode. Well-reasoned, correctly implemented.

**Backslash-escape parity** (new standalone-harness test, `/tmp/sqlite-fuzz2/`,
not committed — throwaway like the round 2 harness): the concern was whether the
translator's lexer recognizes MySQL's default backslash-escape convention
(`\'` = escaped quote, `\\` = escaped backslash, active whenever `NO_BACKSLASH_ESCAPES`
isn't set, which is WordPress's default) the same way the underlying value was actually
escaped by `$wpdb`'s own `_real_escape()` upstream — a mismatch here is the classic
"parser and engine disagree about where the string ends" injection class. Fed it
`addslashes()`-escaped payloads with one and two trailing backslashes immediately before
the terminating quote (`'a\\' OR '1'='1'` and `'a\\\\' ; DROP TABLE t; --'` before
addslashes, `'a\\\\\' ; DROP TABLE t; --'` after — the odd/even-backslash-count case that
breaks naive escaping implementations). Inspected the actual translated SQLite query for
each: the translator correctly converts every MySQL `\'` into SQLite's doubled `''`, and
lone backslashes pass through untouched (SQLite doesn't need to escape them). Checked the
stored value against what MySQL's own escaping rules would have produced for the same
input — they matched exactly in every case, and none of the `DROP TABLE`/`UNION SELECT`
payload text ever left the string literal to become executable SQL structure (confirmed
by re-querying the table afterward — 4 rows, un-dropped, in original order).

## Conclusion

Three fronts, three negatives, each for a specific, checked reason rather than a
surface-level "looks fine": SCF's two select2 paths use different-but-correct escaping
strategies (one server `esc_html()`, one client `strEscape` deferred deliberately) with
one real but non-reachable defense-in-depth gap flagged (missing `esc_url()` in
`acf_get_post_thumbnail()`); Classic Editor re-confirmed to have no dangerous sinks at
all in its entire 1,064-line surface; SQLite integration's identifier quoting and
backslash-escape translation both hold up under adversarial input. Continuing to work
both fronts — SCF and Classic Editor/SQLite — as directed; nothing exploitable found yet
this round.
