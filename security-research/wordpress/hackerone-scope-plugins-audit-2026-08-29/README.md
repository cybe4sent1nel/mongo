# Scope correction + audit of the four in-scope WordPress.org official plugins

## Scope correction (important — read first)

The WordPress HackerOne program's scope page is explicit:

> **Official WordPress plugins** — Only the following plugins that are officially maintained by
> WordPress.org are in scope: **Classic Editor, Create Block Theme, Secure Custom Fields, SQLite
> Database Integration**. Any other plugins, including those that list wordpressdotorg as a
> contributor or developer, are not in scope.

This means the prior round's work in `../vaultpress-remote-endpoint-2026-08-28/` (VaultPress /
Jetpack) is **not reportable to this program**. VaultPress is Automattic's plugin, not one of the
four WordPress.org-maintained plugins above — it belongs to Automattic's separate HackerOne
program. That research stays in this repo as legitimate, real findings, but flagging plainly: it
would be closed as Not Applicable if submitted here, and isn't being submitted here.

This round re-targets the actual in-scope surface: WordPress Core (already covered in
`../finalize-fix-audit-2026-08-28/`) plus the four listed plugins, audited for SQLi, RCE, and
stored XSS as asked.

## Method

Cloned all four plugins fresh from their canonical `WordPress/*` GitHub repos (the same source
WordPress.org's SVN mirrors from) at current HEAD / latest tag:

| Plugin | Repo | Version audited |
|---|---|---|
| Classic Editor | `WordPress/classic-editor` | 1.7.0 (HEAD, no tags — trunk-only plugin) |
| Create Block Theme | `WordPress/create-block-theme` | v2.10.1 |
| Secure Custom Fields | `WordPress/secure-custom-fields` | 6.9.5 (HEAD) |
| SQLite Database Integration | `WordPress/sqlite-database-integration` | v3.0.1 |

For each: grep-swept for the classic sink patterns (`$wpdb->query`/`get_*` without `prepare()`,
`eval`, `unserialize`, `extract`, `create_function`, `call_user_func*` on user-controlled names,
raw `echo`/`printf` of request- or DB-derived data), then manually traced every hit back to its
data source and forward to its rendering/execution context to check whether it's actually
attacker-reachable and actually unescaped/unparameterized — not just pattern-matched.

## Classic Editor — clean

1064 lines, entirely settings-management glue (register_setting, options get/set, admin UI). No
SQL, no eval/unserialize/exec family calls, no dynamic includes. Every echoed value is either a
static translated string, `esc_url()`-wrapped, or a hardcoded CSS token (`is_rtl() ? 'right' :
'left'`). No user input reaches an unescaped sink anywhere in the file. Nothing to report.

## Create Block Theme — one real-looking lead, ruled out

`CBT_Theme_Create::{clone_current_theme,create_child_theme,create_blank_theme}()` all build a
filesystem path as `get_theme_root() . DIRECTORY_SEPARATOR . $theme['slug']`, then `wp_mkdir_p()`
it and `file_put_contents()` several files into it (`theme.json`, `readme.txt`, `style.css`,
`screenshot.png`) — a `slug` that reached this unsanitized would be a path-traversal-to-arbitrary-
file-write, and from there RCE (write a `.php` file into an arbitrary directory reachable from the
web root).

Traced `$theme['slug']` back through the only place it's set: `CBT_REST_API::sanitize_theme_data()`
does `$sanitized_theme['slug'] = sanitize_title( $theme['name'] );` — derived from `name` via
`sanitize_title()`, which strips slashes and non-alphanumeric characters entirely, not from a
client-supplied `slug` field directly. `../../../etc/whatever` collapses to a plain slug string
with no path separators. Traversal isn't reachable.

Also checked: all seven `create-block-theme/v1` REST routes that reach these functions are gated
by `CBT_REST_API::can_modify_theme()` = `current_user_can( 'edit_themes' ) &&
wp_is_file_mod_allowed(...)` — Administrator-only, and respects `DISALLOW_FILE_MODS`/
`DISALLOW_FILE_EDIT`. An admin already has equivalent file-write via the core theme/plugin
installers, so even a hypothetical bypass here wouldn't be a privilege escalation. Nothing to
report.

## Secure Custom Fields — no bug found; documenting what was checked given the size

169k lines total (11M of that is `lang/` translations, ignored). Real source is `includes/`
(2.8M), `src/` (624K), `pro/` (128K). This is the most actively developed and highest-attack-
surface plugin of the four (custom field storage, admin UI, a REST API layer, and a newly-added
"AI Abilities" integration), so it got the most time, but nothing exploitable turned up:

- **SQL**: every `$wpdb->query()`/`get_results()`/`get_row()`/`get_var()` call found
  (`upgrades.php`, `acf-meta-functions.php`, `api-helpers.php`, `wpml.php`,
  `forms/form-taxonomy.php`) uses `$wpdb->prepare()` with placeholders, or (in the one non-prepare
  case, `form-taxonomy.php`'s `delete_term()`) builds a `LIKE` pattern via `$wpdb->esc_like()`
  before still passing it through `prepare()`. No raw concatenation of request data into SQL.
- **Object injection**: the one raw `unserialize()` call site (`acf_maybe_unserialize()`) is called
  with `array( 'allowed_classes' => false )` — the correct hardening that makes PHP Object
  Injection structurally impossible regardless of what classes are loaded in the process. All
  `unserialize()` usage in the codebase goes through this wrapper.
- **`extract()`**: the one call (`acf_get_view()`) uses `EXTR_SKIP` specifically to stop the
  extracted array from overwriting `$view_path`, and both arguments (`$view_path`, `$view_args`)
  come from the plugin's own internal call sites, not request data.
- **Stored XSS in the field-rendering pipeline**: traced the full label/instructions/wrapper-attrs
  rendering path (`acf_render_field_wrap` → `acf_render_field_label` / `acf_get_field_label` /
  `acf_render_field_instructions`). Labels go through plain `esc_html()`. Instructions/hints go
  through `acf_esc_html()` = `wp_kses( $string, 'acf' )`, filtered to WP core's own
  `$allowedposttags` list — the same allowlist normal post content is held to for non-
  `unfiltered_html` users, which strips `on*` event handler attributes and disallowed tags
  regardless of what's in the allowlist. Wrapper HTML attributes (including the `conditional_logic`
  array, which is JSON-encoded first) go through `acf_esc_attrs()`, which `esc_attr()`s every
  value including JSON-encoded arrays/objects. Flexible Content's renamed-layout-title feature
  (`Layout::action_buttons()`, a `phpcs:ignore OutputNotEscaped`-flagged spot that looked
  promising at a glance) turned out to double-escape both the default and renamed title
  (`esc_html()` then `acf_esc_html()` in `get_title()`, plus `esc_html()` again on the renamed
  value at the echo site) — the ignore comment's claim ("escaped earlier in function") checks out.
- **Systematically reviewed all 56 `phpcs:ignore ... OutputNotEscaped` suppression comments**
  outside of `bin/`/`docs/` build scripts (the pattern most likely to hide a real bug — a
  copy-pasted suppression comment where the actual escaping got dropped later). All of them
  checked out: either the value was escaped earlier in the same function/call chain, or it's
  developer-supplied HTML explicitly documented as such (`acf_form()`'s `html_before_fields`/
  `html_after_fields`/etc. args — set in the embedding theme/plugin's own PHP code, not attacker-
  reachable), or CSS run through `wp_strip_all_tags()`.
- **New "AI Abilities" REST-proxy layer** (`src/AI/Abilities/`, a 6.8.0-era feature port,
  ~19k lines across `src/AI/`): reviewed the ability-registration/execution model
  (`AbstractAbilityGroup::execute_rest_request()` dispatches through `rest_do_request()`, so the
  underlying REST route's own `permission_callback` still applies — this isn't a raw
  authorization bypass), and the two `FieldGroup` abilities in full — both gated by
  `current_user_can( acf_get_setting( 'capability' ) )`, ACF's own admin-capability setting
  (`manage_options` by default), matching what the native field-group editor requires. The field-
  sanitization callback (`prepare_field_for_ability_import()`) runs every text-ish sub-value
  (label, instructions, placeholder, prepend/append, wrapper class/id, choices, message,
  conditional-logic values) through `sanitize_text_field()`/`wp_kses_post()`/`sanitize_key()` as
  appropriate before import. Didn't find a capability mismatch or an unsanitized field reaching
  storage through this path.

**Not exhaustively covered**, flagged honestly rather than silently skipped: `pro/` (Options Pages,
Repeater/Flexible Content Pro extras), the full `src/AI/GEO/` schema-generation code (~/2500 lines,
builds JSON-LD from post/field data — a plausible stored-XSS-in-structured-data surface if any
field value reaches raw `<script type="application/ld+json">` output unescaped, not yet checked),
and the WPML integration beyond the two `$wpdb->get_row()` calls already confirmed parameterized.

## SQLite Database Integration — spot-checked the highest-risk component, no bug found, not exhaustive

This is structurally the most interesting target of the four: it's not a typical plugin but a
MySQL-grammar lexer/parser plus a ~20k-line AST-to-SQLite query translator
(`class-wp-mysql-on-sqlite.php`, 7942 lines) that reconstructs every `$wpdb` query WordPress core
and every other plugin issues, in a different SQL dialect, for storage on SQLite. A translator like
this is exactly the shape of codebase where SQL injection bugs hide — dialect-conversion string/
identifier-quoting mismatches are a distinct, well-known bug class from "forgot to call
`$wpdb->prepare()`".

Checked the string-literal and identifier translation paths specifically, since that's where a
mismatch would live:

- `translate_string_literal()` gets the **already-unescaped** value from `WP_MySQL_Token::get_value()`
  (which itself correctly reverses MySQL's backslash-escape rules, including the doubled-quote and
  `NO_BACKSLASH_ESCAPES`-mode cases — read in full), then re-encodes it for SQLite via
  `quote_sqlite_value()`, which delegates to `$this->connection->quote()` — the real PDO/SQLite3
  driver's own quoting routine, not a hand-rolled string-replace. Same pattern for identifiers:
  `quote_sqlite_identifier()` delegates to `$this->connection->quote_identifier()`. Delegating to
  the underlying driver's own quoting function, rather than reimplementing it, is the correct
  pattern and closes off the most obvious version of this bug class.
- Grepped the 3233-line `class-wp-sqlite-information-schema-builder.php` (handles `CREATE TABLE`/
  `ALTER TABLE`/`information_schema` emulation — the other place a hand-built SQL string with an
  interpolated identifier could plausibly hide) for raw string-built SQL; the handful of `sprintf()`
  calls found are all building **exception messages**, not queries.

**Not exhaustively covered, and this is the honest limiting factor**: `class-wp-mysql-on-sqlite.php`
is 7942 lines implementing dozens of individual MySQL-construct-to-SQLite translations (window
functions, `JSON_*` functions, date arithmetic, `INSERT ... ON DUPLICATE KEY UPDATE`, subqueries,
etc.) — only the string/identifier-quoting core was traced in this pass. A translator this size,
this new (SQLite-as-a-WordPress-backend is a recent feature, materially less battle-tested than
20-year-old wpdb/MySQL core code), warrants a dedicated follow-up pass over the less-common
translation branches rather than a single grep sweep — that's the most promising unexplored lead
of this round, not a closed one.

## Scope correction #2: DoS/crash findings are explicitly excluded (rounds 11, 16)

The program's own exclusion list (scope doc 9) is explicit: **"Brute force, DoS, memory
exhaustion, phishing, text injection, or social engineering attacks"** are out of scope, full
stop. Rounds 11 and 16 (`round11-CONFIRMED-...` and `round16-CONFIRMED-...`) each document a
real, reproducible, single-request PHP crash (uncaught `TypeError`, CWE-248/CWE-20) in WordPress
Core's REST API and XML-RPC server respectively. Both write-ups classify the finding as a Denial
of Service in their own text — which means both fall squarely inside the exclusion, regardless of
how many methods/routes are affected, how the crash was found, or what side effects were traced
(round 16's auto-draft database-row side effect included — that row is created by the exact same
`get_default_post_to_edit()` call every ordinary "Add New Post" admin action already triggers, so
it's the same normal side effect landing before an excluded crash, not a distinct pollution
primitive, and unbounded row growth reads as the disk-flavored sibling of the explicitly-excluded
"memory exhaustion" category either way). Leaving their `CONFIRMED` filenames as-is for the
historical record of what was actually found and verified, but the correct status for both is
**Not Applicable / Informative, not a reportable finding** — flagging this plainly rather than
letting a future pass over this audit mistake either for a submittable bug. Going forward, this
audit does not pursue crash/DoS findings as an end goal, regardless of breadth or novelty; only
RCE, SQLi, XSS, auth bypass, privilege escalation, IDOR/broken access control, and SSRF-with-real-
impact are being hunted from here on. Round 6 (SCF bidirectional-field broken access control)
remains the audit's one confirmed, in-scope, reportable finding.

## Round 18: second confirmed finding — SCF gallery `ajax_get_sort_order` IDOR (Low severity)

Round 17 dynamically re-verified Create Block Theme's REST authz boundary (clean) and audited every
`ACF_Ajax` subclass's capability checks in Secure Custom Fields, finding one gap by static read:
`ACF_Field_Gallery::ajax_get_sort_order()` checks a valid field-key-bound nonce but never checks
read access on the attacker-supplied attachment IDs it queries — unlike its two sibling functions in
the same file, which both add the missing object-level `current_user_can()` check on top of the
identical nonce gate. Round 18 built the fixture needed to reproduce this over real HTTP (a real
gallery field, an Administrator-owned `private` post with a real attachment, and a genuine
Contributor session) and confirmed it: the Contributor's own, legitimately-obtained nonce for their
own unrelated gallery field was accepted to query existence/sort-order data for the Administrator's
private attachment, with a negative control showing the sibling function correctly denies the
identical request. This is real, reproducible Missing Authorization / IDOR (CWE-639/CWE-862) — rated
honestly as **Low severity**, since the only information disclosed is attachment-ID existence and
relative sort ordering (no title, content, URL, or other metadata). See
`round17-cbt-authz-dynamic-verify-scf-ajax-audit-sqlite-integration-injection-probe.md` and
`round18-CONFIRMED-scf-gallery-sort-order-idor.md` for full detail.

## Scope correction #3: Low severity is below the acceptance floor — Medium is the minimum (round 18)

Standing instruction: **Low-severity findings are out of scope for submission; Medium is the
minimum accepted severity going forward.** Round 18's gallery `ajax_get_sort_order` IDOR is real,
reproducible, and correctly root-caused — that part of the write-up is accurate and stays as the
historical record of what was actually verified — but it was explicitly self-rated Low severity in
its own text (existence + relative-ordering disclosure only, no content/metadata), which puts it
below this floor. Correcting the record: **round 18 is not a reportable finding under the current
bar.** It does not get relabeled `CONFIRMED` away from being real — it's still a genuine bug — but
it is not being submitted, and future passes over this audit should not count it as the second
confirmed finding. Round 6 (SCF bidirectional-field broken access control) remains the audit's only
finding that clears the bar. Hunting continues for fresh Medium/High/Critical findings only — RCE,
SQLi, XSS, auth bypass, privilege escalation, and IDOR/broken access control with real impact beyond
bare existence/ordering disclosure (still excluding DoS per scope correction #2).

## Honest summary

No new SQLi/RCE/stored-XSS vulnerability confirmed in any of the four in-scope plugins this round.
Classic Editor and Create Block Theme got a genuinely complete pass (both small enough to fully
trace). Secure Custom Fields and SQLite Database Integration are large enough that "no bug found"
means "no bug found in the areas covered," not "fully audited" — both have named, specific
unexplored areas above rather than a blanket "looks fine." All four are actively maintained by
WordPress.org with their own security review history, which is consistent with not finding a quick
win on a first pass; the honest next step is following the two named leads (SCF's GEO/JSON-LD
output, and the SQLite translator's less-common branches) rather than re-sweeping what's already
been checked.
