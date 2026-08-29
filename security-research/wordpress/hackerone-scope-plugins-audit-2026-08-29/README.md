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
Repeater/Flexible Content Pro extras), and the WPML integration beyond the two `$wpdb->get_row()`
calls already confirmed parameterized.

**Update (Round 23):** the `src/AI/GEO/` JSON-LD lead above has since been checked and closed — see
below. It was a real, plausible vector in general, but the plugin's single output site already uses
`JSON_HEX_TAG`, which is the correct defense.

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

**Update (Round 22):** followed up on exactly that lead with a dedicated pass over the
string/identifier-quoting core specifically (still not the full 7942 lines — window
functions/`JSON_*`/date-arithmetic branches remain the next follow-up). Found two genuine
escaping-consistency bugs in the exact class hunted for — both already fixed by the maintainer in
the past several weeks and confirmed present in the current `v3.0.1` release, so not live: (1)
`_real_escape()` used `addslashes()` instead of MySQL-compatible escaping, which under
`NO_BACKSLASH_ESCAPES` SQL mode would have let an escaped quote be mis-parsed as a real string
terminator (classic escape-bypass injection shape) — fixed by rejecting that SQL mode outright and
centralizing escaping in the driver's own connection; (2) quoted identifiers were unescaped using
string-literal backslash rules instead of MySQL's actual "identifiers never treat backslash as an
escape" rule — fixed as part of the same hardening pass that added `ANSI_QUOTES` support. See
`round22-sqlite-integration-mysql-translator-deep-dive.md` for the full trace of both, including why
each was a real bug and why no bypass remains in either fix.

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

## Round 19: candidate second finding — SCF nav-menu arbitrary-object ACF meta write (Medium)

Read SCF's own recent security-hardening commit (`64a2287`, "Hardening and code-quality
improvements across fields, REST, and abilities") for the same reason round 15/16 read
`wordpress-develop`'s recent commits: a maintainer who just fixed several instances of one bug
class is the strongest signal for where an unfixed sibling of that same class still lives. That
commit added a capability + nonce check to `WC_Order.php`'s WooCommerce-order ACF save path;
`includes/forms/form-nav-menu.php`'s `update_nav_menu_items()` has a structurally similar,
**unfixed** version of the same bug: it iterates attacker-controlled keys of
`$_POST['menu-item-acf']` and passes each straight to `acf_save_post()` with no per-target
authorization check, gated only by a `'nav_menu'`-scoped nonce that has nothing to do with the
object actually being written.

Dynamically confirmed by firing the real `wp_update_nav_menu` hook with a realistic `'nav_menu'`
nonce plus a smuggled `menu-item-acf` entry: successfully wrote an ACF field value onto **a
different user's profile** and, separately, onto **an arbitrary post**, neither related to the nav
menu being saved. A negative control confirmed the legitimate save path for that same user field
(`form-user.php`, `acf_verify_nonce('user')`) correctly rejects the `'nav_menu'` nonce used in the
attack — proving the gap is specific to `update_nav_menu_items()`, not "any nonce works everywhere."
Per the code, the identical mechanism also reaches the `'woo_order_<id>'` pseudo-ID `WC_Order.php`
just added its own dedicated guard for — a concrete bypass of a fix the vendor made deliberately,
though not independently re-verified dynamically since WooCommerce isn't installed on this
throwaway install.

Rated **Medium**: real, reproducible Missing Authorization (CWE-862) with an arbitrary-write
primitive (not just a read/existence leak like round 18), reachable by anyone holding
`edit_theme_options` — Administrator-only by default, but a capability commonly delegated to
non-Administrator "menu manager" roles in real deployments, for whom this is a genuine privilege
escalation. Full detail, reasoning, and PoC in
`round19-CONFIRMED-scf-navmenu-arbitrary-object-acf-meta-write.md`.

**Severity ceiling checked explicitly, not assumed**: verified this cannot be argued to High
(`AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N` ≈ 4.9) by attacking the three things that would actually move
the CVSS score — not the `woo_order_<id>` reachability or "admin-only by default" framing, which
don't move the arithmetic either way. Traced every real WordPress Core caller of the
`wp_update_nav_menu` action (classic `nav-menus.php`, the REST `WP_REST_Menus_Controller`, and the
Customizer's `WP_Customize_Nav_Menu_Setting`); all three independently require `edit_theme_options`
— the `nav_menu` taxonomy hardcodes it at registration (`wp-includes/taxonomy.php:124-129`) and the
Customizer's `'customize'` meta capability maps to it unconditionally
(`wp-includes/capabilities.php:698-700`) — so `PR` cannot drop below High through any Core path.
No companion confidentiality-read primitive exists in this code path (write-only sink, no data
returned to the requester), and no security-boundary/scope change occurs. Reporting the Medium
rating as the ceiling actually demonstrated, not a starting point to argue up from.

## Round 20 — sibling hunt off disclosed HackerOne #3931777, honest negative result

**File:** `round20-hackerone-3931777-sibling-hunt-negative.md`

Prompted by the public disclosure of #3931777 (arbitrary file deletion via `POST /wp/v2/media/<id>/finalize`
poisoning `_wp_attachment_metadata`, fixed for WordPress 7.1). Used that report's exact bug shape — a
path-confinement check whose boundary is derived from the same attacker-controlled value it's meant to
constrain — as a search pattern against freshly-pulled `WordPress/wordpress-develop` and
`WordPress/gutenberg` trunk, plus every file-deletion call site in all four in-scope plugins.

Found that `wp_delete_attachment_files()`'s vulnerable `$backup_sizes` branch is **unchanged** on trunk —
WordPress fixed this by closing the only entry point (`finalize_item()` now validates every submitted
filename against a provenance allowlist of names the server itself actually produced) rather than
hardening the sink itself, which is worth flagging as a standing hardening recommendation but is not a
live bug: traced every other write-site of the two vulnerable meta keys in current core (XML-RPC,
Customizer, custom-header/background, site-icon) and confirmed each regenerates metadata from a real,
server-controlled file rather than accepting a client string. Checked every `unlink()`/`wp_delete_file()`
call in all four in-scope plugins individually, tracing each target path back to its data source rather
than pattern-matching superficially — Classic Editor and SQLite Database Integration have no
file-deletion code at all; Create Block Theme's candidates all either delete WordPress's own temp files,
a hardcoded-literal screenshot filename, or apply `basename()` before concatenation (which structurally
prevents escaping the target directory regardless of input, unlike the disclosed bug's broken
after-the-fact containment check); Secure Custom Fields's file-deletion path already uses the *correct*
pattern (an independently-built directory allowlist, not a boundary derived from the file being deleted)
and is explicitly versioned as a prior hardening pass (`@since SCF 6.9.3`). No fresh, currently-
exploitable sibling found — reported as a genuine negative result after a wide search, not narrowed to
look for confirmation.

## Round 21 — adversarial re-read of the #3931777 fix itself, plus a wider sweep of every other
## media-editing code path — one genuine logic quirk found and fully traced, still no reportable finding

**File:** `round21-finalize-item-basename-collapse-and-wider-sweep-negative.md`

Directed to dig deeper and widen scope rather than re-check Round 20's ground. This round assumed the
fix itself might have a gap and adversarially re-read `validate_sub_size_provenance()`/
`get_sideloaded_file_names()`: confirmed the strict `in_array(..., true)` allowlist check cannot be
bypassed with a `../`-laden string, since every allowlist entry is itself a value WordPress already
generated. Found one genuine, previously-undocumented quirk in the process: `finalize_item()`'s
`'original'`/`'scaled'` branch can legitimately set the top-level `_wp_attachment_metadata['file']` to a
bare basename (no subdirectory) because the allowlist includes basename-only forms — traced this all the
way through `wp_delete_attachment_files()`'s fragile `backup_sizes` branch and confirmed it only ever
*widens* the confinement directory to the uploads base folder (never escapes it), and that the only other
input to that branch (`_wp_attachment_backup_sizes`) is never written by `finalize_item()` at all — it
remains independently safe per Round 20. Also read end-to-end (not just grepped) three areas Round 20
didn't individually walk through: the REST-native `edit_media_item()` crop/rotate/flip endpoint (safe —
always writes brand-new, server-named files), all three `wp-admin/includes/image-edit.php` AJAX functions
(`wp_save_image()`, `wp_restore_image()`, `stream_preview_image()` — all safe, confirmed no request field
reaches a `_wp_attachment_backup_sizes` file value), and Create Block Theme's font/media/zip
download-and-write pipeline (already comprehensively hardened by a single upstream commit covering all
three files together, and gated behind `edit_theme_options`/`edit_themes` throughout, which WordPress's
own model already treats as code-execution-equivalent trust). No fresh Medium+ finding — reported
honestly, with the one real quirk documented for the record rather than omitted or oversold.

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

## Round 25 — sibling hunt off disclosed HackerOne #3931771 (stored XSS via unescaped sub-size
## filename), the second half of the pair started in Round 20

**File:** `round25-hackerone-3931771-xss-sibling-hunt-negative.md`

The discloser of #3931771 explicitly asked that it be read together with #3931777 (Round 20's
subject): same unsanitized `finalize_item()` write, two different sinks. Confirmed the write-side
fix (`validate_sub_size_provenance()`, r63200, the exact same commit Round 20 already traced) also
closes this chain — the reported payload can no longer pass the provenance allowlist. Separately
confirmed, by direct code reading, that the *output*-side defect the discloser flagged as
independently pre-existing and needing its own fix (`wp-admin/includes/media.php`'s `get_media_item()`
and `edit_form_image_editor()` both interpolate a sub-size URL into a quoted HTML attribute with
zero escaping — `esc_url()` is missing from all three call sites) is still literally present,
unpatched, in current trunk. It isn't live today only because no other write path into that value
survives: re-verified every other core write site regenerates filenames through
`sanitize_file_name()` (confirmed its strip list includes `'`, `"`, `<`, `>`), and none of the four
in-scope plugins touch `_wp_attachment_metadata` with anything but a server-regenerated path. A real,
named hardening gap for the record — the first place to check if any future core feature or plugin
ever reopens a raw write to these fields — but not a live, reportable finding today.
