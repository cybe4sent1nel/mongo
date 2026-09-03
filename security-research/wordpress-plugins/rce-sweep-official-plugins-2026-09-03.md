# RCE sweep — all six in-scope WordPress.org / official codebases (2026-09-03)

Systematic hunt for **remote code execution** across every codebase in the WordPress
HackerOne scope list, cloned at current HEAD. One RCE-class finding (Create Block Theme,
reported separately); **no unauthenticated or low-privilege RCE found**. This is the record of
every primitive checked and why it is not reachable, so the ground is not re-covered.

| codebase | version / HEAD |
|---|---|
| Create Block Theme | 2.10.1 @ `5524f19` |
| Secure Custom Fields | 6.9.5 |
| BuddyPress | 15.0.0-alpha @ `4af6c90` |
| bbPress | 2.7.0-alpha-2 |
| SQLite Database Integration | HEAD |
| Classic Editor | HEAD |

## 1. Direct execution primitives — none

`eval`, `create_function`, `assert`, `preg_replace` with `/e`, `proc_open`, `shell_exec`,
`passthru`, `popen`: **zero hits** across all six codebases (excluding tests/vendor).

## 2. Dynamic `include` / `require` — all allowlisted or literal

BuddyPress builds include paths from `bp_current_action()`, which is a **URL path segment** —
the classic LFI shape. Every one of them is gated by a strict allowlist:

```php
if ( in_array( bp_current_action(), array( 'create', 'join', 'leave-group' ), true ) ) {
    require_once $this->path . 'bp-groups/actions/' . bp_current_action() . '.php';
}
```

Checked and confirmed allowlisted (`in_array(..., true)` against fixed arrays) in:
`bp-groups` (×3), `bp-friends`, `bp-settings` (×2), `bp-activity`, `bp-messages` (×2),
`bp-members`. The activity component's `screens/` include uses `$filenames[ $slug ]` — the
**value** is a hardcoded filename and the lookup is `isset()`-gated, so the URL segment never
reaches the path. No traversal is possible.

Secure Custom Fields' `acf_include()` (`includes/acf-utility-functions.php:152`,
`include_once $file_path`) is called with **string literals** everywhere in production; the only
variable-argument callers are in `tests/`.

## 3. PHP object injection — blocked in every codebase

| codebase | site | why not reachable |
|---|---|---|
| Secure Custom Fields | `acf-helper-functions.php:607` | already `@unserialize( …, array( 'allowed_classes' => false ) )`. |
| BuddyPress | `bp_unserialize_profile_field()` + `xprofile_sanitize_data_value_before_save()` | no `allowed_classes` guard, **but** the value is `maybe_serialize()`d before the sanitizer, so an attacker's `O:…` string arrives as `s:49:"O:14:"…";` — unserializing that yields a **string**, never an object. Traced live (filter-chain instrumentation). A canary class with `__wakeup`/`__destruct` did **not** fire. The kses chain additionally slash-escapes quotes, mangling any `O:` payload. |
| bbPress | `admin/converters/*.php` (~20 sites) | forum-importer code; unserializes password hashes from an **operator-supplied external forum database**, admin-triggered. Not request-reachable. |
| SQLite Database Integration | `integrations/query-monitor/boot.php:137` | Query Monitor integration on an option value; not attacker-controlled. |

WordPress core's one clean POP gadget (`WP_HTML_Token::__destruct` → `call_user_func`) is
neutralized by its throwing `__wakeup` on PHP 8.4 — separately verified (see
`../wordpress-core/rce-surface-audit-2026-09-03/`).

## 4. Arbitrary-callable dispatch — none

The SQLite plugin registers PHP callables as SQL-callable UDFs via
`PDO::sqliteCreateFunction()` (`class-wp-sqlite-pdo-user-defined-functions.php`) — an RCE-shaped
surface. The map binds ~60 SQL names to **methods of that one class**, all implementing MySQL
semantics; none performs `call_user_func`, file I/O, includes, or `unserialize`. Its two
`preg_replace` calls use static patterns with dynamic subjects (no `/e`). No arbitrary PHP
function is exposed to SQL. No `ATTACH DATABASE`, `load_extension`, or `writefile` handling
exists, so the SQLite file-write→RCE technique has no entry point in the plugin itself.

## 5. File uploads — hardened WP path

BuddyPress avatar/cover uploads (any member can perform these — the classic low-privilege RCE
vector) go through `BP_Attachment::upload()` → `wp_handle_upload()` with
`$overrides['mimes']` set from `validate_mime_types()`, plus `wp_check_filetype_and_ext()`.
Filenames are sanitized by core. The raw `$_FILES['file']['name']` at
`bp-core-attachments.php:1590` is used only as a `do_action()` argument, never as a path.

## 6. The one RCE-class finding

**Create Block Theme** `strip_php_tags()` is bypassable by `<?`-recombination
(`<<??php` → `<?php`), reintroducing executable PHP into exported `patterns/*.php` which block
themes `require` at init. Verified end-to-end (`RCE uid=0`). It is gated by
`edit_themes` + `wp_is_file_mod_allowed()` and contained by kses for non-admin content, and it
does **not** bypass `DISALLOW_FILE_EDIT`/`DISALLOW_FILE_MODS` — so it defeats a deliberate
defense-in-depth control rather than crossing a privilege boundary. Full report:
`create-block-theme-strip-php-bypass-2026-09-03/`.

## Conclusion

Across the six officially-maintained codebases, the classic RCE primitives are either absent or
correctly gated: no dynamic execution functions, every URL-derived include allowlisted, object
injection structurally blocked, no arbitrary-callable dispatch, and uploads on the hardened core
path. **No unauthenticated or low-privilege RCE was found.** The only code-execution issue is an
admin-gated control bypass in Create Block Theme.
