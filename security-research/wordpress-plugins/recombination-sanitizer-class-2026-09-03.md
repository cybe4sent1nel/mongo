# Defect class sweep: single-pass removal sanitizers (recombination bypass)

Generalising the Create Block Theme finding into a class and hunting every instance across
WordPress core and all six in-scope plugin codebases.

## The class

A sanitizer that removes a dangerous substring with **one non-recursive pass**
(`preg_replace`/`str_replace` with an empty replacement) can be defeated by *nesting*: deleting an
inner occurrence joins the surrounding bytes into a fresh occurrence, which is never re-scanned.

```
<<??php                        →  <?php                        (CBT)
<scri<script>x</script>pt>...  →  <script>alert(1)</script>    (BuddyPress)
```

## Instances found

### 1. Create Block Theme — `strip_php_tags()` — **exploitable, reported**

`preg_replace('/<\?/', '', $content)` guarding PHP injection into exported `patterns/*.php`.
Attacker-controlled input (a synced pattern authored by an **Editor**), reachable, proven to
`RCE uid=0`. Full report: `create-block-theme-strip-php-bypass-2026-09-03/`.

### 2. BuddyPress — `bp_strip_script_and_style_tags()` — **latent, hardening**

`bp-core/bp-core-functions.php:4841`:

```php
function bp_strip_script_and_style_tags( $string ) {
    return preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $string );
}
```

Demonstrated bypass — the function *reconstructs* the tag it claims to remove:

```
in : <scri<script>x</script>pt>alert(1)</scri<script>y</script>pt>
out: <script>alert(1)</script>
```

**Not currently exploitable in BuddyPress itself.** Its only caller is
`bp_nouveau_messages_catch_hook_content()`
(`bp-templates/bp-nouveau/includes/messages/functions.php:534`), which passes buffered output of
*other plugins'* action hooks (`ob_get_contents()`), not user input. So this is a hardening issue,
not a vulnerability — I am not claiming otherwise.

It is still worth fixing, because it is **public API with a name that invites use on untrusted
input**: any theme or plugin calling `bp_strip_script_and_style_tags()` on user content gets a
sanitizer that does not do what its name says. Fix by looping to a fixed point:

```php
do {
    $prev   = $string;
    $string = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $string );
} while ( $string !== $prev );
```

## Instances checked and cleared

| site | why it is safe |
|---|---|
| `wp-includes/formatting.php:5628` (`wp_strip_all_tags`) | same regex, but immediately followed by `strip_tags()`, which removes any reconstructed tag. |
| `wp-includes/class-wp-xmlrpc-server.php:7102` | same regex on a fetched remote page for pingback excerpt generation; the result is subsequently kses-filtered as comment content. |
| `wp-includes/PHPMailer/PHPMailer.php:4852` | followed by `strip_tags()`. |
| `wp-includes/ms-files.php:33` — `str_replace( '..', '', $_GET['file'] )` | checked the arithmetic: a dots-only run is consumed left-to-right in non-overlapping pairs, leaving at most one dot, so `..` cannot re-form. (`....` → ``, `...` → `.`, `x....` → `x`.) Ugly but not bypassable this way. |
| CBT `strip_php_tags()` second pass (`<script language="php">`) | recombination did not reconstruct the opening tag in testing, and the legacy `<script language=php>` parser is gone in PHP 7+. |
| CBT header escaping `str_replace( '*/', '*&#47;', $title )` | cannot re-form `*/`: the replacement's `*` is always followed by `&`, so no join produces `*` + `/`. Verified against `**//`, `*/*/`, `**/`. |
| bbPress converter `preg_replace` calls | admin-triggered forum-import code, operator-supplied external DB. |

## Conclusion

Across core and all six in-scope plugins, the class has exactly **two** instances. One
(Create Block Theme) is attacker-reachable and yields Editor → RCE. The other (BuddyPress) is a
genuine bypass of a public helper but is not fed attacker-controlled input by first-party code,
so it is reported as hardening only.
