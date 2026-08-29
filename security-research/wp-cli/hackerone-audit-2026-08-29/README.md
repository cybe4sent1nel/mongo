# WP-CLI security audit — 2026-08-29

## Scope

Per the WP-CLI HackerOne program: all code under the `wp-cli` GitHub organization. Primary targets are
the main `wp-cli/wp-cli` repository and the command repositories bundled into the distributed WP-CLI
Phar/installation (per `wp-cli/wp-cli-bundle`'s `composer.json`): `ability-command`, `ai-command`,
`block-command`, `cache-command`, `checksum-command`, `config-command`, `core-command`, `cron-command`,
`db-command`, `embed-command`, `entity-command`, `eval-command`, `export-command`, `extension-command`,
`i18n-command`, `import-command`, `language-command`, `maintenance-mode-command`, `media-command`,
`rewrite-command`, `role-command`, `scaffold-command`, `search-replace-command`, `server-command`,
`shell-command`, `site-health-command`, `super-admin-command`, `widget-command`, plus `package-command`
(dev-required, bundled into Phar builds). Other `wp-cli/*` repositories are in scope but lower priority
per the program's own framing.

Cloned (full history fetched for `wp-cli/wp-cli` specifically, to review recent security-relevant commit
history; shallow clones for the rest): `wp-cli/wp-cli`, `wp-cli/wp-cli-bundle`, `wp-cli/db-command`,
`wp-cli/search-replace-command`, `wp-cli/core-command`, `wp-cli/extension-command`,
`wp-cli/package-command`, `wp-cli/config-command`, `wp-cli/scaffold-command`, `wp-cli/checksum-command`,
`wp-cli/i18n-command`, `wp-cli/import-command`, `wp-cli/media-command`, `wp-cli/eval-command`,
`wp-cli/entity-command`, `wp-cli/language-command`.

## Method

Hunting RCE / SQLi / auth-bypass / IDOR only, Medium-severity floor (per standing instruction carried
over from the WordPress plugin audit in this same repo) — DoS/crash bugs are out of scope regardless of
novelty. Combined static review with the technique that's paid off repeatedly in the WordPress-plugin
side of this audit: read the target's own recent git history for security-shaped commits first, since a
maintainer who just hardened one instance of a bug class is the strongest available signal for finding an
unpatched sibling of the same class elsewhere in the codebase. `wp-cli/wp-cli`'s `Runner.php` turned out
to have exactly that shape (a string of 2026 commits, several explicitly AI-co-authored, hardening SSH
command construction against argument injection) — reviewed in full below. Where a candidate bug was
found, verified empirically with real PHP/Mustache/tar/ZipArchive/bash execution rather than asserted
from source reading alone, matching the standard set on the WordPress side of this audit.

## Scope correction #1 — WP-CLI's own trust model: CLI arguments are not a privilege boundary

WP-CLI's published security-reporting guidance states its threat model explicitly: running `wp` at all
requires the ability to already execute code as that local user, so a report needs to show someone
*outside* that trust boundary gaining something they couldn't otherwise get — "a remote attacker can
convince a WP-CLI user to run a malicious command" is explicitly called out as social engineering, not a
WP-CLI vulnerability. This directly affects how Round 1 below should be read — see the correction banner
at the top of that file. Going forward, a candidate finding only counts as reportable here if the
malicious value can be shown crossing that trust boundary through WP-CLI's *own* supported mechanism
(e.g. a value read back from already-stored WordPress content by an already-running, already-privileged
automated/cron invocation), not via a hypothesized external wrapper that itself failed to sanitize input
before invoking a trusted local tool.

## Round 1 — technically CONFIRMED, likely N/A under the trust model above: `Utils\mustache_render()` disables all escaping, systemically

**File:** `round1-CONFIRMED-mustache-render-template-injection-rce.md` (see correction banner at its top)

`WP_CLI\Utils\mustache_render()` (`php/utils.php`) configures its Mustache engine with an `escape`
callback that is a pure identity function — no HTML escaping, no context-aware escaping, nothing. This
has been true since 2013 (`b877a4bb`) and is unchanged on current `main`. Every command that generates a
file from a `.mustache` template through this shared helper inherits zero output encoding. Concretely
confirmed with real end-to-end PHP execution (not just a source-level claim) in two independent
commands, via two different injection shapes:

1. **`wp config create --dbname=<payload>`**: a single-quote in the `--dbname` value breaks out of the
   `define( 'DB_NAME', '{{dbname}}' );` PHP string literal in the generated `wp-config.php`, injecting an
   arbitrary top-level PHP statement that runs on every subsequent WordPress page load (`wp-config.php`
   is `require_once`'d on every boot). Demonstrated writing a working webshell to disk and using it to
   execute arbitrary OS commands as root in this session's sandbox.
2. **`wp scaffold plugin <slug> --plugin_name=<payload>`**: `*/` in the `--plugin_name` value closes the
   generated plugin file's `/** ... */` doc-comment early; the payload's own trailing `/*` reopens a
   comment to swallow the rest of the header harmlessly, leaving a real, executable PHP statement in
   between. Demonstrated the same webshell-write-and-execute chain.

A third call site (`wp scaffold post-type`, same quote-breakout shape as (1)) was confirmed by static
read of the template and the command's argument handling but not independently re-run through the
engine, since the underlying mechanism was already proven twice with real execution.

**Honest reachability note** (full reasoning in the round file): none of `--dbname`/`--plugin_name`/etc.
are documented as code-execution vectors — they're plain descriptive-string parameters, which is exactly
what makes this a real vulnerability rather than a `wp eval`-shaped non-issue. The realistic high-value
threat model is automated WordPress-provisioning tooling (hosting panels, WP-as-a-Service backends,
CI/CD scaffolding) that passes a less-trusted, customer-originated string (a chosen site name, a chosen
plugin title) straight through to these WP-CLI flags, trusting them to be inert text — a completely
reasonable assumption given how they're documented, and now shown not to hold. This audit doesn't have
visibility into any one specific such wrapper and isn't claiming one; what's concretely and non-
speculatively demonstrated is that the WP-CLI-side primitive itself grants unrestricted OS command
execution the moment an untrusted string reaches one of these parameters, with no other precondition.

## Areas reviewed and found sound (no bypass/vulnerability found — reported honestly, not omitted)

- **`Runner.php` SSH/Docker/Vagrant remote-command construction** (`--ssh=`, aliases, `ssh-args`,
  `proxyjump`, `key`, `ssh_config`, `path`, `host`, `user`): the maintainers have been actively hardening
  this exact area through 2026 (commits `39ce97b3` "Prevent leading hyphens in SSH connection
  parameters", `847a2c1e` "Anchor SSH argument safe-set check with \A..\z to reject trailing newlines",
  both AI-co-authored). Re-audited `validate_ssh_bits()` and `generate_ssh_command()` in full looking for
  an unpatched sibling gap. Found that `path` (used via `--workdir` for Docker schemes, or a local `cd`
  for SSH/Vagrant) is *not* included in the leading-hyphen validation the other fields received —
  checked whether this is exploitable rather than assuming either way: empirically tested
  `docker exec --workdir -x ...` (docker's own CLI flag parser consumes the next token as the flag's
  value regardless of a leading hyphen — confirmed via `docker exec --workdir --privileged
  <container> ...` reaching the identical "no daemon" error as a normal path, meaning flag-parsing
  already succeeded) and `bash -c "cd '-oProxyCommand=...'"` (bash's `cd` builtin rejects any unrecognized
  leading-hyphen argument with "invalid option", and its narrow recognized set `-L/-P/-e/-@/--` is
  behaviorally inert). Both closed by empirical test, not by assumption — `path` being excluded from that
  specific validation does not appear to be an exploitable gap.
- **`extract_subdir_path()` / `safe_parse_path()`**: a `eval()` call here was replaced (`1c064352`,
  Copilot-authored) with a hand-written recursive-descent parser supporting only quoted-string literals,
  `dirname()` calls, and `.` concatenation, explicitly rejecting anything else (including unescaped `$`
  in double-quoted strings). Read the full parser; found it a sound, minimal, non-Turing-complete grammar
  with no code-execution surface — the replacement is correct.
- **`search-replace-command`'s `SearchReplacer`**: `unserialize()` is called with
  `['allowed_classes' => ['stdClass']]` (filterable, but safe by default), blocking arbitrary
  class-instantiation PHP Object Injection; re-serialization is a full `serialize()` of the reconstructed
  structure (not a naive length-preserving string patch), so it doesn't reintroduce the classic
  "search-replace corrupts serialized string lengths" data-corruption bug either.
- **`WP_CLI\Extractor` (zip/tar extraction shared by `core-command`/`extension-command`/
  `scaffold-command` downloads)**: empirically tested all three extraction backends it uses
  (`ZipArchive::extractTo()`, the `tar` CLI, `PharData::extractTo()`) against both classic zip-slip
  (`../`-laden entry names) and symlink-based zip-slip variants, using real crafted archives — all three
  backends correctly confine extraction to the destination directory on this PHP 8.4/GNU tar 1.35
  environment, and neither `ZipArchive` nor `PharData` preserves symlink entries as real on-disk symlinks
  (both flatten them to inert regular files), closing the symlink-escape variant too. The fallback chain
  (`tar` CLI → `PharData` on failure) doesn't reopen the gap either, since `PharData` was independently
  confirmed safe.
- **`Utils\esc_cmd()` / `assoc_args_to_str()` / `escapeshellarg_preserve_tilde()`**: standard, correctly
  applied `escapeshellarg()`-based patterns; the tilde-preservation helper only ever leaves a fixed
  2-character, metacharacter-free `~/` prefix unescaped, fully escaping everything after it.
- **`config-command`'s `print_dotenv()`** (`wp config get --format=dotenv`): does have a real but
  low-value escaping bug (`str_replace("'", "\'", $value)` without first escaping pre-existing
  backslashes — the classic "escape the quote but not the escape character" mistake), but it only
  reformats a value already sitting in the *site owner's own, already-trusted* `wp-config.php` for
  display on `STDOUT`; there's no attacker-controlled input reaching it and no file this audit found that
  re-parses that stdout output as executable config. Noted for completeness, not pursued as a finding —
  doesn't meet the reachability bar the confirmed Round 1 findings do.

## Scope note

Everything in this directory targets the actual named program scope (`wp-cli/wp-cli` plus bundled
command repos) directly — no out-of-scope-plugin detour this time.
