# RCE sweep: WordPress 7.1.0 core + Jetpack (first-party plugin monorepo)

Prompted by a claim ("there's an RCE bug in the latest WordPress release, whoever finds it wins")
that I have not been able to corroborate from any source — treating it the same way this
engagement has treated every other unverified claim: worth chasing, not worth repeating as fact.
Scope: WordPress core 7.1.0 (already cloned this session), plus Automattic's first-party plugins.

**Status: no fresh RCE found in either codebase after a genuine pass through the highest-value bug
classes (PHP object injection, eval-class code execution, OS command injection, file-upload-to-PHP-
execution). One real but practically-unreachable defense-in-depth gap in vendored code. Full
first-party-plugin coverage was not achieved — Jetpack alone is a 17-plugin monorepo and Akismet
could not be cloned in this sandbox (see Limits).**

## WordPress core 7.1.0

### PHP Object Injection (`unserialize()` on client-influenceable data) — checked exhaustively, closed

Found and checked every live `unserialize()` call site in `src/` (excluding vendored libraries'
dead/unreachable code):

- `class-wp-rest-widgets-controller.php:589`, `class-wp-rest-widget-types-controller.php:498`,
  `blocks/legacy-widget.php:44`, `class-wp-customize-widgets.php:1496` — all four are the
  "Legacy Widget" block's encoded-instance deserialization. Every one is gated by
  `hash_equals( wp_hash( $decoded_bytes ), $client_supplied_hash )` *before* `unserialize()` runs.
  `wp_hash()` is keyed off the site's own `AUTH_KEY` salt, which never reaches the client — so an
  attacker cannot forge a hash for arbitrary serialized bytes without the salt. Checked all four
  individually rather than assuming they share the pattern (this engagement's PowerShell audit
  found real value in not assuming consistency across sibling code paths).
- `wp-includes/rss.php`'s `RSSCache::unserialize()` (legacy Magpie RSS) — grepped, confirmed it is
  never instantiated or called from anywhere else in `src/`. Dead code.

### `eval()` / `create_function()` / string-`assert()` — none live

Zero hits in `src/` outside vendored test-only `assert()` calls (SimplePie, Text_Diff use PHP 8's
boolean-assertion form for internal invariants, not the deprecated string-eval form). One `eval()`
reference in `class-pclzip.php` is inside a comment, not live code.

### OS command injection (`exec`/`shell_exec`/`system`/`passthru`/`popen`) — one real gap, not practically reachable

`wp-includes/ID3/getid3.php`'s Windows-only `vorbiscomment.exe` invocation builds its command line
by wrapping the analyzed file's path in raw double quotes with **no `escapeshellarg()`** — the
Unix branch two lines below does use it correctly, which is what made this worth a second look
(an inconsistency between two branches of the same function is exactly the shape of bug this
session has found real issues in before). Classic Windows command-injection shape in isolation.
Not practically exploitable via any WordPress-reachable path, for two independent reasons:

1. WordPress ships no `wp-includes/ID3/helperapps/vorbiscomment.exe` — confirmed via `find`. The
   `file_exists()` guard around this branch short-circuits on essentially every real install; it
   only activates if a server admin has manually installed this specific, long-obsolete Windows
   helper binary.
2. Even then, the file path getID3 sees (`$this->info['filenamepath']`) is the already-uploaded
   attachment path, which has already been through WordPress's own `sanitize_file_name()` —
   confirmed that function strips `"` from filenames, which is what this injection needs.

Worth a one-line upstream `escapeshellarg()` fix for defense-in-depth (getID3 is a separate
upstream project vendored into `wp-includes/ID3/`), but not a live vulnerability given both
blockers. Not filing this as a finding — flagging the reasoning here so it isn't re-walked.

### File-upload-to-PHP-execution — not touched by this pass

Read `wp_check_filetype_and_ext()` (the core mime-sniffing/extension-cross-check gate) in full.
It's the same heavily-scrutinized logic that's been stable for years — extension-vs-`finfo`
mismatch handling, HEIC/HEIF special-casing, `nonspecific_types` leeway list. Didn't find an
obvious bypass on read, but this needs adversarial testing (crafted polyglot files, extension
edge cases) rather than a source read to actually clear or break — flagging as not disproven
rather than as checked-clean.

## Jetpack (Automattic's flagship first-party plugin — `projects/plugins/jetpack`, v16.2)

The `Automattic/jetpack` repo is a monorepo containing 17 first-party plugins (`backup`, `boost`,
`protect`, `search`, `social`, `videopress`, `vaultpress`, a CRM-adjacent set, etc.) plus shared
packages. This pass covered the `jetpack` plugin itself only — the others are unaudited (see
Limits).

### `unserialize()` sweep — no attacker-reachable instance found

- `json-endpoints/class.jetpack-json-api-themes-install-endpoint.php:170` — deserializes the
  **response body of a `wp_remote_post()` to a hardcoded URL**
  (`https://api.wordpress.org/themes/info/1.0/`, the legacy PHP-serialization theme-info API; the
  code's own comment flags migrating to the JSON 1.1 API as a `@todo`). This is real PHP Object
  Injection *shape*, but the deserialized bytes come from a fixed, first-party HTTPS endpoint, not
  from request input — reaching it requires already controlling wordpress.org's API or breaking
  TLS, neither of which is a WordPress-site-level attack. Also gated behind `install_themes`
  (admin-level). Not attacker-reachable as a WordPress vulnerability; flagged only because the
  code's own `@todo` shows the team is already aware this legacy pattern is fragile.
- `class.json-api.php:484`, `sal/class.json-api-links.php:418` — deserialize the plugin's own
  internally-built endpoint-registry array (`$endpoint_path_versions` is a key the plugin
  constructed itself when registering its own REST routes, not request data). Not attacker input.
- `modules/videopress/class.videopress-player.php:136` — deserializes a value the same code path
  just wrote via `wp_cache_set()`/`serialize()` a few lines above. Round-trips the plugin's own
  data through the object cache; not attacker-reachable unless the object cache backend itself is
  independently compromised (a different, unrelated threat model).

### `eval()` / `create_function()` — none in production code

All matches are in `tests/php/`, using `eval()` to define minimal stub functions/classes for test
isolation. Zero in shipped plugin code.

### Media upload API (`json-endpoints/class.wpcom-json-api-upload-media-endpoint.php`)

Jetpack's own `/sites/%s/media/new` JSON API endpoint (used by wordpress.com/mobile-app clients
against a Jetpack-connected self-hosted site) — checked because a plugin reimplementing upload
handling instead of delegating to core is exactly where a validation gap tends to hide. It doesn't
reimplement anything: it populates `$_FILES` and calls core's own `media_handle_upload()`, which
runs through `wp_handle_upload()` → `wp_check_filetype_and_ext()`, the same gate core's own upload
paths use. Gated on `current_user_can( 'upload_files' )`. No custom, weaker validation found.

## Honest limits — what this pass did not cover

- **Akismet could not be cloned in this sandbox** (`git clone` to `Automattic/akismet` failed with
  "could not read Username for 'https://github.com': terminal prompts disabled" on every retry,
  while the much larger `Automattic/jetpack` clone succeeded moments earlier and later WordPress/
  Gutenberg clones this session worked fine — looks like a transient or repo-specific sandbox
  network quirk, not a real access restriction). Not audited at all this round.
- **16 of Jetpack's 17 first-party plugins were not touched**: `backup`/`vaultpress` (restore-from-
  backup logic is a classically dangerous surface — arbitrary file write during a restore
  operation is exactly RCE-shaped), `search`, `protect`, `social`, `boost`, the CRM-adjacent
  plugins, `wpcomsh`, and the shared `packages/` directory (notably `packages/sync`, which
  deserializes data between a site and WordPress.com over the connection — the single most
  promising unaudited surface given this session's PHP-object-injection focus, and
  `packages/waf`, both only grepped in passing for `$_FILES`, never read).
- **`wp_check_filetype_and_ext()` was read but not adversarially tested** — a source read can miss
  a bypass that only shows up against a crafted file; this needs an actual polyglot/edge-case test
  pass, not just a code read, before it can be called clear.
- No live install, no build, no execution of any binary this round — source-level analysis only,
  consistent with this engagement's standing constraints.

## Where I'd point continued effort, in priority order

1. `packages/sync` in the Jetpack monorepo — the module whose entire job is deserializing data
   between two ends of a connection is the single highest-value unaudited surface here.
2. `backup`/`vaultpress` restore logic — file-write-from-backup-archive is structurally the same
   bug shape as the WordPress core CAB/zip-extraction path traversal already covered earlier in
   this engagement's WordPress work, in a codebase that hasn't had that specific lens applied yet.
3. A real adversarial pass against `wp_check_filetype_and_ext()` rather than a read-through.
4. Retry the Akismet clone (smaller, more tractable scope) once the sandbox network issue is
   understood, or ask for it to be provided directly.
