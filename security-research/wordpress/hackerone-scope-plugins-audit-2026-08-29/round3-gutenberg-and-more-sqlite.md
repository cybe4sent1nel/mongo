# Round 3: Gutenberg block-library sweep, WP Core Font Library, more SQLite translator edge cases

Worked two fronts in parallel this round per direction: the SQLite translator's remaining
functions, and Gutenberg proper (both named as open leads at the end of round 2). Widened the
target class to include privilege escalation, not just SQLi/RCE/stored XSS. Still no exploitable
bug confirmed — this round covers new ground (Gutenberg block-library, and WP Core's Font Library
feature, not touched in rounds 1–2) rather than re-checking what's already ruled out.

## Gutenberg block-library: systematic sweep for unescaped attribute-to-HTML paths

Grepped all 92 block-library `index.php` render files for `$attributes[...]` values reaching HTML
output, then individually traced every candidate that looked unescaped at first read:

- **`search`**: several `sprintf('color: %s;', $attributes['style']['color']['text'])`-style calls
  build style fragments with no `esc_attr()` at their own call site — but the *combined* style
  string always passes through `safecss_filter_attr()` + `esc_attr()` right before output
  (`get_styles_for_block_core_search()`'s return array). Not exploitable.
- **`post-terms`**: `$attributes['prefix']`/`['suffix']` are concatenated straight into
  `<span>...</span>` with no escaping at the concatenation site — but the assembled string is
  passed through `wp_kses_post()` immediately after, before being handed to `get_the_term_list()`.
  Not exploitable.
- **`post-navigation-link`**: `$attributes['arrow']` concatenated into a `class="..."` value with
  no `esc_attr()` — but it's gated by `isset( $arrow_map[ $attributes['arrow'] ] )` first, an
  allowlist of exactly two hardcoded-safe strings (`'arrow'`, `'chevron'`); the code has an
  explicit comment explaining this is intentional ("Only use hardcoded values here, otherwise we
  need to add escaping"). Not exploitable.
- **`avatar`**: `$author_name` (the one non-obviously-safe piece of data, a user's display name)
  is wrapped in `esc_attr()` inline. Not exploitable.
- **`comment-reply-link`, `term-name`, and every other `'has-text-align-' . $attributes['textAlign']`-
  shaped class-string build across the library**: traced these all to a single point of truth —
  `get_block_wrapper_attributes()` (`wp-includes/class-wp-block-supports.php`) — which
  unconditionally `esc_attr()`s every attribute value (`class`, `style`, `id`, `aria-label`, and
  any extra attribute) before returning the HTML attribute string. Since nearly every block routes
  its wrapper class/style through this one function, the entire class of "unescaped-looking string
  concatenation into `$classes`/`$styles` arrays" that shows up dozens of times across the
  block-library is closed by this one central chokepoint, not by each call site individually.

No stored-XSS bypass found in the block-library render layer. The pattern throughout is
consistent: individual concatenation sites look unescaped in isolation, but every one checked
funnels through a shared sanitization point (`get_block_wrapper_attributes()`, `wp_kses_post()`,
or `safecss_filter_attr()`) before reaching output.

## WP Core Font Library (6.5+, not previously examined) — new territory, held up

Font Library (`wp-includes/fonts/`, `wp-includes/rest-api/endpoints/class-wp-rest-font-*.php`) is
newer core code with a file-upload surface — exactly the shape worth checking fresh for RCE
(upload-a-webshell-as-a-font-file) or privesc (write access without the intended capability):

- **Upload path**: `WP_REST_Font_Faces_Controller::handle_font_file_upload()` uses core's
  `wp_handle_upload()` with `mimes` overridden to `WP_Font_Utils::get_allowed_font_mime_types()`.
  `wp_handle_upload()` performs real MIME sniffing via `wp_check_filetype_and_ext()` (extension
  *and* file-content check, not just a client-supplied `Content-Type` header) — the same hardened
  path every other core media upload uses, not a custom/weaker one.
- **Non-file `src` values**: a font face's `src` can also be a plain URL string instead of an
  uploaded file (`create_item()`'s `isset( $file_params[ $src ] )` branch). Checked what stops
  this from being an arbitrary/local-file-path injection:
  `validate_create_font_face_settings()` requires `wp_http_validate_url( $src )` to pass — core's
  URL validator, which rejects anything without a valid `http(s)` scheme and host. Not a path
  traversal or `file://` vector.
- **Font Collections' remote JSON fetch** (`WP_Font_Collection::load_from_url()`) — the one place
  in this feature that does a server-side HTTP fetch from a URL — uses `wp_safe_remote_get()`
  specifically (the SSRF-hardened variant that blocks loopback/private-range targets by default),
  not plain `wp_remote_get()`. It also only fetches a JSON *manifest*, not font binaries, and
  collection URLs are registered via a PHP-only API (`wp_register_font_collection()`), not exposed
  as free-form REST input from an arbitrary requester.
- **Capability mapping**: both `wp_font_family` and `wp_font_face` post types register every
  relevant capability (`create_posts`, `edit_posts`, `edit_others_posts`, `delete_posts`, etc.)
  mapped to `edit_theme_options` — consistently admin-level, no capability lower than intended
  slipping through for create/edit/delete.

No RCE, SSRF, or privesc bypass found in this feature.

## SQLite Database Integration: two more targeted translator tests

- **`INSERT ... ON DUPLICATE KEY UPDATE` with a quote-laden update expression**
  (`... ON DUPLICATE KEY UPDATE data = CONCAT(data, 'in''jected')`): translated to SQLite's
  `ON CONFLICT DO UPDATE SET \`data\` = CAST((\`data\` || 'in''jected') AS TEXT)` — the doubled
  quote in the literal round-trips correctly, no escape-context mismatch.
- **`JSON_EXTRACT`/`JSON_SET` with adversarial path/value strings** (an unescaped quote in a JSON
  path expression; a value shaped like a SQL-injection payload passed as a JSON string value):
  both failed safely with `malformed JSON` exceptions rather than being misinterpreted as SQL or
  executed — SQLite's own JSON functions do their own strict JSON parsing independent of the
  translator's string-quoting layer, so a malformed-looking JSON payload just errors out before it
  can matter.

## Honest summary

This was the widest single-round sweep yet — the first time Gutenberg's block-library and WP
Core's Font Library got real attention rather than a narrow single-function check — and it still
didn't produce a confirmed SQLi/RCE/stored-XSS/privesc bug. The recurring shape across every false
lead this round is the same: WordPress's own escaping/validation primitives
(`get_block_wrapper_attributes()`, `wp_kses_post()`, `safecss_filter_attr()`, `wp_handle_upload()`,
`wp_http_validate_url()`, `wp_safe_remote_get()`, capability-mapped custom post types) are being
used correctly and consistently at the actual point where untrusted data would otherwise become
dangerous, even when the *call site itself* looks unescaped in isolation. That's a genuine
property of this codebase's design, not an accident of what got checked.

## Addendum: Create Block Theme's font/media download path — already deliberately hardened

Followed up on the file-write surface flagged as not fully checked in round 1
(`theme-fonts.php`/`theme-media.php`, the actual per-file names for downloaded font/image assets,
as opposed to the theme *slug* already ruled out). Found the opposite of a fresh bug: this is the
most deliberately hardened code encountered in the whole audit.

`CBT_Theme_Fonts::is_allowed_font_url()` and `CBT_Theme_Media::is_allowed_media_url()` (explicitly
cross-referencing each other in their docblocks as mirrored logic) both reject any URL whose
basename has *any* dot-separated segment matching a dangerous-extension denylist (`php`, `phtml`,
`phar`, `php3`-`php8`, `phps`, `html`, `htaccess`, `cgi`, `pl`, `py`, `rb`, `sh`, `asp`, `jsp`,
`js`, `mjs`, etc.) — specifically to close off the classic multi-extension polyglot bypass
(`evil.php.woff2`, `shell.php.jpg`) before even checking the allowlist. On top of that,
`is_allowed_font_file()` does **magic-byte verification** of the downloaded body against the claimed
extension (`wOF2`/`wOFF`/`OTTO`/TTF-signature/EOT-version-field), with an explicit comment
explaining *why* MIME-sniffing via `finfo`/`wp_check_filetype_and_ext()` wasn't trusted here
(no font MIMEs in WP core's registry, libmagic version variance) — i.e., this reads as a
considered, deliberate design decision, not an oversight. `make_filename_from_fontface()` builds
the actual on-disk filename via `sanitize_title()` on every component, closing off path traversal
via font-face metadata too.

This isn't a new finding — it's confirmation that this specific file-upload surface, which *looks*
exactly like the shape of bug this audit is hunting for, already received real security attention.
Worth recording precisely because it explains part of why this audit keeps coming up empty: this
isn't unaudited code.
