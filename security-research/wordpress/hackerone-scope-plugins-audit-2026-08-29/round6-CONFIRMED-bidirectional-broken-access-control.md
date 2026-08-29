# CONFIRMED, live: Secure Custom Fields' 6.9.5 "REST" fix for bidirectional-field
# broken access control does not cover the default (non-REST) save path

**Plugin:** Secure Custom Fields (`WordPress/secure-custom-fields`, cloned HEAD =
`99cd25279b`, i.e. the *current* `6.9.5` release)
**Class:** Broken Access Control / IDOR — a user without `edit_post` on object B can
force a write into object B's meta, via a field on object A they legitimately own.
**Status: empirically confirmed on a live WordPress 7.1 + SCF 6.9.5 install, not just
argued from source.** This is the real thing the whole "you're missing something, people
are finding stored XSS and RCE" pushback was pointing at — a genuine, fresh, currently-live
bug in one of the four in-scope plugins, found by finally taking the plugin's own
changelog seriously rather than only sweeping for unescaped output.

## The tell that led here

`readme.txt`'s `= 6.9.5 =` entry (*Release Date 7th August 2026* — this is the current
release, not a historical one) lists, under `*Security*`:

> **REST updates now reject bidirectional field writes when the current user cannot edit
> an inverse target.**

That sentence is doing a lot of work: it confirms (a) the SCF team identified exactly this
bug class — a bidirectional field write reaching an "inverse target" object the acting
user isn't allowed to edit — and (b) they scoped the fix to **REST updates**, specifically.
A fix that names its own boundary that precisely is worth checking on both sides of that
boundary, not just trusting the changelog's implicit "and that's the whole story."

## The feature, briefly

SCF's Relationship/Post Object/User/Taxonomy fields support a "Bidirectional" setting
(`includes/acf-bidirectional-functions.php`): when field A (say, on post type "post") is
marked bidirectional with a `bidirectional_target` of field B (on any compatible type),
saving field A on object X doesn't just store the selected IDs on X — it also reaches out
and updates field B *on each selected object* to add/remove a back-reference to X. This is
a legitimate, commonly-used feature (mutual "related posts," reciprocal relationships) and
is enabled by default (`'enable_bidirection' => true` in `secure-custom-fields.php`).

The write to the *target* object happens in `acf_update_bidirectional_values()`
(`includes/acf-bidirectional-functions.php:21`), which calls `update_field($target_field,
..., $target_post_id)` directly — **with no capability check on `$target_post_id`
anywhere in that function, or anywhere in the `update_value()` chain that calls it**
(traced through all four field types that support it: relationship, post_object, user,
taxonomy — none add one). The implicit trust model is "if you can edit the object holding
the bidirectional field, you can also modify whatever object your selection points at" —
which silently breaks the moment the objects you can select from aren't all objects you
can also edit. Relationship/Post Object fields never filter their search results or their
saved-value validation by the *selecting* user's `edit_post` capability on the *candidate*
posts (confirmed in round 4 of this same audit) — by design, you're meant to be able to
relate to posts you can only read. Combined, that's the whole bug: pick any post you can
read, and your unrelated edit of your own post silently writes into it.

## Where the 6.9.5 fix actually landed, and where it didn't

Traced every place `acf_current_user_can_edit_in_context()` — the permission check the
6.9.5 changelog entry is describing — is actually called:

1. `includes/rest-api/class-acf-rest-api.php::check_bidirectional_target_permissions()`
   — hooked on `rest_dispatch_request`, runs before SCF's REST `acf` field's
   `update_callback` is allowed to apply anything, and returns `WP_Error` (`403
   acf_rest_cannot_update_bidirectional_target`) if any bidirectional destination isn't
   editable by the current user. This is the actual 6.9.5 fix, and I confirmed it works
   (see Test 2 below).
2. `includes/Datastore/REST_Save.php::preflight_datastore_request()` — the *other* place
   this check exists, also REST-hooked (`rest_dispatch_request`), but its entire
   registration is gated behind `acf_is_using_datastore()`
   (`includes/datastore.php:22`), which requires the `acf/settings/enable_datastore`
   filter to be explicitly turned on — **default `false`**, confirmed by reading the
   function and re-confirmed live (`acf_is_using_datastore(): bool(false)` on a stock
   install, printed directly in the test below).

Neither of these hooks into, or is called by, the actual function that performs the
write (`acf_update_bidirectional_values()`), nor into the standard save entrypoint
(`acf_save_post()` → `_acf_do_save_post()` → `acf_update_values()` →
`acf_update_value()` → field type's `update_value()`). That standard entrypoint is what
`ACF_Form_Post::save_post()` (`includes/forms/form-post.php:375`) calls, hooked on
WordPress core's own `save_post` action — the mechanism behind **both** the classic
wp-admin post-edit screen **and** the standard Gutenberg block editor, which saves custom
(non-block-registered) meta box data via the "meta-box-loader" AJAX request, which fires
`save_post` the same way the classic editor's plain form POST does
(`includes/forms/form-gutenberg.php` confirms this explicitly — it only rearranges *where*
the meta box UI renders, and its one save-related hook checks for
`$_GET['meta-box-loader']` specifically to relax *validation*, not to swap the save
mechanism). **No special configuration, no REST API client, no Classic Editor plugin
requirement** — this is the save path every default WordPress site with SCF uses today.

## Empirical confirmation

Stood up the same WordPress 7.1 + SCF install used earlier in this session (this time
with SCF actually current, `99cd25279b` / 6.9.5), created:
- Two users: `admin` (ID 1) and `author1` (ID 2, role `author` — no `edit_others_posts`).
- Two posts: one authored by `admin` (ID 10), one authored by `author1` (ID 11).
- A field group (`group_bidir_test`) active on post type `post`, `show_in_rest => 1`,
  with `related_posts` (relationship, `bidirectional => 1`, `bidirectional_target =>
  [backlinks]`) and `backlinks` (a second relationship field, the sync target).

Confirmed the negative control first: `current_user_can('edit_post', 10)` as `author1` is
`false` — the test setup genuinely has no accidental access.

**Test 1 — the default (non-REST) save path, exactly what `ACF_Form_Post::save_post()`
itself calls:**

```php
wp_set_current_user($author_id);                 // author1, no edit_post on post 10
$_POST['acf'] = ['field_related_posts' => ['10']]; // pointing at admin's post
acf_save_post($author_post_id, $_POST['acf']);     // author1 saving THEIR OWN post (11)
```

Result:
```
admin_post (10) backlinks BEFORE: []
admin_post (10) backlinks AFTER:  ["11"]
```

`author1`, saving only their own post, with no capability whatsoever on post 10, caused
post 10's `backlinks` field to be updated to reference post 11. This is a real,
reproducible, unauthorized write into an object the acting user cannot edit — via a
completely ordinary field save on an object they *do* own.

**Test 2 — the same attack via the REST API, to confirm the 6.9.5 fix actually holds
there (it does — this isn't a story about REST being broken too):**

```php
wp_set_current_user($author_id);
$request = new WP_REST_Request('POST', '/wp/v2/posts/11');
$request->set_body(json_encode(['acf' => ['field_related_posts' => ['10']]]));
$response = rest_do_request($request);
```

Result: `status=403`, `error code=acf_rest_cannot_update_bidirectional_target`,
`admin backlinks after: []` — correctly and cleanly blocked, exactly as the changelog
describes. Included specifically to make the asymmetry precise rather than assumed: the
fix is real and works where it was applied; it simply wasn't applied to the path most
installs actually use.

## Impact

Any user who can edit **any** object with a bidirectional-enabled relationship/post
object/user/taxonomy field pointed at a compatible target type can force a write into
**any other object of that target type they can merely select** (which, per the field's
own by-design behavior, is not capability-filtered — you can relate to what you can read)
— regardless of whether they have `edit_post`/equivalent on that target. Concretely, on
any site using this fairly common, on-by-default feature:

- A Contributor/Author can inject unwanted relationship references into posts owned by
  other users, or into content managed by higher-privileged roles (e.g., a "Featured In"
  or "Approved By"-style field an Editor/Admin configured, if it happens to be the
  bidirectional target of a field a lower role can also touch) — a genuine horizontal (and
  in the "approved by"-style case, effectively vertical) access-control break, achieved
  through a first-class, intentional plugin feature rather than a memory-safety bug.
- Because the same `acf_update_bidirectional_values()` call also handles *removal*
  (`array_diff`), the same primitive can silently strip an existing back-reference from an
  object the attacker can't edit, not just add one — a quieter, harder-to-notice content
  integrity attack.
- The written values are always object IDs (post/term/user), not arbitrary strings — so
  this is not itself a direct stored-XSS primitive — but it is a real, working, unauthenticated-
  relative-to-the-target write, i.e., broken access control / an IDOR of the shape HackerOne
  programs consistently treat as valid regardless of whether the payload itself is "just" an ID.

## Recommendation

Move the permission check `acf_update_bidirectional_values()` already has *a name for*
(`acf_current_user_can_edit_in_context()`) into the actual write path itself — inside
`acf_update_bidirectional_values()` (or `_scf_prepare_bidirectional_update()`, which
already computes the exact `$additions`/`$subtractions` destination list) — rather than
only pre-flighting it at the REST dispatch layer. That closes the gap for every save
entrypoint (classic form, Gutenberg meta-box-loader, REST, front-end `acf_form()`,
programmatic `update_field()` calls) at once, instead of requiring a matching pre-flight
hook to be added per entrypoint (which is how this gap happened: two REST-specific
pre-flights exist, one gated behind a default-off feature flag, and the actual majority
save path has neither).

## Scope note

Filed under Secure Custom Fields, one of this program's four in-scope plugins. Verified
against `99cd25279b` (the current `trunk`/6.9.5 HEAD as cloned this session) — this is not
a historical/already-patched issue; the 6.9.5 release that shipped the partial fix is the
version this was found live in.
