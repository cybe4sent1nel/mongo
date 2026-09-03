# WordPress 7.1 core — RCE surface audit (2026-09-03)

Per request: deeply audit every core surface for **RCE**, focusing on Block
Bindings, oEmbed/embed, XML-RPC, and REST field callbacks, plus the classic PHP
object-injection path. Live lab: WordPress 7.1 on PHP 8.4.19 (localhost:8371).
**No RCE found.** This records each primitive and why it is not reachable/usable,
with the one empirical test that matters (the object-injection gadget).

## 1. PHP object injection — primitive reachable, but no usable gadget on PHP 8.4

**Reachable `unserialize` sinks** (raw, non-`maybe_`):

| sink | verdict |
|---|---|
| `class-wp-customize-widgets.php:1496` | Guarded by `hash_equals( get_instance_hash_key($decoded), $value['instance_hash_key'] )` — an HMAC over a server secret. This is the historical widget object-injection fix; an attacker cannot forge the key. **Not exploitable.** |
| `rss.php:809` (`RSSCache::unserialize`) | Deprecated MagpieRSS cache. The modern feed path (`fetch_feed()` / RSS block) uses SimplePie, not this. **Dead code**, not request-reachable. |
| `SimplePie` cache serialize/unserialize | Cache blobs are written by SimplePie itself (serialize of its own objects) into a server cache dir; an attacker controlling *feed content* does not control the serialized class graph, and cannot write the cache file directly. Not request-reachable. |

**`maybe_unserialize` (meta/options/transients)** is the broadly-reachable sink:
a raw string stored as meta is `is_serialized()`-checked and unserialized on read.
So the *injection primitive* can exist wherever a low-privilege user stores a raw
`O:`-string meta value. **But injection needs a gadget.**

**The gadget question — tested empirically.** Core's one clean POP gadget is
`WP_HTML_Token::__destruct` (html-api/class-wp-html-token.php:112):

```php
public function __destruct() {
    if ( is_callable( $this->on_destroy ) ) {
        call_user_func( $this->on_destroy, $this->bookmark_name );   // arbitrary callable + arg
    }
}
```

WP 6.4.2 added a throwing `__wakeup` (`throw new \LogicException(...)`). A thrown
`__wakeup` does not *always* prevent `__destruct` (a documented PHP weakness), so
this was tested rather than assumed. Payload
`O:13:"WP_HTML_Token":2:{s:13:"bookmark_name";s:..:"<path>";s:10:"on_destroy";s:5:"touch";}`
through `unserialize()` on **PHP 8.4.19**:

```
unserialize threw: LogicException: WP_HTML_Token should never be unserialized
GADGET_FIRED exists: no (guard held)
```

On PHP 8.4 the throwing `__wakeup` **does** suppress `__destruct`, and because it
throws for *any* `WP_HTML_Token` in the object graph, the class cannot participate
in a chain either — it poisons the whole `unserialize`. The other magic-method
classes in core are not usable gadgets: `SimplePie\Item::__destruct` only
`unset($this->feed)`, its `__toString` is `md5(serialize(...))`,
`PHPMailer::__destruct` only calls `smtpClose()`; none do a `call_user_func` /
file-write / include with attacker-controlled properties. **No completable POP
chain in 7.1 core on modern PHP.** (poc: `poc/t_gadget.php`)

## 2. Block Bindings API — no arbitrary callable, output escaped

`WP_Block::process_block_bindings()` resolves the binding `source` **by registry
name** via `get_block_bindings_source()`; an unregistered name is skipped. Only
the four core sources exist (`post-meta`, `post-data`, `term-data`,
`pattern-overrides`) — the attacker cannot map a source to an arbitrary callable.
The `post-meta` source (`block-bindings/post-meta.php`) is capability- and
allowlist-gated: requires `postId` context, blocks non-public posts without
`read_post`, blocks password-protected posts, blocks `is_protected_meta` keys, and
**requires the key to be `show_in_rest`-registered**. The resolved value is placed
via `replace_html`: `html`/`rich-text` attributes go through `wp_kses_post(
$source_value )`, `attribute` sources through `WP_HTML_Tag_Processor::set_attribute`
(entity-escaped). No RCE and no XSS.

## 3. XML-RPC / IXR — whitelisted callbacks, XML (no `unserialize`)

`IXR_Server::call()` looks the request method name up in `$this->callbacks`
(the registered XML-RPC method map) *before* dispatch; a miss returns fault
-32601. The `$method` passed to `call_user_func($method, $args)`
(class-IXR-server.php:121) is therefore a server-registered callback
(`this:wp_getPost`, …), and the `this:` branch additionally `method_exists`-checks
against the server class. The attacker chooses *which whitelisted method*, never an
arbitrary callable. IXR parses XML-RPC via an XML parser — there is **no PHP
`unserialize`** in the message path, so no object injection. (Pingback remains an
SSRF concern, explicitly out of scope this engagement.)

## 4. oEmbed / embed and REST field callbacks

- **oEmbed**: discovery/proxy fetch a remote URL and parse **JSON/XML** responses;
  there is no `unserialize` of the response, and provider output is `wp_kses`-run.
  The residual risk is SSRF (out of scope), not RCE.
- **REST**: a route's `callback` / `permission_callback` are defined in PHP at
  `register_rest_route` time; they are never selected from request input. Field
  `get_callback`/`update_callback` likewise. No arbitrary-callable dispatch.

## 5. `extract` / variable `include`/`require`

`template.php:795` `extract( $wp_query->query_vars, EXTR_SKIP )` creates named
template vars (no variable-variables; `EXTR_SKIP` won't overwrite) — not code
execution. Every variable `include`/`require` in `wp-includes` loads an
internally-registered path (block-metadata manifests, icons manifest, pattern
`filePath`, `.l10n.php` translations, located template files) — none accept a
request-controlled path. No LFI→RCE.

## Conclusion

WordPress 7.1 core exposes no request-reachable RCE on PHP 8.4: the object-injection
gadget is neutralized by the throwing `__wakeup`, the raw `unserialize` sinks are
HMAC-guarded / deprecated / non-reachable, Block Bindings and XML-RPC dispatch are
registry/whitelist-gated, and no code path takes a request-controlled callable or
include path. Consistent with the stored-XSS rounds, core's defenses hold across
the RCE surface.

### Reproduce
```
php poc/t_gadget.php    # WP_HTML_Token __destruct gadget -> "guard held" on PHP 8.4
```
