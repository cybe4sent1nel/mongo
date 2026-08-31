# mongo-php-driver: BSON-to-PHP unbounded recursion → stack overflow

First finding from the `mongo-php-driver` audit pass (tag `2.4.1`, commit
`3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241`).

See `HACKERONE-REPORT.md` for the full write-up. Short version: `phongo_bson.c`'s
`phongo_bson_visit_document`/`phongo_bson_visit_array` mutually recurse into
`bson_iter_visit_all()` once per level of BSON nesting, with no depth limit
anywhere. A single BSON document with ~200,000 nested sub-documents (1.6MB,
8 bytes/level — far fewer levels would also work) crashes the PHP process with a
real stack overflow: confirmed with AddressSanitizer (clean `stack-overflow`
report) and with a plain production build (SIGSEGV, exit 139, no PHP exception).

The important part: this isn't limited to explicit `Document::fromBSON()->toPHP()`
calls. `MongoDB/Cursor.c` calls the exact same vulnerable entry point on every
document returned while iterating a cursor — i.e. **any ordinary query result**.
A malicious or compromised server (or a MITM without TLS) can crash any PHP
application using this driver via a single crafted document in a normal query
response, no special client code or credentials required.

`build_nested_bson.py` builds the payload; `poc.php` drives the crash via
`MongoDB\BSON\Document::fromBSON()->toPHP()`.
