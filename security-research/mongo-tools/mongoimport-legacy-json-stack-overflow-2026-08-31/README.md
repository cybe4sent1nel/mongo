# mongoimport --legacy: unbounded recursion → uncaught stack overflow

Finding #4 from the ongoing `mongo-tools` audit pass (tag `100.18.0`, commit
`21a342dfee6468ad9350d156d25086da64dd03b1`).

See `HACKERONE-REPORT.md` for the full write-up. Short version: `mongoimport --type=json --legacy`
resolves legacy extended-JSON values via a hand-written, mutually-recursive walk
(`common/bsonutil.ConvertLegacyExtJSONValueToBSON` ⇄ `ParseLegacyExtJSONValue`) that has no
nesting-depth limit. A single ~4 MB JSON document with two million levels of array nesting
crashes the process with a Go `fatal error: stack overflow` (exit code 2) — empirically
reproduced against a locally-built `100.18.0` binary. This is first-party `mongo-tools` code
(`common/bsonutil`), a different code path from the previously-reported `mongo-go-driver`
extended-JSON depth bypass, though the same underlying bug class (CWE-674).

No authentication to the target `mongod` is required — the crash happens during local file
parsing, before any data reaches the server.
