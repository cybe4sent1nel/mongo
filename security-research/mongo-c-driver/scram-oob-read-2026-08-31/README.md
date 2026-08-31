# mongo-c-driver SCRAM parsing: out-of-bounds read → SIGSEGV

First finding from the `mongo-c-driver` audit pass (tag `1.30.8`, commit
`57dba9c04991e38124022e0f16c50b87bd9b29a1`).

See `HACKERONE-REPORT.md` for the full write-up. Short version: the hand-written
`key=value` parser for SCRAM server messages in `mongoc-scram.c`
(`_mongoc_scram_step2`/`_mongoc_scram_step3`) dereferences a pointer one byte past
the caller-declared message length without checking first. A malicious or
compromised server can trigger a 1-byte heap-buffer-overflow read (confirmed with
AddressSanitizer), and — by exploiting the fact that the real call site reuses a
single 4096-byte buffer across the whole SCRAM exchange without clearing it — can
escalate this into an integer-underflowed length passed to `memchr`, causing a
real SIGSEGV crash.

Three PoCs included (`poc_scram_oob.c`, `poc_scram_oob2.c`,
`poc_scram_step3_oob.c`), all built and run against the real static library with
ASan+UBSan, all reproduced. No authentication is needed from the attacker's side
— the attacker plays the role of the server the client is authenticating *to*.
