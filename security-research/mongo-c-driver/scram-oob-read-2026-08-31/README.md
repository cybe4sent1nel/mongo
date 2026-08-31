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
escalate this into an integer-underflowed length passed to `memchr`. That either
crashes the process (SIGSEGV, confirmed with AddressSanitizer) or, if the scan
happens to land on a comma byte instead of an unmapped page, copies a bounded
span of adjacent process memory into a value the driver then treats as the
server-echoed client nonce. A **second, independent bug** found in the same
function — a nonce-mismatch check that sets an error but is missing the
`goto FAIL` every other check in the function has — lets that captured memory
flow, unrejected, straight into the client's own outgoing SASL message. Chained,
these give a malicious server a credible (analytically demonstrated, not yet
reduced to a clean minimal PoC of a specific leaked secret) path to having the
client transmit adjacent process memory back to it, not just crash.

Five PoCs included (`poc_scram_oob.c`, `poc_scram_oob2.c`,
`poc_scram_step3_oob.c`, `poc_scram_leak4.c`), all built and run against the real
static library, reproducing the OOB read, the SIGSEGV escalation, the identical
bug in step3, and — for `poc_scram_leak4.c` — the missing-`goto FAIL` fallthrough
itself (confirmed reaching the message-construction stage before failing on a
separate, incidental buffer-capacity check in that specific synthetic run). No
authentication is needed from the attacker's side — the attacker plays the role
of the server the client is authenticating *to*.
