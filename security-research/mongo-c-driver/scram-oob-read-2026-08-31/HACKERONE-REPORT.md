# Title

Out-of-bounds heap read in SCRAM authentication response parsing (`_mongoc_scram_step2`/`_mongoc_scram_step3`), escalating via an integer-underflowed `memchr` call to either a crash (confirmed) or, chained with a second, independent missing-validation bug in the same function, potential disclosure of adjacent process memory back to the attacker (analytically demonstrated, not yet reduced to a minimal clean PoC) — triggerable by a malicious/compromised `mongod` (or a MITM without TLS) against any client using `mongo-c-driver`

## Summary

`mongo-c-driver`'s SCRAM-SHA-1/SCRAM-SHA-256 client authentication code (`src/libmongoc/src/mongoc/mongoc-scram.c`) parses the comma-separated `key=value` fields of the SASL messages sent by the **server** (`r=`/`s=`/`i=` in the server-first-message, `v=`/`e=` in the server-final-message) with a hand-written loop that, after recognizing a key character, advances the read pointer and dereferences it to check for `=` **without first checking that the pointer is still within the caller-supplied length**. A server response that is truncated so it ends immediately after a bare key character (no following `=value`) causes:

1. A **1-byte out-of-bounds heap read** (confirmed with AddressSanitizer), and, when the byte immediately following the logical end of the message happens to be `=` (which — as demonstrated below — an attacker reliably controls via the buffer-reuse pattern in the real call site),
2. An **integer underflow in a subsequent pointer-difference computed as the length argument to `memchr`**, turning it into a wraparound-huge `size_t`, causing `memchr` to scan far outside any valid memory. Depending on what byte values it encounters:
   - if no comma byte is present anywhere in reachable memory before an unmapped page, the process **crashes with SIGSEGV** (confirmed with AddressSanitizer), or
   - if a comma byte *is* found at some reachable distance, the scan **succeeds** and the driver treats everything between the wild pointer and that comma as the value of whichever SCRAM field was being parsed — i.e. it copies that span of adjacent process memory into a heap buffer.

When the field being parsed this way is `r=` (the server-echoed client nonce), that captured memory does not stay local: I found a **second, independent bug** in the same function — the check that verifies the server actually echoed the client's real nonce (`mongoc-scram.c` lines 666-673) sets an error on mismatch but is **missing the `goto FAIL`** that every other validation failure in this function has, so a mismatched (here: leaked-memory-garbage) nonce is *not* rejected. Execution falls straight through into building the client's own next message (`"c=biws,r=" + <captured memory> + ",p=..."`), which is what actually gets sent back over the wire. Chained together, these two bugs give a malicious server a path to read a bounded span of the connecting client's process memory and have the client transmit it back to that same server — not merely crash it.

This fires while the driver is authenticating to a server — i.e., it is entirely attacker-controlled from the server side of the connection, requires no valid credentials from the attacker, and affects the connecting client application. Both identically-shaped parsing loops in `_mongoc_scram_step2` (processes the server-first-message) and `_mongoc_scram_step3` (processes the server-final-message) have the base OOB-read defect; both were independently reproduced with AddressSanitizer below. The missing-`goto FAIL` chaining is specific to `_mongoc_scram_step2`'s handling of `r=`, since that is the field whose value flows unchecked into the outgoing message.

I want to be precise about what is proven versus analytically demonstrated: the OOB read and the SIGSEGV crash are both reproduced and confirmed with AddressSanitizer. The missing `goto FAIL` is confirmed by direct code reading (there is no code path between the error being set and the function proceeding to build and return the outgoing message). The full disclosure chain — a real secret byte from client memory reaching the wire — I was able to drive up to the point of the driver *attempting* to transmit a captured span of memory (see "Escalation analysis" below), but did not reduce to a single, clean, deterministic PoC that prints a specific leaked secret, because the exact distance to the nearest comma byte is a function of the real process's memory layout at the time, which my synthetic test harness does not faithfully reproduce (a real, complex application linking this driver has a much richer and more attacker-shapeable memory layout around the 4096-byte reused buffer than a small standalone test binary does). I'm reporting the chain at the confidence level each part actually supports, rather than claiming a fully-proven memory leak I have not concretely captured.

## Weakness

CWE-125 (Out-of-bounds Read), escalating via CWE-191 (Integer Underflow) in a pointer-difference used as an unsigned length argument, to either a crash (SIGSEGV, confirmed) in `memchr`, or — chained with CWE-295-adjacent missing validation enforcement (a set-but-unenforced error check) — potential disclosure of adjacent process memory to the attacker (CWE-200), analytically demonstrated.

## Authentication Required

**None, from the attacker's side.** The attacker *is* the entity the client is authenticating to (a malicious or compromised `mongod`/`mongos`, a rogue node a misconfigured/poisoned SRV or connection string points at, or an active on-path attacker when TLS is not used or certificate verification is disabled) — no valid MongoDB credentials are needed to send a malformed SASL reply. The victim is the client application: any process linking `mongo-c-driver` that attempts to authenticate with `SCRAM-SHA-1` or `SCRAM-SHA-256` (the default mechanism) against that server is affected during the authentication handshake, before it has any way to have verified the server's legitimacy.

## Component / Version

- Repository: `mongodb/mongo-c-driver` (HackerOne scope: **C Driver**)
- Tag audited: `1.30.8`
- Commit: [`57dba9c04991e38124022e0f16c50b87bd9b29a1`](https://github.com/mongodb/mongo-c-driver/commit/57dba9c04991e38124022e0f16c50b87bd9b29a1)
- Confirmed with a from-source build (`-fsanitize=address,undefined`, GCC 13, Ubuntu 24.04)

## Root cause, with links to the exact code

[`src/libmongoc/src/mongoc/mongoc-scram.c#L590-L643`](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L590-L643), `_mongoc_scram_step2`'s parser for the server-first-message:

```c
for (const uint8_t *ptr = inbuf; ptr < inbuf + inbuflen;) {
   switch (*ptr) {
   case 'r': current_val = &val_r; current_val_len = &val_r_len; break;
   case 's': current_val = &val_s; current_val_len = &val_s_len; break;
   case 'i': current_val = &val_i; current_val_len = &val_i_len; break;
   default: /* ...error... */ goto FAIL;
   }

   ptr++;                                  // <-- may now equal inbuf + inbuflen

   if (*ptr != '=') {                      // <-- L615: OOB read if so
      /* ...error... */
      goto FAIL;
   }

   ptr++;                                  // <-- may now equal inbuf + inbuflen + 1

   const uint8_t *const next_comma =
      (const uint8_t *) memchr (ptr, ',', (inbuf + inbuflen) - ptr);   // <-- L626
   ...
```

If the message ends right after a bare `r`/`s`/`i` (loop entered with `ptr == inbuf + inbuflen - 1`), the first `ptr++` puts `ptr` exactly at `inbuf + inbuflen` — one past the caller-declared valid range — and the very next line dereferences it. There is no `ptr < inbuf + inbuflen` (or equivalent) check between the two increments and their dereferences anywhere in the loop.

Worse: if that out-of-bounds byte happens to read as `'='` (attacker-influenced — see below), the code does **one more** unchecked `ptr++` and then computes `(inbuf + inbuflen) - ptr` as the length passed to `memchr`. At this point `ptr > inbuf + inbuflen`, so the pointer difference is **negative**, and being implicitly converted to `memchr`'s `size_t` parameter, **wraps around to a value near `SIZE_MAX`** — `memchr` then scans forward from `ptr` for a comma across essentially the entire address space until it hits an unmapped page, crashing the process.

[`_mongoc_scram_step3`](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L864-L895), which parses the server-final-message (`v=`/`e=`), has the byte-for-byte identical pattern (dereference at line 885, `memchr` at line 895) — same bug, same root cause, independently reproduced below.

### Why the "worse" (`memchr`/SIGSEGV) path is realistic, not just a synthetic PoC artifact

The real call site, [`mongoc-cluster.c`'s `_mongoc_cluster_auth_scram_continue`](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1423-L1466), declares **one** `uint8_t buf[4096]` stack buffer *outside* the SCRAM round-trip loop and reuses it, unmodified beyond the bytes actually written, as both the input and output buffer for every step:

```c
uint8_t buf[4096] = {0};
uint32_t buflen = 0;
...
if (!_mongoc_cluster_scram_handle_reply (scram, sasl_start_reply, &done, &conv_id, buf, sizeof buf, &buflen, error))
   return false;
for (;;) {
   if (!_mongoc_scram_step (scram, buf, buflen, buf, sizeof buf, &buflen, error))
      return false;
   ...
   /* ...send buf[0..buflen) to the server, get a new reply, call
      _mongoc_cluster_scram_handle_reply again, which memcpy()s only
      the new *buflen bytes into buf — bytes beyond the new buflen are
      untouched leftovers from the PREVIOUS message. */
```

[`_mongoc_cluster_scram_handle_reply`](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1391-L1399) only overwrites `buf[0 .. *buflen)`:

```c
bson_iter_binary (&iter, &btype, buflen, (const uint8_t **) &tmpstr);
if (*buflen > bufmax) { /* ...error... */ }
memcpy (buf, tmpstr, *buflen);
```

So a malicious server that controls **both** SASL round trips can: (1) in its first reply, pad the free-form tail of the `r=` field (the SCRAM spec lets the server append its own extension after the client's echoed nonce — entirely free-form, entirely server-chosen) so that a `'='` byte lands at a byte offset of its choosing within the 4096-byte buffer; then (2) send a second, shorter reply that is truncated to end exactly at that offset. The stale `'='` byte from the first message is still sitting in `buf` at that offset, since nothing clears it — turning the 1-byte overread into the unbounded `memchr` call and the SIGSEGV crash, in the exact buffer the real driver uses in production, not just an artificially-shrunk test buffer.

### Escalation analysis: from a crash to a potential memory disclosure

The `memchr` call at line 626 (step2) / 895 (step3) does not have to crash. Whether it does depends entirely on what byte the wild pointer walk encounters first:

- If it hits an unmapped page before any `','` byte (0x2C) — **SIGSEGV**, PoC 2 above.
- If it hits a `','` byte first — `memchr` returns a valid pointer, and the code treats the entire span between the wild pointer and that comma as the field's value: it `bson_malloc`s a buffer of that size and `memcpy`s that much adjacent memory into it. This is the point where a bounded span of process memory (whatever was actually sitting past the reused buffer) gets copied out.

**A key thing an attacker controls: whether the scan stays inside their own earlier message, or runs past it into unrelated memory.** The 4096-byte `buf` in `mongoc-cluster.c` is refilled, up to `*buflen` bytes, by the attacker's *own* prior SASL reply (`memcpy (buf, tmpstr, *buflen)` — see above). If the attacker's first reply avoids the byte `','` anywhere past the point where their second, truncated reply will end, the wild scan cannot find a comma within `buf` itself — because every byte remaining there is the attacker's own, comma-free content — and is forced to run **past the end of the 4096-byte array** into whatever else is adjacent on the stack: other local variables in the same or a caller's stack frame. *That* is memory the attacker does not already know and did not supply — a genuine potential disclosure target, not just an echo of their own bytes back to themselves.

**Which field's value actually reaches the wire.** Whichever key (`r`/`s`/`i` in step2, `v`/`e` in step3) is the truncated one is the one whose value gets set to the captured span. Of these, `r=` (the client-nonce echo) is the interesting one: I found that [the nonce-verification check](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L666-L673) —

```c
/* verify our nonce */
if (mcommon_cmp_less_us (val_r_len, scram->encoded_nonce_len) ||
    mongoc_memcmp (val_r, scram->encoded_nonce, scram->encoded_nonce_len)) {
   bson_set_error (error, MONGOC_ERROR_SCRAM, MONGOC_ERROR_SCRAM_PROTOCOL_ERROR,
                   "SCRAM Failure: client nonce not repeated in sasl step 2");
}
// <-- no `goto FAIL;` here, unlike every other check in this function

*outbuflen = 0;
if (!_mongoc_scram_buf_write ("c=biws,r=", -1, outbuf, outbufmax, outbuflen)) { goto BUFFER; }
if (!_mongoc_scram_buf_write ((char *) val_r, val_r_len, outbuf, outbufmax, outbuflen)) { goto BUFFER; }
```

— sets an error on a mismatched nonce but has **no `goto FAIL`**, unlike literally every other validation failure in this function (`no r param`, `no s param`, `no i param`, bad salt, bad iterations — all `goto FAIL` immediately). Execution falls straight through and writes `val_r` — at this point, the captured span of adjacent memory — directly into `outbuf`, which becomes the client's own `saslContinue` command, sent back to the server.

**What I confirmed versus what remains to be pinned down.** Both size limits gating a full round trip (`outbuf` and `scram->auth_message`, [the latter allocated as `bson_malloc (outbufmax)`](https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L351-L353) — i.e. also 4096 in the real call site) are the same ~4096-byte order of magnitude, so a captured span needs to land under roughly that size for `_mongoc_scram_step` to return `true` with the leak embedded in `outbuf` rather than failing on a buffer-capacity check partway through. I built a harness (`poc_scram_leak4.c`, included) that reaches exactly this stage — reproducing steps 1-2 of a real handshake, then the missing-`goto FAIL` fallthrough itself (`step2 returned 0 (error: SCRAM Failure: could not buffer auth message in sasl step2)` — confirming the code proceeded all the way through the unenforced nonce check and the `outbuf` write before finally failing on the *separate* `auth_message` capacity check) — but in my synthetic single-purpose test binary, the nearest comma the wild scan actually found was well beyond 4096 bytes away, so I did not walk away with a concrete transmitted secret byte in hand. A real, complex application process has far more heap/stack content of far more varied shapes within a few KB of any given stack buffer than a minimal test binary does, and the attacker's comma-avoidance strategy above gives them meaningful influence over where the scan actually lands — so I consider the disclosure path credible and worth fixing alongside the crash, without claiming I have extracted a specific secret from a specific victim process.

## Steps to Reproduce

Built `1.30.8` from source with AddressSanitizer + UBSan (`-fsanitize=address,undefined -g -O0`), then linked a small standalone C harness directly against the compiled `libmongoc-static-1.0.a`/`libbson-static-1.0.a`, calling the real (non-static, internally-linked) `_mongoc_scram_step`/`_mongoc_scram_init`/`_mongoc_scram_set_user`/`_mongoc_scram_set_pass` exactly as `mongoc-cluster.c` does, to drive a full, real SCRAM handshake and feed it a malicious step message.

**PoC 1 — the base 1-byte OOB read (`_mongoc_scram_step2`), exact-size heap buffer:**
```c
/* step1: get a real client nonce */
_mongoc_scram_init(&scram, MONGOC_CRYPTO_ALGORITHM_SHA_256);
_mongoc_scram_set_user(&scram, "testuser");
_mongoc_scram_set_pass(&scram, "testpass");
_mongoc_scram_step(&scram, out_buf, 0, out_buf, sizeof(out_buf), &out_buflen, &error);

/* malicious "server-first-message": well-formed up to a bare 'i' with no '=' */
char *msg = "r=<client-nonce>,s=YWJjZA==,i";     /* ends right after 'i' */
uint8_t *inbuf = bson_malloc(strlen(msg));        /* exact size, no slack */
memcpy(inbuf, msg, strlen(msg));

scram.step = 1;
_mongoc_scram_step(&scram, inbuf, (uint32_t) strlen(msg), out_buf, sizeof(out_buf), &out_buflen, &error);
```
Result:
```
==3031==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at ... thread T0
    #0 in _mongoc_scram_step2 mongoc-scram.c:615
    #1 in _mongoc_scram_step   mongoc-scram.c:975
0x... is located 0 bytes after 47-byte region [...]
allocated by thread T0 here:
    #1 in bson_malloc bson-memory.c:101
    #2 in main poc_scram_oob.c:61
SUMMARY: AddressSanitizer: heap-buffer-overflow mongoc-scram.c:615 in _mongoc_scram_step2
```

**PoC 2 — the escalation to SIGSEGV**, simulating the real call site's stale-byte reuse (allocate `n+1` bytes, set the caller-declared length to `n`, and place `'='` at the byte just past it — exactly what happens naturally when the real 4096-byte `buf` in `mongoc-cluster.c` still holds a `'='` left over from an earlier, attacker-controlled message):
```
crafted payload (16 logical bytes, 17 allocated): r=<nonce>,s=..,i | stale-byte='='
==3042==ERROR: AddressSanitizer: SEGV on unknown address 0x504000010000
    #0 in __memchr_evex_rtm ...
    #1 in memchr ...
    #2 in _mongoc_scram_step2 mongoc-scram.c:626
    #3 in _mongoc_scram_step   mongoc-scram.c:975
SUMMARY: AddressSanitizer: SEGV mongoc-scram.c:626 in _mongoc_scram_step2
```

**PoC 3 — identical bug in `_mongoc_scram_step3`**, reached via a *fully legitimate* step-1 → step-2 exchange (real nonce, real 16-byte salt, `i=4096`, real `salted_password`/`client_key` computed) followed by a malformed step-3 server-final-message ending bare at `v`:
```
step2 (legit) succeeded, step=2
==3063==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at ... thread T0
    #0 in _mongoc_scram_step3 mongoc-scram.c:885
    #1 in _mongoc_scram_step   mongoc-scram.c:977
0x... is located 0 bytes after 18-byte region [...]
SUMMARY: AddressSanitizer: heap-buffer-overflow mongoc-scram.c:885 in _mongoc_scram_step3
```

All three reproduced consistently across multiple runs.

## Impact

Any application built on `mongo-c-driver` (or a binding built on top of it) that authenticates with `SCRAM-SHA-1`/`SCRAM-SHA-256` (the default and near-universal mechanism) against a server it does not fully trust — a malicious or compromised cluster member, a poisoned DNS/SRV record, a proxy, or an on-path attacker when TLS is not enforced/verified — is exposed to a single malformed SASL reply during the authentication handshake, before the client has any basis for having verified the server's identity. This is a genuine memory-safety bug (an out-of-bounds read that a hostile peer can escalate into an unbounded `memchr` scan) in a widely-used, memory-unsafe-language official database driver — the exact bug class this program's C-driver scope exists for. Two distinct outcomes are in scope depending on what the wild scan encounters:

- **Confirmed (AddressSanitizer-reproduced): a reliable crash/DoS** against the connecting client — this alone is a solid finding on its own.
- **Analytically demonstrated, chained with the missing-`goto FAIL` bug in the same function: potential disclosure of a bounded span of the client process's adjacent memory back to the attacker**, via the `r=` field of the client's own next SASL message. I was able to drive this chain up to the point where the driver is actively attempting to transmit a captured memory span (see "Escalation analysis" above) and to confirm, by direct code reading, that the safety check that should reject this exact scenario (a nonce that doesn't match) is present but not enforced. I did not extract a specific secret value from a specific victim process — that depends on real-process memory layout my synthetic harness doesn't reproduce — so I'm not claiming a proven data exfiltration, only a credible, code-confirmed path to one that I believe is worth fixing at the same time as the crash.

## Suggested Fix

1. Add an explicit bounds check before each dereference in both loops, e.g.:
```c
ptr++;
if (ptr >= inbuf + inbuflen || *ptr != '=') {
   bson_set_error (...);
   goto FAIL;
}
ptr++;
if (ptr > inbuf + inbuflen) {
   bson_set_error (...);
   goto FAIL;
}
const uint8_t *const next_comma = (const uint8_t *) memchr (ptr, ',', (inbuf + inbuflen) - ptr);
```
applied identically to `_mongoc_scram_step2` (lines 613-626) and `_mongoc_scram_step3` (lines 883-895). This alone closes both the crash and the disclosure path, since it removes the only way `ptr` can ever exceed `inbuf + inbuflen`.

2. Independently, add the missing `goto FAIL;` right after the nonce-mismatch `bson_set_error` at lines 669-673 — a mismatched nonce should abort the handshake immediately like every other validation failure in this function does, both as defense-in-depth against bug classes like this one and because silently proceeding on a nonce mismatch weakens SCRAM's own protection against a server that doesn't correctly echo the client's nonce (a core anti-replay/anti-downgrade property of the protocol).

3. Separately, `_mongoc_cluster_auth_scram_continue`'s reused `buf[4096]` should be re-zeroed (or the previous message's byte range explicitly cleared) before each new server reply is copied in, so a parser bug elsewhere can't be re-exposed to the same class of issue by stale bytes from an earlier round trip.

## Supporting Material

- Vulnerable loops: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L590-L643 (step2) and https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L864-L895 (step3)
- Missing `goto FAIL` (chaining bug): https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L666-L683
- Reused-buffer call site: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1423-L1466
- `memcpy`-only-new-bytes helper: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1346-L1402
- `auth_message` sized identically to `outbuf`: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L351-L353
- `poc_scram_leak4.c` (included in this directory): drives a real step1→step2 handshake and reaches the unenforced-nonce-check fallthrough, confirming the escalation chain reaches the message-construction stage before failing on the separate `auth_message` capacity check in this specific synthetic memory layout.
