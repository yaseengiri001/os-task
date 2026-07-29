/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Self-test: verifies the crypto module against PUBLISHED test vectors
 * -----------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 *   A hash function that is subtly wrong still produces confident-looking
 *   hex output. Nothing about the program would appear broken - authentication
 *   would still "work", because a wrong hash compared against another wrong
 *   hash still matches. The defect would only surface as a security hole.
 *
 *   The only way to know an implementation is correct is to check it against
 *   vectors published with the standard, computed independently by its authors.
 *   Every part of Task 3 depends on this module, so this test runs first.
 *
 * SOURCES OF THE VECTORS
 *   SHA-256      FIPS 180-4 / NIST example documents
 *   HMAC-SHA256  RFC 4231, section 4
 *   PBKDF2       RFC 7914, section 11
 *
 * BUILD & RUN
 *   make test
 * -----------------------------------------------------------------------------
 */

#include "sha256.h"
#include "chacha20.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

/* Compare a computed value against the expected hex string and report.
   The buffer is sized for the longest vector checked here (114 bytes). */
static void check(const char *label, const uint8_t *got, size_t len,
                  const char *expected_hex)
{
    char hex[512];
    hex_encode(got, len, hex);
    checks++;

    if (strcmp(hex, expected_hex) == 0) {
        /* Long values are truncated in the PASS line so the table stays
           readable; the comparison itself is always against the full value. */
        if (strlen(hex) <= 64) printf("  PASS  %-42s %s\n", label, hex);
        else                   printf("  PASS  %-42s %.60s...\n", label, hex);
    } else {
        printf("  FAIL  %-42s\n", label);
        printf("        expected %s\n", expected_hex);
        printf("        got      %s\n", hex);
        failures++;
    }
}

int main(void)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t key[131], data[64];

    printf("Crypto self-test - checking against published vectors\n");
    printf("=====================================================\n\n");

    /* ---- SHA-256 (FIPS 180-4) ------------------------------------------- */
    printf("SHA-256  (FIPS 180-4)\n");

    sha256((const uint8_t *)"", 0, digest);
    check("empty string", digest, 32,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256((const uint8_t *)"abc", 3, digest);
    check("\"abc\"", digest, 32,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /* 56 bytes: exercises the padding path where the length does NOT fit in
       the final block and a second block is needed. */
    const char *msg2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t *)msg2, strlen(msg2), digest);
    check("56-byte message (two-block padding)", digest, 32,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* One million 'a' characters: exercises the streaming update path. */
    {
        SHA256_CTX ctx;
        uint8_t chunk[1000];
        memset(chunk, 'a', sizeof(chunk));
        sha256_init(&ctx);
        for (int i = 0; i < 1000; i++) sha256_update(&ctx, chunk, sizeof(chunk));
        sha256_final(&ctx, digest);
        check("one million 'a' (streaming)", digest, 32,
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    /* ---- HMAC-SHA256 (RFC 4231) ----------------------------------------- */
    printf("\nHMAC-SHA256  (RFC 4231)\n");

    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, digest);
    check("case 1: 20-byte key", digest, 32,
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    hmac_sha256((const uint8_t *)"Jefe", 4,
                (const uint8_t *)"what do ya want for nothing?", 28, digest);
    check("case 2: short key", digest, 32,
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    hmac_sha256(key, 20, data, 50, digest);
    check("case 3: repeated data", digest, 32,
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* A key longer than the 64-byte block, which must be hashed down first. */
    memset(key, 0xaa, 131);
    hmac_sha256(key, 131,
                (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First",
                54, digest);
    check("case 6: key longer than block size", digest, 32,
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    /* ---- PBKDF2-HMAC-SHA256 (RFC 7914) ---------------------------------- */
    printf("\nPBKDF2-HMAC-SHA256  (RFC 7914)\n");

    pbkdf2_hmac_sha256("password", (const uint8_t *)"salt", 4, 1, digest, 32);
    check("password/salt, 1 iteration", digest, 32,
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    pbkdf2_hmac_sha256("password", (const uint8_t *)"salt", 4, 2, digest, 32);
    check("password/salt, 2 iterations", digest, 32,
          "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

    pbkdf2_hmac_sha256("password", (const uint8_t *)"salt", 4, 4096, digest, 32);
    check("password/salt, 4096 iterations", digest, 32,
          "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

    /* ---- ChaCha20 (RFC 8439) -------------------------------------------- */
    printf("\nChaCha20  (RFC 8439)\n");
    {
        uint8_t cc_key[32], cc_nonce[12], block[64];

        /* The RFC's key is simply the bytes 0x00..0x1f. */
        for (int i = 0; i < 32; i++) cc_key[i] = (uint8_t)i;

        /* Section 2.3.2: the raw block function. */
        memset(cc_nonce, 0, 12);
        cc_nonce[3] = 0x09; cc_nonce[7] = 0x4a;
        chacha20_block(cc_key, 1, cc_nonce, block);
        check("2.3.2 keystream block", block, 64,
              "10f1e7e4d13b5915500fdd1fa32071c4"
              "c7d1f4c733c068030422aa9ac3d46c4e"
              "d2826446079faa0914c2d705d98b02a2"
              "b5129cd1de164eb9cbd083e8a2503c4e");

        /* Section 2.4.2: encrypting a real message. */
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could "
                         "offer you only one tip for the future, sunscreen "
                         "would be it.";
        size_t  ptlen = strlen(pt);
        uint8_t ct[256], back[256];

        memset(cc_nonce, 0, 12);
        cc_nonce[7] = 0x4a;
        chacha20_xor(cc_key, 1, cc_nonce, (const uint8_t *)pt, ct, ptlen);
        check("2.4.2 encryption (114 bytes)", ct, ptlen,
              "6e2e359a2568f98041ba0728dd0d6981"
              "e97e7aec1d4360c20a27afccfd9fae0b"
              "f91b65c5524733ab8f593dabcd62b357"
              "1639d624e65152ab8f530c359f0861d8"
              "07ca0dbf500d6a6156a38e088a22b65e"
              "52bc514d16ccf806818ce91ab7793736"
              "5af90bbf74a35be6b40b8eedf2785e42"
              "874d");

        /* Decryption is the SAME operation run again - XOR is its own
           inverse. This is the property Part 4 relies on. */
        chacha20_xor(cc_key, 1, cc_nonce, ct, back, ptlen);
        checks++;
        if (memcmp(back, pt, ptlen) == 0) {
            printf("  PASS  %-42s round-trip returns the plaintext\n",
                   "decrypt == encrypt (XOR self-inverse)");
        } else {
            printf("  FAIL  %-42s\n", "decrypt == encrypt");
            failures++;
        }
    }

    /* ---- constant-time comparison ---------------------------------------- */
    printf("\nConstant-time comparison\n");
    {
        uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 4}, c[4] = {1, 2, 3, 5};
        checks++;
        if (constant_time_equal(a, b, 4) && !constant_time_equal(a, c, 4)) {
            printf("  PASS  %-42s equal matches, unequal differs\n", "behaviour");
        } else {
            printf("  FAIL  %-42s\n", "behaviour");
            failures++;
        }
    }

    /* ---- verdict --------------------------------------------------------- */
    printf("\n=====================================================\n");
    if (failures == 0) {
        printf("All %d checks PASSED - the crypto module matches the standards.\n",
               checks);
        return 0;
    }
    printf("%d of %d checks FAILED - do not rely on this build.\n", failures, checks);
    return 1;
}
