/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Shared crypto module: SHA-256, HMAC-SHA256 and PBKDF2
 * -----------------------------------------------------------------------------
 * WHY THIS IS A SHARED MODULE RATHER THAN COPIED INTO EACH PART
 *   Parts 2 (authentication), 4 (encryption) and 5 (audit logging) all need a
 *   hash function. Copying the implementation into each one would be a genuine
 *   SECURITY problem, not just untidy: if a defect were found, every copy would
 *   have to be found and fixed, and the one that was missed would be the one
 *   still exploitable. Cryptographic code should exist exactly once, so there is
 *   a single place to audit and a single place to fix. Every part therefore
 *   links against this one implementation.
 *
 * WHAT IS HERE
 *   sha256      - the FIPS 180-4 hash function, implemented from scratch
 *   hmac_sha256 - RFC 2104 keyed authentication (proves a message was not
 *                 altered by someone without the key)
 *   pbkdf2      - RFC 8018 password-based key derivation: deliberately SLOW,
 *                 which is what makes stolen password hashes expensive to crack
 *
 * A NOTE ON USING A HAND-WRITTEN IMPLEMENTATION
 *   Real systems must use a reviewed library (OpenSSL, libsodium), never a
 *   hand-rolled one - the algorithm being correct is not the same as the
 *   implementation being safe against timing and side-channel attacks. It is
 *   written from scratch here because the module is about understanding these
 *   mechanisms, and because the brief asks for no external dependencies. This
 *   limitation is stated plainly in the security analysis rather than hidden.
 * -----------------------------------------------------------------------------
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32   /* 256 bits = 32 bytes */
#define SHA256_BLOCK_SIZE  64   /* 512 bits = 64 bytes */

/* Streaming interface: init -> update (any number of times) -> final. */
typedef struct {
    uint32_t state[8];                    /* the eight working hash words   */
    uint64_t bitlen;                      /* total message length in bits   */
    uint8_t  buffer[SHA256_BLOCK_SIZE];   /* partial block not yet processed */
    size_t   buflen;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/* One-shot convenience wrapper around the three calls above. */
void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

/* Write a digest as lowercase hex. `out` needs 2*len + 1 bytes. */
void hex_encode(const uint8_t *data, size_t len, char *out);

/*
 * HMAC-SHA256 (RFC 2104).
 * A plain hash cannot authenticate a message, because anyone can recompute it.
 * HMAC mixes in a secret key, so only a holder of the key can produce a valid
 * tag. Used here to detect tampering with ciphertext and with the audit log.
 */
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen,
                 uint8_t out[SHA256_DIGEST_SIZE]);

/*
 * PBKDF2-HMAC-SHA256 (RFC 8018).
 * Turns a low-entropy password into a key. The iteration count makes each
 * guess cost real time, so an attacker holding a stolen hash file has to pay
 * that cost for every candidate password they try.
 */
void pbkdf2_hmac_sha256(const char *password,
                        const uint8_t *salt, size_t saltlen,
                        uint32_t iterations,
                        uint8_t *out, size_t outlen);

/*
 * Compare two buffers in CONSTANT TIME.
 * A normal memcmp returns as soon as it finds a difference, so how long it took
 * leaks how many leading bytes were correct. An attacker can use that to
 * recover a secret one byte at a time. This version always inspects every byte.
 */
int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* SHA256_H */
