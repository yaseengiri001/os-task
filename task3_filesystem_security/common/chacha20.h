/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Shared crypto module: ChaCha20 stream cipher (RFC 8439)
 * -----------------------------------------------------------------------------
 * WHY CHACHA20 AND NOT A CAESAR / XOR CIPHER
 *   A Caesar cipher shifts every letter by a fixed amount. It has 25 possible
 *   keys, so it is broken by trying all of them, and it does not even need
 *   that: it preserves letter frequencies, so counting characters recovers the
 *   plaintext instantly. A repeating-XOR key is only slightly better and falls
 *   to the same statistical attack. Neither provides confidentiality against
 *   anyone who is actually trying, so implementing one would demonstrate the
 *   IDEA of encryption without demonstrating encryption.
 *
 *   ChaCha20 is a real, current cipher: it is standardised in RFC 8439, used in
 *   TLS 1.3, WireGuard, SSH and the Linux kernel's random number generator. It
 *   is a good fit here because it is genuinely strong yet small enough to
 *   implement and explain, and because it needs no lookup tables - which is
 *   what makes it naturally resistant to the cache-timing attacks that plague
 *   naive AES implementations.
 *
 * HOW A STREAM CIPHER WORKS
 *   ChaCha20 does not encrypt the message directly. It generates a KEYSTREAM -
 *   a long sequence of bytes that is indistinguishable from random to anyone
 *   without the key - and XORs it with the data:
 *
 *       ciphertext = plaintext XOR keystream
 *       plaintext  = ciphertext XOR keystream      (XOR is its own inverse,
 *                                                   so one function does both)
 *
 *   The keystream comes from repeatedly scrambling a 64-byte state built from
 *   the key, a nonce, and a block counter, through 20 rounds of additions,
 *   XORs and rotations.
 *
 * THE ONE RULE THAT MUST NEVER BE BROKEN
 *   A (key, nonce) pair must NEVER be reused for two different messages. If it
 *   is, both are encrypted with the identical keystream, and XORing the two
 *   ciphertexts together cancels the keystream out completely:
 *
 *       C1 XOR C2 = (P1 XOR KS) XOR (P2 XOR KS) = P1 XOR P2
 *
 *   The attacker now has the XOR of two plaintexts and no key is needed to
 *   attack it. This is not a theoretical concern - it is the flaw that broke
 *   WEP Wi-Fi encryption. The file encryption in Part 4 therefore generates a
 *   fresh random nonce for every single file it writes.
 * -----------------------------------------------------------------------------
 */

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_SIZE   32   /* 256-bit key */
#define CHACHA20_NONCE_SIZE 12   /*  96-bit nonce, as specified by RFC 8439 */
#define CHACHA20_BLOCK_SIZE 64

/*
 * Generate one 64-byte keystream block for the given key, counter and nonce.
 * Exposed mainly so the self-test can check it against the RFC's published
 * block vector; normal callers want chacha20_xor below.
 */
void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                    uint32_t counter,
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint8_t out[CHACHA20_BLOCK_SIZE]);

/*
 * Encrypt OR decrypt `len` bytes from `in` into `out`.
 * One function serves both directions because XOR is its own inverse - running
 * it twice with the same key and nonce returns the original data.
 */
void chacha20_xor(const uint8_t key[CHACHA20_KEY_SIZE],
                  uint32_t counter,
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  const uint8_t *in, uint8_t *out, size_t len);

#endif /* CHACHA20_H */
