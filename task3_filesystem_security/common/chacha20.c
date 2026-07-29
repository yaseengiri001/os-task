/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * ChaCha20 stream cipher - implementation (RFC 8439)
 * -----------------------------------------------------------------------------
 * THE STATE
 *   ChaCha20 works on sixteen 32-bit words laid out as a 4x4 matrix:
 *
 *       +----------+----------+----------+----------+
 *       | constant | constant | constant | constant |   fixed "expand 32-byte k"
 *       +----------+----------+----------+----------+
 *       |   key    |   key    |   key    |   key    |   256-bit key
 *       +----------+----------+----------+----------+
 *       |   key    |   key    |   key    |   key    |
 *       +----------+----------+----------+----------+
 *       | counter  |  nonce   |  nonce   |  nonce   |   block counter + 96-bit nonce
 *       +----------+----------+----------+----------+
 *
 *   The four constants are simply the ASCII of "expand 32-byte k". They are
 *   public and fixed; their job is to ensure part of the state is never under
 *   an attacker's control.
 *
 * THE QUARTER ROUND
 *   All the mixing is built from one operation applied to four words:
 *
 *       a += b;  d ^= a;  d <<<= 16;
 *       c += d;  b ^= c;  b <<<= 12;
 *       a += b;  d ^= a;  d <<<=  8;
 *       c += d;  b ^= c;  b <<<=  7;
 *
 *   Only Addition, Rotation and XOR are used - a design known as ARX. Because
 *   there are no lookup tables, execution time does not depend on the key, so
 *   the cipher is naturally immune to the cache-timing attacks that affect
 *   table-driven AES implementations.
 *
 *   Twenty rounds are applied as ten "double rounds": four quarter rounds down
 *   the COLUMNS, then four along the DIAGONALS. Alternating the two patterns is
 *   what spreads every input bit across the whole state within a few rounds.
 * -----------------------------------------------------------------------------
 */

#include "chacha20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d)          \
    a += b; d ^= a; d = ROTL32(d, 16);    \
    c += d; b ^= c; b = ROTL32(b, 12);    \
    a += b; d ^= a; d = ROTL32(d,  8);    \
    c += d; b ^= c; b = ROTL32(b,  7);

/* Read four bytes as a little-endian 32-bit word. Doing this explicitly rather
   than casting a pointer keeps the code correct on big-endian machines too. */
static uint32_t load32_le(const uint8_t *p)
{
    return  (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
}

void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                    uint32_t counter,
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint8_t out[CHACHA20_BLOCK_SIZE])
{
    uint32_t state[16], working[16];

    /* Row 0: the ASCII of "expand 32-byte k", as little-endian words. */
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;

    /* Rows 1-2: the 256-bit key. */
    for (int i = 0; i < 8; i++) state[4 + i] = load32_le(key + i * 4);

    /* Row 3: block counter, then the 96-bit nonce. */
    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    memcpy(working, state, sizeof(state));

    /* 20 rounds = 10 double rounds (columns, then diagonals). */
    for (int i = 0; i < 10; i++) {
        /* column rounds */
        QUARTERROUND(working[0], working[4], working[ 8], working[12])
        QUARTERROUND(working[1], working[5], working[ 9], working[13])
        QUARTERROUND(working[2], working[6], working[10], working[14])
        QUARTERROUND(working[3], working[7], working[11], working[15])
        /* diagonal rounds */
        QUARTERROUND(working[0], working[5], working[10], working[15])
        QUARTERROUND(working[1], working[6], working[11], working[12])
        QUARTERROUND(working[2], working[7], working[ 8], working[13])
        QUARTERROUND(working[3], working[4], working[ 9], working[14])
    }

    /*
     * Add the ORIGINAL state back into the scrambled one before output. This
     * matters: the 20 rounds are individually reversible, so without this step
     * an attacker who saw a keystream block could run the rounds backwards and
     * recover the key. The addition destroys that invertibility.
     */
    for (int i = 0; i < 16; i++)
        store32_le(out + i * 4, working[i] + state[i]);
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY_SIZE],
                  uint32_t counter,
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    size_t  done = 0;

    /* Produce the keystream one 64-byte block at a time, incrementing the
       counter so every block differs, and XOR it over the data. The final
       block is simply used partially - a stream cipher needs no padding, so
       the ciphertext is always exactly as long as the plaintext. */
    while (done < len) {
        chacha20_block(key, counter, nonce, keystream);

        size_t chunk = len - done;
        if (chunk > CHACHA20_BLOCK_SIZE) chunk = CHACHA20_BLOCK_SIZE;

        for (size_t i = 0; i < chunk; i++)
            out[done + i] = in[done + i] ^ keystream[i];

        done += chunk;
        counter++;
    }
}
