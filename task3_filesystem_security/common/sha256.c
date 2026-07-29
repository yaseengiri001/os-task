/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Shared crypto module - implementation
 * -----------------------------------------------------------------------------
 * HOW SHA-256 WORKS (the short version)
 *   The message is padded and split into 512-bit blocks. Eight 32-bit working
 *   words are set to fixed constants, then each block is mixed into them over
 *   64 rounds using bitwise rotations, XORs and additions. The final value of
 *   those eight words is the digest.
 *
 *   The design goals are: any change to the input changes about half the output
 *   bits (the avalanche effect), and the process cannot be run backwards to
 *   recover the input.
 *
 * WHERE THE MAGIC NUMBERS COME FROM
 *   They are not arbitrary, and that matters for trust. The initial state is
 *   the first 32 bits of the fractional parts of the square roots of the first
 *   8 primes; the 64 round constants use the cube roots of the first 64 primes.
 *   Numbers with an obvious, checkable origin like this are called
 *   "nothing-up-my-sleeve" numbers: they demonstrate that the designer did not
 *   secretly choose values that create a hidden weakness.
 * -----------------------------------------------------------------------------
 */

#include "sha256.h"
#include <string.h>

/* ---- the six logical functions defined by FIPS 180-4 --------------------- */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))          /* choose          */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) /* majority    */
#define EP0(x)  (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)  (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* Round constants: first 32 bits of the fractional parts of the cube roots
   of the first 64 primes (2, 3, 5, 7, ...). */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Compress one 512-bit block into the running state. This is the heart of the
 * algorithm; everything else is buffering and padding.
 */
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    /* Words 0-15 are the block itself, read as big-endian 32-bit integers. */
    for (int i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t)data[j]     << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] <<  8) |  (uint32_t)data[j + 3];

    /* Words 16-63 are derived by the message schedule, which spreads each
       input bit's influence across the whole block. */
    for (int i = 16; i < 64; i++)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* Feed-forward: adding the old state back is what makes the compression
       function one-way. Without it the rounds could simply be reversed. */
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->buflen = 0;
    ctx->bitlen = 0;
    /* First 32 bits of the fractional parts of the square roots of the first
       8 primes - see the note on nothing-up-my-sleeve numbers above. */
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    /* Buffer input until a whole 64-byte block is available, then compress. */
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->buflen++] = data[i];
        if (ctx->buflen == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    size_t i = ctx->buflen;

    /* PADDING. Append a single 1 bit (the byte 0x80), then zeros, then the
       original message length as a 64-bit big-endian count of BITS.
       Including the length is what stops two different messages from sharing
       a padded form (a length-extension style ambiguity).                    */
    ctx->buffer[i++] = 0x80;
    if (i > 56) {                       /* no room for the length - pad out
                                           this block and start another      */
        while (i < SHA256_BLOCK_SIZE) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        i = 0;
    }
    while (i < 56) ctx->buffer[i++] = 0x00;

    ctx->bitlen += (uint64_t)ctx->buflen * 8;
    for (int b = 7; b >= 0; b--)
        ctx->buffer[56 + (7 - b)] = (uint8_t)(ctx->bitlen >> (b * 8));
    sha256_transform(ctx, ctx->buffer);

    /* Output the state as big-endian bytes. */
    for (int j = 0; j < 8; j++)
        for (int b = 0; b < 4; b++)
            digest[j * 4 + b] = (uint8_t)(ctx->state[j] >> (24 - b * 8));
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

void hex_encode(const uint8_t *data, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/*
 * HMAC-SHA256 = H((key XOR opad) || H((key XOR ipad) || message))
 *
 * The two-pass construction is not decoration. Simply hashing key||message
 * would be vulnerable to a LENGTH-EXTENSION attack: because SHA-256 exposes
 * its internal state as the digest, an attacker who has a valid tag can append
 * data and compute a valid tag for the longer message without knowing the key.
 * The outer hash hides that state and prevents it.
 */
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen,
                 uint8_t out[SHA256_DIGEST_SIZE])
{
    uint8_t k[SHA256_BLOCK_SIZE]  = {0};
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    uint8_t inner[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;

    /* Keys longer than one block are hashed down first; shorter keys are
       zero-padded (that is what the {0} initialiser above does). */
    if (keylen > SHA256_BLOCK_SIZE) sha256(key, keylen, k);
    else                            memcpy(k, key, keylen);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = H(ipad || message) */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, inner);

    /* out = H(opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}

/*
 * PBKDF2 with HMAC-SHA256 as the underlying function.
 *
 * For each output block i:
 *     U1 = HMAC(password, salt || i)
 *     U2 = HMAC(password, U1) ... and so on, `iterations` times
 *     block = U1 XOR U2 XOR ... XOR Un
 *
 * The chain is deliberately serial - each step needs the previous one - so it
 * cannot be parallelised away. That is the entire point: it makes every guess
 * an attacker tries cost the same real time it costs us once at login.
 */
void pbkdf2_hmac_sha256(const char *password,
                        const uint8_t *salt, size_t saltlen,
                        uint32_t iterations,
                        uint8_t *out, size_t outlen)
{
    uint8_t  u[SHA256_DIGEST_SIZE], t[SHA256_DIGEST_SIZE];
    uint8_t  block_input[128];
    size_t   pwlen  = strlen(password);
    uint32_t blocks = (uint32_t)((outlen + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE);
    size_t   done   = 0;

    for (uint32_t i = 1; i <= blocks; i++) {
        /* First iteration hashes salt || big-endian block index. */
        size_t n = (saltlen < sizeof(block_input) - 4) ? saltlen
                                                       : sizeof(block_input) - 4;
        memcpy(block_input, salt, n);
        block_input[n + 0] = (uint8_t)(i >> 24);
        block_input[n + 1] = (uint8_t)(i >> 16);
        block_input[n + 2] = (uint8_t)(i >>  8);
        block_input[n + 3] = (uint8_t)(i);

        hmac_sha256((const uint8_t *)password, pwlen, block_input, n + 4, u);
        memcpy(t, u, SHA256_DIGEST_SIZE);

        /* Remaining iterations chain and accumulate by XOR. */
        for (uint32_t j = 1; j < iterations; j++) {
            hmac_sha256((const uint8_t *)password, pwlen, u, SHA256_DIGEST_SIZE, u);
            for (int b = 0; b < SHA256_DIGEST_SIZE; b++) t[b] ^= u[b];
        }

        size_t take = (outlen - done < SHA256_DIGEST_SIZE) ? outlen - done
                                                           : SHA256_DIGEST_SIZE;
        memcpy(out + done, t, take);
        done += take;
    }
}

/*
 * Constant-time comparison. The loop ORs together the differences of every
 * byte pair and only checks the result at the very end, so the running time
 * does not depend on WHERE the first difference is. Using memcmp here would
 * leak that position through timing and allow a secret to be guessed one byte
 * at a time.
 */
int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}
