/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Part 4 of 5: Encryption and decryption of sensitive files
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 3.1(4): "Encryption/decryption capability for sensitive files."
 *
 * WHY ENCRYPTION IS NEEDED AT ALL WHEN PERMISSIONS EXIST
 *   Part 3's permission bits are enforced by the KERNEL, so they only hold
 *   while that kernel is in charge. They protect nothing against someone who:
 *       - removes the disk and reads it on another machine,
 *       - boots from a USB stick,
 *       - restores an unencrypted backup,
 *       - or simply has root on the system.
 *   Encryption moves the protection from the operating system into the DATA
 *   itself, so it survives all of those. Permissions and encryption are
 *   complementary layers, not alternatives.
 *
 * WHAT THIS IMPLEMENTS
 *   ChaCha20 for confidentiality + HMAC-SHA256 for integrity, with the file key
 *   derived from a password using PBKDF2. This is a standard authenticated
 *   encryption construction.
 *
 * WHY INTEGRITY IS NOT OPTIONAL
 *   A stream cipher hides content but does nothing to stop MODIFICATION.
 *   Because ciphertext = plaintext XOR keystream, flipping a bit of ciphertext
 *   flips exactly that bit of the decrypted plaintext. An attacker who cannot
 *   read a file can still make targeted changes to it - turning "transfer 100"
 *   into "transfer 900" without ever knowing the key. A MAC is what detects
 *   this. Encryption alone provides secrecy, never trustworthiness.
 *
 * ENCRYPT-THEN-MAC, AND WHY THAT ORDER
 *   The MAC is computed over the CIPHERTEXT, and it is verified BEFORE any
 *   decryption is attempted. The alternative orders (MAC-then-encrypt,
 *   encrypt-and-MAC) require touching attacker-controlled data before it has
 *   been authenticated, which is what made padding-oracle attacks possible
 *   against SSL/TLS. Encrypt-then-MAC is the order proven secure in general.
 *
 * THE FILE FORMAT
 *       magic  4 bytes   "SFV1", so the format is identifiable
 *       salt  16 bytes   random per file - makes the derived key unique
 *       nonce 12 bytes   random per file - see the warning below
 *       data   n bytes   ciphertext, exactly as long as the plaintext
 *       tag   32 bytes   HMAC-SHA256 over magic || salt || nonce || data
 *
 *   The salt and nonce are stored in the clear. Neither is secret; they only
 *   have to be UNIQUE. Storing them is what lets the file be decrypted later
 *   from the password alone.
 *
 * THE ONE RULE THAT MUST NEVER BE BROKEN
 *   Never encrypt two different files with the same key AND nonce. Doing so
 *   reuses the keystream, and XORing the two ciphertexts cancels it out
 *   entirely, leaving the XOR of the two plaintexts - attackable with no key
 *   at all. This is the flaw that broke WEP Wi-Fi. A fresh random salt and
 *   nonce are therefore generated for EVERY file written.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include "../common/sha256.h"
#include "../common/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define MAGIC          "SFV1"
#define MAGIC_LEN      4
#define SALT_LEN       16
#define NONCE_LEN      CHACHA20_NONCE_SIZE   /* 12 */
#define TAG_LEN        SHA256_DIGEST_SIZE    /* 32 */
#define HEADER_LEN     (MAGIC_LEN + SALT_LEN + NONCE_LEN)
#define KDF_ROUNDS     200000
#define MAX_FILE       8192

/* Two independent keys are derived from the password in one pass: one for the
   cipher and one for the MAC. Using the SAME key for both would let the two
   primitives interact in ways neither was analysed for, so they are always
   separated. */
#define KEY_MATERIAL   (CHACHA20_KEY_SIZE + 32)

static int secure_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) { close(fd); return -1; }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

/*
 * Encrypt `plaintext` into `outfile` under `password`.
 * Returns the number of bytes written, or -1.
 */
static long encrypt_file(const char *outfile, const char *password,
                         const uint8_t *plaintext, size_t ptlen)
{
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    uint8_t keys[KEY_MATERIAL];
    uint8_t buffer[MAX_FILE];

    if (ptlen + HEADER_LEN + TAG_LEN > MAX_FILE) {
        printf("    file too large for this demonstration buffer\n");
        return -1;
    }

    /* A fresh salt and nonce for THIS file - never reused. */
    if (secure_random(salt, SALT_LEN) != 0 ||
        secure_random(nonce, NONCE_LEN) != 0) {
        printf("    no secure randomness available\n");
        return -1;
    }

    /* One slow derivation produces both keys. */
    pbkdf2_hmac_sha256(password, salt, SALT_LEN, KDF_ROUNDS, keys, KEY_MATERIAL);
    const uint8_t *cipher_key = keys;
    const uint8_t *mac_key    = keys + CHACHA20_KEY_SIZE;

    /* Lay out the header. */
    size_t off = 0;
    memcpy(buffer + off, MAGIC, MAGIC_LEN);   off += MAGIC_LEN;
    memcpy(buffer + off, salt,  SALT_LEN);    off += SALT_LEN;
    memcpy(buffer + off, nonce, NONCE_LEN);   off += NONCE_LEN;

    /* Encrypt. Counter starts at 1, following RFC 8439's convention of
       reserving block 0 for other uses. */
    chacha20_xor(cipher_key, 1, nonce, plaintext, buffer + off, ptlen);
    off += ptlen;

    /* ENCRYPT-THEN-MAC: authenticate the header and ciphertext together.
       Covering the header too stops an attacker swapping the stored nonce,
       which would otherwise change how the file decrypts. */
    hmac_sha256(mac_key, 32, buffer, off, buffer + off);
    off += TAG_LEN;

    int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("    cannot write %s: %s\n", outfile, strerror(errno));
        return -1;
    }
    if (write(fd, buffer, off) != (ssize_t)off) {
        close(fd);
        return -1;
    }
    close(fd);
    return (long)off;
}

/*
 * Decrypt `infile` under `password` into `out`.
 * Returns the plaintext length, or -1 if authentication fails.
 */
static long decrypt_file(const char *infile, const char *password,
                         uint8_t *out, size_t outsz)
{
    uint8_t buffer[MAX_FILE];
    uint8_t keys[KEY_MATERIAL];
    uint8_t expected_tag[TAG_LEN];

    int fd = open(infile, O_RDONLY);
    if (fd < 0) {
        printf("    cannot read %s: %s\n", infile, strerror(errno));
        return -1;
    }
    ssize_t total = read(fd, buffer, sizeof(buffer));
    close(fd);

    if (total < (ssize_t)(HEADER_LEN + TAG_LEN)) {
        printf("    REJECTED: file is too short to be valid\n");
        return -1;
    }
    if (memcmp(buffer, MAGIC, MAGIC_LEN) != 0) {
        printf("    REJECTED: wrong magic - not a file this tool wrote\n");
        return -1;
    }

    const uint8_t *salt  = buffer + MAGIC_LEN;
    const uint8_t *nonce = buffer + MAGIC_LEN + SALT_LEN;
    size_t ctlen = (size_t)total - HEADER_LEN - TAG_LEN;

    if (ctlen > outsz) {
        printf("    REJECTED: plaintext would not fit in the output buffer\n");
        return -1;
    }

    pbkdf2_hmac_sha256(password, salt, SALT_LEN, KDF_ROUNDS, keys, KEY_MATERIAL);
    const uint8_t *cipher_key = keys;
    const uint8_t *mac_key    = keys + CHACHA20_KEY_SIZE;

    /*
     * VERIFY BEFORE DECRYPTING. Nothing derived from the file is used until
     * the tag proves it is exactly what we wrote. Decrypting first and
     * checking afterwards is the mistake that padding-oracle attacks exploit.
     *
     * The comparison is constant-time so that a near-miss tag cannot be
     * distinguished from a wildly wrong one by timing.
     */
    hmac_sha256(mac_key, 32, buffer, (size_t)total - TAG_LEN, expected_tag);
    if (!constant_time_equal(expected_tag, buffer + total - TAG_LEN, TAG_LEN)) {
        printf("    AUTHENTICATION FAILED - wrong password, or the file was\n");
        printf("    altered. Nothing was decrypted.\n");
        return -1;
    }

    chacha20_xor(cipher_key, 1, nonce, buffer + HEADER_LEN, out, ctlen);
    return (long)ctlen;
}

/* Print the first `n` bytes of a file as hex, to show what is on disk. */
static void show_file_hex(const char *path, int n)
{
    uint8_t buf[64];
    char    hex[160];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    ssize_t got = read(fd, buf, (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf));
    close(fd);
    if (got <= 0) return;
    hex_encode(buf, (size_t)got, hex);
    printf("    on disk: %s...\n", hex);
}

/* ---- The contrast: why a Caesar cipher is not encryption ---------------- */

static void caesar(const char *in, char *out, int shift)
{
    int i = 0;
    for (; in[i]; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z')      out[i] = (char)('a' + (c - 'a' + shift + 26) % 26);
        else if (c >= 'A' && c <= 'Z') out[i] = (char)('A' + (c - 'A' + shift + 26) % 26);
        else                            out[i] = c;
    }
    out[i] = '\0';
}

/*
 * Break a Caesar cipher without the key, by frequency analysis.
 * English text is about 12% 'e', so whichever letter is commonest in the
 * ciphertext is almost always an enciphered 'e', which reveals the shift.
 */
static void break_caesar(const char *ciphertext)
{
    int counts[26] = {0};
    for (const char *p = ciphertext; *p; p++) {
        char c = *p;
        if (c >= 'a' && c <= 'z') counts[c - 'a']++;
        else if (c >= 'A' && c <= 'Z') counts[c - 'A']++;
    }
    int best = 0;
    for (int i = 1; i < 26; i++) if (counts[i] > counts[best]) best = i;

    int guessed_shift = (best - ('e' - 'a') + 26) % 26;
    char recovered[512];
    caesar(ciphertext, recovered, -guessed_shift);

    printf("    commonest letter is '%c' -> assume it enciphers 'e'\n", 'a' + best);
    printf("    deduced shift: %d\n", guessed_shift);
    printf("    recovered:  \"%s\"\n", recovered);
}

int main(void)
{
    const char *password = "a-strong-file-password";
    const char *secret   = "SALARY REPORT (CONFIDENTIAL)\n"
                           "alice  62000\n"
                           "bob    58000\n";
    uint8_t recovered[MAX_FILE];

    printf("=== Encryption and decryption of sensitive files ===\n");
    printf("Requirement 3.1(4)\n\n");
    printf("Construction: ChaCha20 (confidentiality) + HMAC-SHA256 (integrity),\n");
    printf("key derived by PBKDF2-HMAC-SHA256 with %d rounds.\n\n", KDF_ROUNDS);

    /* ---- 1. Encrypt ------------------------------------------------------ */
    printf("1. Encrypting a sensitive file\n");
    printf("    plaintext (%zu bytes):\n----\n%s----\n", strlen(secret), secret);

    long written = encrypt_file("salary.enc", password,
                                (const uint8_t *)secret, strlen(secret));
    if (written < 0) return EXIT_FAILURE;
    printf("    wrote salary.enc: %ld bytes "
           "(%d header + %zu ciphertext + %d tag)\n",
           written, HEADER_LEN, strlen(secret), TAG_LEN);
    show_file_hex("salary.enc", 32);
    printf("    The plaintext is not recoverable from that without the key.\n\n");

    /* ---- 2. Decrypt ------------------------------------------------------ */
    printf("2. Decrypting with the correct password\n");
    long len = decrypt_file("salary.enc", password, recovered, sizeof(recovered));
    if (len >= 0) {
        recovered[len] = '\0';
        printf("    recovered %ld bytes:\n----\n%s----\n", len, (char *)recovered);
        printf("    round trip %s\n",
               (len == (long)strlen(secret) &&
                memcmp(recovered, secret, (size_t)len) == 0)
                   ? "EXACT - byte-for-byte identical to the original"
                   : "MISMATCH");
    }
    printf("\n");

    /* ---- 3. Wrong password ----------------------------------------------- */
    printf("3. Decrypting with the WRONG password\n");
    decrypt_file("salary.enc", "not-the-password", recovered, sizeof(recovered));
    printf("    Note the failure is reported by the MAC check, so no incorrect\n");
    printf("    plaintext is ever produced or acted upon.\n\n");

    /* ---- 4. Tampering ---------------------------------------------------- */
    printf("4. Tamper detection: flipping a single bit of the ciphertext\n");
    {
        int fd = open("salary.enc", O_RDWR);
        if (fd >= 0) {
            uint8_t byte;
            off_t target = HEADER_LEN + 5;      /* somewhere in the ciphertext */
            pread(fd, &byte, 1, target);
            printf("    byte %ld: 0x%02x -> 0x%02x (one bit changed)\n",
                   (long)target, byte, byte ^ 0x01);
            byte ^= 0x01;
            pwrite(fd, &byte, 1, target);
            close(fd);
        }
        decrypt_file("salary.enc", password, recovered, sizeof(recovered));
        printf("    Without the MAC this would have silently decrypted to text\n");
        printf("    with one bit changed - a targeted edit by someone who could\n");
        printf("    not read the file. The MAC is what makes that detectable.\n\n");

        /* put it back so the file is left valid */
        int fd2 = open("salary.enc", O_RDWR);
        if (fd2 >= 0) {
            uint8_t byte;
            off_t target = HEADER_LEN + 5;
            pread(fd2, &byte, 1, target);
            byte ^= 0x01;
            pwrite(fd2, &byte, 1, target);
            close(fd2);
        }
    }

    /* ---- 5. Fresh nonce per file ----------------------------------------- */
    printf("5. The SAME plaintext encrypted twice must look different\n");
    encrypt_file("same_a.enc", password, (const uint8_t *)secret, strlen(secret));
    encrypt_file("same_b.enc", password, (const uint8_t *)secret, strlen(secret));
    show_file_hex("same_a.enc", 24);
    show_file_hex("same_b.enc", 24);
    {
        uint8_t a[MAX_FILE], b[MAX_FILE];
        int fa = open("same_a.enc", O_RDONLY), fb = open("same_b.enc", O_RDONLY);
        ssize_t na = read(fa, a, sizeof(a)), nb = read(fb, b, sizeof(b));
        close(fa); close(fb);
        printf("    identical ciphertext? %s\n",
               (na == nb && memcmp(a, b, (size_t)na) == 0)
                   ? "YES - keystream reuse, a serious flaw"
                   : "NO - each file used a fresh random salt and nonce");
        printf("    This is what prevents the keystream-reuse attack that broke\n");
        printf("    WEP: without it, XORing two ciphertexts would cancel the\n");
        printf("    keystream and expose both plaintexts.\n\n");
    }

    /* ---- 6. The contrast with a classical cipher ------------------------- */
    printf("6. For contrast: why a Caesar cipher is not encryption\n");
    {
        const char *msg = "the salary figures must remain confidential and "
                          "should never be revealed to anyone outside finance";
        char enciphered[512];
        caesar(msg, enciphered, 3);
        printf("    plaintext:  \"%.52s...\"\n", msg);
        printf("    shifted +3: \"%.52s...\"\n", enciphered);
        printf("    Breaking it WITHOUT the key, by frequency analysis alone:\n");
        break_caesar(enciphered);
        printf("    Recovered in microseconds, with no key and no guessing. A\n");
        printf("    Caesar cipher has 25 possible keys and preserves letter\n");
        printf("    frequencies, so it obscures text without protecting it.\n\n");
    }

    printf("Summary\n");
    printf("  Encryption defends data where permissions cannot: on a stolen\n");
    printf("  disk, in a backup, or against root. ChaCha20 provides the\n");
    printf("  confidentiality; HMAC-SHA256 provides the integrity WITHOUT which\n");
    printf("  a stream cipher can be edited bit-by-bit by an attacker who\n");
    printf("  cannot read it. The MAC is verified before anything is decrypted,\n");
    printf("  and every file gets a fresh salt and nonce.\n");

    /* tidy up the demonstration files */
    unlink("same_a.enc");
    unlink("same_b.enc");
    return EXIT_SUCCESS;
}
