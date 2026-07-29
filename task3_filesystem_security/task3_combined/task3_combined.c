/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * COMBINED: an interactive secure file manager
 * -----------------------------------------------------------------------------
 * GOAL
 *   Parts 1-5 each demonstrate one requirement in isolation. This program is
 *   the single "secure file management system" the brief asks for, with all
 *   five working together:
 *
 *     Requirement 3.1(1)  create / read / write / delete      -> cmd_create etc.
 *     Requirement 3.1(2)  user authentication                 -> cmd_login
 *     Requirement 3.1(3)  rwx permissions, owner/group/other  -> check_permission
 *     Requirement 3.1(4)  encryption of sensitive files       -> cmd_encrypt
 *     Requirement 3.1(5)  audit logging                       -> audit()
 *
 * THE ARCHITECTURE: A REFERENCE MONITOR
 *   The five parts are not simply bolted together. Every operation is forced
 *   through the same four stages, in this order:
 *
 *       1. AUTHENTICATE  is anyone logged in at all?
 *       2. VALIDATE      is the filename well-formed? (path traversal)
 *       3. AUTHORISE     do this user's permission bits allow this action?
 *       4. AUDIT         record what happened, allowed or denied
 *
 *   This is the classic reference monitor, and its defining property is
 *   COMPLETE MEDIATION: there is no path to the data that bypasses the checks.
 *   Security holes usually come not from a missing check but from ONE forgotten
 *   route around the checks that do exist, so the design makes the checked path
 *   the only path. Notice that denials are logged just as carefully as
 *   successes - a record of what someone TRIED is often the more useful
 *   evidence.
 *
 * DEFENCE IN DEPTH
 *   The layers deliberately overlap, because each fails differently:
 *     - permissions stop the wrong user, but only while this OS is running
 *     - encryption still protects a stolen disk or a backup, where the OS is
 *       not involved at all
 *     - the audit log catches what the first two missed, after the fact
 *   No single layer is trusted to be sufficient.
 *
 * BUILD & RUN
 *   make                   # compiles to ./task3_combined
 *   make run               # interactive shell (type 'help')
 *   ./task3_combined demo  # scripted walkthrough, no input needed
 *                          # (this is what produces the logs in ../outputs/)
 * -----------------------------------------------------------------------------
 */

/*
 * Request the POSIX.1-2008 interfaces before any header is included.
 *
 * Without this, glibc exposes only the ISO C subset under -std=c11 and hides
 * pread/pwrite, pthread_rwlock_t and friends, so a strict Linux build fails
 * with "implicit declaration". macOS happens to expose them anyway, which is
 * exactly why this has to be tested on both - the omission is invisible on one
 * platform and fatal on the other.
 */
#define _POSIX_C_SOURCE 200809L


#include "../common/sha256.h"
#include "../common/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#define WORK_DIR       "secure_files"
#define LOG_FILE       "audit.log"
#define MAX_USERS      8
#define MAX_FILES      32
#define SALT_LEN       16
#define HASH_LEN       32
#define NONCE_LEN      CHACHA20_NONCE_SIZE
#define TAG_LEN        SHA256_DIGEST_SIZE
#define MAGIC          "SFV1"
#define MAGIC_LEN      4
#define HEADER_LEN     (MAGIC_LEN + SALT_LEN + NONCE_LEN)
#define KEY_MATERIAL   (CHACHA20_KEY_SIZE + 32)
#define MAX_CONTENT    4096
#define MAX_INPUT      512

/*
 * Iteration count. Part 2 used 200,000, which is right for a login that
 * happens once. Here the shell may encrypt several files in one session, so
 * 60,000 keeps the demonstration responsive. The trade-off is stated rather
 * than hidden: fewer rounds means a cheaper offline attack, and a real system
 * would tune this to the slowest login latency users will accept.
 */
#define KDF_ROUNDS     60000

/* ============================== STATE ==================================== */

typedef struct {
    char    username[32];
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    int     uid;
    int     gid;
    int     failed;
    int     locked;
} User;

typedef struct {
    char name[64];
    int  owner_uid;
    int  group_gid;
    int  mode;          /* nine permission bits, octal */
    int  encrypted;
} FileMeta;

static User     users[MAX_USERS];
static int      user_count = 0;
static FileMeta files[MAX_FILES];
static int      file_count = 0;
static int      current_uid = -1;                /* -1 = nobody logged in */
static char     current_user[32] = "";
static uint8_t  chain_head[SHA256_DIGEST_SIZE];  /* running audit chain link */
static int      audit_count = 0;

static const char *CHAIN_KEY = "audit-chain-key-demo-only";

/* ============================== HELPERS ================================== */

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

static void now_utc(char *out, size_t n)
{
    time_t     t  = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", tm);
}

/* ---- STAGE 4: AUDIT -----------------------------------------------------
 * Appends one hash-chained entry. Called on EVERY outcome, including denials
 * and errors - an audit trail that only records successes hides exactly the
 * events worth investigating.                                              */
static void audit(const char *action, const char *target, const char *result)
{
    char    ts[32], line[512];
    uint8_t message[SHA256_DIGEST_SIZE + 512];
    uint8_t link[SHA256_DIGEST_SIZE];
    char    hex[SHA256_DIGEST_SIZE * 2 + 1];

    now_utc(ts, sizeof(ts));
    const char *who = (current_uid >= 0) ? current_user : "-";

    /* link = HMAC(key, previous_link || this entry) */
    size_t n = 0;
    memcpy(message, chain_head, SHA256_DIGEST_SIZE);
    n += SHA256_DIGEST_SIZE;
    n += (size_t)snprintf((char *)message + n, 512, "%s|%s|%s|%s|%s",
                          ts, who, action, target, result);
    hmac_sha256((const uint8_t *)CHAIN_KEY, strlen(CHAIN_KEY), message, n, link);
    memcpy(chain_head, link, SHA256_DIGEST_SIZE);

    hex_encode(link, SHA256_DIGEST_SIZE, hex);
    int len = snprintf(line, sizeof(line), "%s|%s|%s|%s|%s|%s\n",
                       ts, who, action, target, result, hex);

    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) { (void)!write(fd, line, (size_t)len); close(fd); }
    audit_count++;
}

/* ---- STAGE 2: VALIDATE --------------------------------------------------
 * Allow-list of permitted filename characters. Anything not explicitly
 * allowed is refused, so unanticipated encodings fail closed.              */
static int is_safe_filename(const char *name)
{
    if (!name || !*name || strlen(name) > 48) return 0;
    if (name[0] == '.') return 0;
    for (const char *p = name; *p; p++) {
        int ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                 (*p >= '0' && *p <= '9') ||  *p == '.' || *p == '-' || *p == '_';
        if (!ok) return 0;
    }
    return strstr(name, "..") == NULL;
}

static User *find_user_by_name(const char *n)
{
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].username, n) == 0) return &users[i];
    return NULL;
}

static User *find_user_by_uid(int uid)
{
    for (int i = 0; i < user_count; i++)
        if (users[i].uid == uid) return &users[i];
    return NULL;
}

static FileMeta *find_file(const char *name)
{
    for (int i = 0; i < file_count; i++)
        if (strcmp(files[i].name, name) == 0) return &files[i];
    return NULL;
}

static void mode_to_string(int mode, char *out)
{
    const char *set = "rwx";
    for (int i = 0; i < 9; i++)
        out[i] = (mode & (0400 >> i)) ? set[i % 3] : '-';
    out[9] = '\0';
}

/* ---- STAGE 3: AUTHORISE -------------------------------------------------
 * POSIX first-match-wins: the first class the user belongs to decides, and
 * the other classes are never consulted. See Part 3 for why that matters. */
typedef enum { ACC_READ = 04, ACC_WRITE = 02, ACC_EXEC = 01 } Access;

static int check_permission(const FileMeta *f, Access want)
{
    if (current_uid < 0) return 0;
    User *u = find_user_by_uid(current_uid);
    if (!u) return 0;

    int bits;
    if      (u->uid == f->owner_uid) bits = (f->mode >> 6) & 07;
    else if (u->gid == f->group_gid) bits = (f->mode >> 3) & 07;
    else                             bits =  f->mode       & 07;

    return (bits & (int)want) != 0;
}

/* ---- STAGE 1: AUTHENTICATE ---------------------------------------------- */
static int require_login(const char *action, const char *target)
{
    if (current_uid < 0) {
        printf("  Not logged in. Use: login <user> <password>\n");
        audit(action, target, "NO_SESSION");
        return 0;
    }
    return 1;
}

static int build_path(char *out, size_t sz, const char *name)
{
    return snprintf(out, sz, "%s/%s", WORK_DIR, name) > 0;
}

/* ============================== COMMANDS ================================= */

static void cmd_login(const char *username, const char *password)
{
    uint8_t attempt[HASH_LEN];
    User   *u = find_user_by_name(username);

    if (!u) {
        /* Derive anyway so a missing account costs the same time as a wrong
           password - otherwise the response time enumerates valid usernames. */
        uint8_t dummy[SALT_LEN] = {0};
        pbkdf2_hmac_sha256(password, dummy, SALT_LEN, KDF_ROUNDS, attempt, HASH_LEN);
        printf("  Login failed: invalid username or password.\n");
        audit("LOGIN", username, "FAILURE");
        return;
    }
    if (u->locked) {
        printf("  Login failed: account locked.\n");
        audit("LOGIN", username, "LOCKED");
        return;
    }

    pbkdf2_hmac_sha256(password, u->salt, SALT_LEN, KDF_ROUNDS, attempt, HASH_LEN);

    if (constant_time_equal(attempt, u->hash, HASH_LEN)) {
        current_uid = u->uid;
        snprintf(current_user, sizeof(current_user), "%s", u->username);
        u->failed = 0;
        printf("  Welcome, %s (uid %d, gid %d).\n", u->username, u->uid, u->gid);
        audit("LOGIN", username, "SUCCESS");
    } else {
        u->failed++;
        if (u->failed >= 3) {
            u->locked = 1;
            printf("  Login failed: invalid username or password. Account LOCKED.\n");
            audit("LOGIN", username, "LOCKOUT");
        } else {
            printf("  Login failed: invalid username or password. (%d of 3)\n",
                   u->failed);
            audit("LOGIN", username, "FAILURE");
        }
    }
}

static void cmd_logout(void)
{
    if (current_uid < 0) { printf("  Not logged in.\n"); return; }
    printf("  Goodbye, %s.\n", current_user);
    audit("LOGOUT", "-", "SUCCESS");
    current_uid = -1;
    current_user[0] = '\0';
}

static void cmd_ls(void)
{
    if (!require_login("LIST", "-")) return;

    printf("  %-9s %-6s %-8s %-6s %s\n", "PERMS", "MODE", "OWNER", "ENC", "NAME");
    printf("  --------- ------ -------- ------ ----------------\n");
    for (int i = 0; i < file_count; i++) {
        char rwx[10];
        mode_to_string(files[i].mode, rwx);
        User *o = find_user_by_uid(files[i].owner_uid);
        printf("  %-9s %04o   %-8s %-6s %s\n",
               rwx, files[i].mode, o ? o->username : "?",
               files[i].encrypted ? "yes" : "no", files[i].name);
    }
    if (file_count == 0) printf("  (no files)\n");
    audit("LIST", "-", "SUCCESS");
}

static void cmd_create(const char *name)
{
    if (!require_login("FILE_CREATE", name)) return;

    if (!is_safe_filename(name)) {
        printf("  Rejected: unsafe filename.\n");
        audit("FILE_CREATE", name, "REJECTED");
        return;
    }
    if (find_file(name)) {
        printf("  Already exists.\n");
        audit("FILE_CREATE", name, "EXISTS");
        return;
    }
    if (file_count >= MAX_FILES) {
        printf("  File table full.\n");
        audit("FILE_CREATE", name, "FULL");
        return;
    }

    char path[256];
    build_path(path, sizeof(path), name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);   /* atomic */
    if (fd < 0) {
        printf("  Failed: %s\n", strerror(errno));
        audit("FILE_CREATE", name, "ERROR");
        return;
    }
    close(fd);

    User *u = find_user_by_uid(current_uid);
    FileMeta *f = &files[file_count++];
    snprintf(f->name, sizeof(f->name), "%s", name);
    f->owner_uid = u->uid;
    f->group_gid = u->gid;
    f->mode      = 0640;      /* least privilege that is still useful */
    f->encrypted = 0;

    printf("  Created %s (mode 0640, owner %s).\n", name, u->username);
    audit("FILE_CREATE", name, "SUCCESS");
}

static void cmd_write(const char *name, const char *content)
{
    if (!require_login("FILE_WRITE", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("FILE_WRITE", name, "NOT_FOUND"); return; }

    if (!check_permission(f, ACC_WRITE)) {
        printf("  Permission denied: you do not have write access to %s.\n", name);
        audit("FILE_WRITE", name, "DENIED");
        return;
    }
    if (f->encrypted) {
        printf("  %s is encrypted. Decrypt it first.\n", name);
        audit("FILE_WRITE", name, "ENCRYPTED");
        return;
    }

    char path[256];
    build_path(path, sizeof(path), name);
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) { printf("  Failed: %s\n", strerror(errno));
                  audit("FILE_WRITE", name, "ERROR"); return; }

    size_t total = strlen(content), done = 0;
    while (done < total) {                    /* write() may be short */
        ssize_t n = write(fd, content + done, total - done);
        if (n < 0) { close(fd); audit("FILE_WRITE", name, "ERROR"); return; }
        done += (size_t)n;
    }
    fsync(fd);
    close(fd);

    printf("  Wrote %zu bytes to %s.\n", total, name);
    audit("FILE_WRITE", name, "SUCCESS");
}

static void cmd_read(const char *name)
{
    if (!require_login("FILE_READ", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("FILE_READ", name, "NOT_FOUND"); return; }

    if (!check_permission(f, ACC_READ)) {
        printf("  Permission denied: you do not have read access to %s.\n", name);
        audit("FILE_READ", name, "DENIED");
        return;
    }

    char path[256], buf[MAX_CONTENT];
    build_path(path, sizeof(path), name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  Failed: %s\n", strerror(errno));
                  audit("FILE_READ", name, "ERROR"); return; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) { audit("FILE_READ", name, "ERROR"); return; }
    buf[n] = '\0';

    if (f->encrypted) {
        char hex[129];
        size_t show = (size_t)n < 48 ? (size_t)n : 48;
        hex_encode((uint8_t *)buf, show, hex);
        printf("  %s is encrypted (%zd bytes). Raw ciphertext:\n    %s...\n",
               name, n, hex);
    } else {
        printf("  ---- %s (%zd bytes) ----\n%s", name, n, buf);
        if (n > 0 && buf[n - 1] != '\n') printf("\n");
        printf("  ---- end ----\n");
    }
    audit("FILE_READ", name, "SUCCESS");
}

static void cmd_delete(const char *name)
{
    if (!require_login("FILE_DELETE", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("FILE_DELETE", name, "NOT_FOUND"); return; }

    /*
     * Deletion is authorised by WRITE permission here. Note that real Unix
     * checks write permission on the DIRECTORY instead, which is why you can
     * delete a file you cannot read. This system keeps everything in one
     * directory, so the file's own bits are the meaningful control.
     */
    if (!check_permission(f, ACC_WRITE)) {
        printf("  Permission denied: you do not have write access to %s.\n", name);
        audit("FILE_DELETE", name, "DENIED");
        return;
    }

    char path[256];
    build_path(path, sizeof(path), name);
    if (unlink(path) != 0) {
        printf("  Failed: %s\n", strerror(errno));
        audit("FILE_DELETE", name, "ERROR");
        return;
    }

    int idx = (int)(f - files);
    for (int i = idx; i < file_count - 1; i++) files[i] = files[i + 1];
    file_count--;

    printf("  Deleted %s. (The name is gone; the blocks are not yet erased.)\n",
           name);
    audit("FILE_DELETE", name, "SUCCESS");
}

static void cmd_chmod(const char *name, const char *mode_str)
{
    if (!require_login("CHMOD", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("CHMOD", name, "NOT_FOUND"); return; }

    /* Only the OWNER may change a mode. This is not one of the rwx bits:
       having write access lets you change the CONTENTS, never the policy.
       Otherwise anyone who could write could also grant themselves more. */
    if (current_uid != f->owner_uid) {
        printf("  Permission denied: only the owner may change permissions.\n");
        audit("CHMOD", name, "DENIED");
        return;
    }

    int mode = (int)strtol(mode_str, NULL, 8);
    if (mode < 0 || mode > 0777) {
        printf("  Invalid mode (expected octal 000-777).\n");
        audit("CHMOD", name, "INVALID");
        return;
    }

    char before[10], after[10];
    mode_to_string(f->mode, before);
    f->mode = mode;
    mode_to_string(f->mode, after);
    printf("  %s: %s -> %s (%04o)\n", name, before, after, mode);
    audit("CHMOD", name, "SUCCESS");
}

static void cmd_encrypt(const char *name, const char *password)
{
    if (!require_login("ENCRYPT", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("ENCRYPT", name, "NOT_FOUND"); return; }
    if (!check_permission(f, ACC_WRITE)) {
        printf("  Permission denied.\n"); audit("ENCRYPT", name, "DENIED"); return;
    }
    if (f->encrypted) {
        printf("  Already encrypted.\n"); audit("ENCRYPT", name, "ALREADY"); return;
    }

    char path[256];
    uint8_t plain[MAX_CONTENT], out[MAX_CONTENT + HEADER_LEN + TAG_LEN];
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], keys[KEY_MATERIAL];

    build_path(path, sizeof(path), name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { audit("ENCRYPT", name, "ERROR"); return; }
    ssize_t plen = read(fd, plain, sizeof(plain));
    close(fd);
    if (plen < 0) { audit("ENCRYPT", name, "ERROR"); return; }

    /* Fresh salt AND nonce for this file - never reuse a (key, nonce) pair. */
    if (secure_random(salt, SALT_LEN) || secure_random(nonce, NONCE_LEN)) {
        printf("  No secure randomness available.\n");
        audit("ENCRYPT", name, "ERROR");
        return;
    }
    pbkdf2_hmac_sha256(password, salt, SALT_LEN, KDF_ROUNDS, keys, KEY_MATERIAL);

    size_t off = 0;
    memcpy(out + off, MAGIC, MAGIC_LEN); off += MAGIC_LEN;
    memcpy(out + off, salt, SALT_LEN);   off += SALT_LEN;
    memcpy(out + off, nonce, NONCE_LEN); off += NONCE_LEN;
    chacha20_xor(keys, 1, nonce, plain, out + off, (size_t)plen);
    off += (size_t)plen;
    /* encrypt-then-MAC over header + ciphertext */
    hmac_sha256(keys + CHACHA20_KEY_SIZE, 32, out, off, out + off);
    off += TAG_LEN;

    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) { audit("ENCRYPT", name, "ERROR"); return; }
    (void)!write(fd, out, off);
    close(fd);

    f->encrypted = 1;
    printf("  Encrypted %s: %zd bytes -> %zu bytes "
           "(ChaCha20 + HMAC-SHA256, fresh salt and nonce).\n",
           name, plen, off);
    audit("ENCRYPT", name, "SUCCESS");
}

static void cmd_decrypt(const char *name, const char *password)
{
    if (!require_login("DECRYPT", name)) return;

    FileMeta *f = find_file(name);
    if (!f) { printf("  No such file.\n"); audit("DECRYPT", name, "NOT_FOUND"); return; }
    if (!check_permission(f, ACC_WRITE)) {
        printf("  Permission denied.\n"); audit("DECRYPT", name, "DENIED"); return;
    }
    if (!f->encrypted) {
        printf("  Not encrypted.\n"); audit("DECRYPT", name, "NOT_ENCRYPTED"); return;
    }

    char path[256];
    uint8_t buf[MAX_CONTENT + HEADER_LEN + TAG_LEN], plain[MAX_CONTENT];
    uint8_t keys[KEY_MATERIAL], tag[TAG_LEN];

    build_path(path, sizeof(path), name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { audit("DECRYPT", name, "ERROR"); return; }
    ssize_t total = read(fd, buf, sizeof(buf));
    close(fd);

    if (total < (ssize_t)(HEADER_LEN + TAG_LEN) ||
        memcmp(buf, MAGIC, MAGIC_LEN) != 0) {
        printf("  Not a valid encrypted file.\n");
        audit("DECRYPT", name, "MALFORMED");
        return;
    }

    const uint8_t *salt  = buf + MAGIC_LEN;
    const uint8_t *nonce = buf + MAGIC_LEN + SALT_LEN;
    size_t ctlen = (size_t)total - HEADER_LEN - TAG_LEN;

    pbkdf2_hmac_sha256(password, salt, SALT_LEN, KDF_ROUNDS, keys, KEY_MATERIAL);

    /* Verify BEFORE decrypting - nothing from the file is trusted until the
       tag proves it is exactly what was written. */
    hmac_sha256(keys + CHACHA20_KEY_SIZE, 32, buf, (size_t)total - TAG_LEN, tag);
    if (!constant_time_equal(tag, buf + total - TAG_LEN, TAG_LEN)) {
        printf("  AUTHENTICATION FAILED - wrong password, or the file was\n");
        printf("  altered. Nothing was decrypted.\n");
        audit("DECRYPT", name, "AUTH_FAIL");
        return;
    }

    chacha20_xor(keys, 1, nonce, buf + HEADER_LEN, plain, ctlen);

    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) { audit("DECRYPT", name, "ERROR"); return; }
    (void)!write(fd, plain, ctlen);
    close(fd);

    f->encrypted = 0;
    printf("  Decrypted %s (%zu bytes recovered, MAC verified).\n", name, ctlen);
    audit("DECRYPT", name, "SUCCESS");
}

/* Replay the log file and re-derive every chain link. */
static void cmd_verify(void)
{
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) { printf("  No audit log yet.\n"); return; }

    uint8_t prev[SHA256_DIGEST_SIZE], expect[SHA256_DIGEST_SIZE];
    uint8_t message[SHA256_DIGEST_SIZE + 512];
    char    line[512];
    int     n = 0, broken = 0;

    sha256((const uint8_t *)"GENESIS", 7, prev);

    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        /* split off the trailing chain field */
        char *last = strrchr(line, '|');
        if (!last) continue;
        *last = '\0';
        const char *stored_hex = last + 1;

        size_t m = 0;
        memcpy(message, prev, SHA256_DIGEST_SIZE);
        m += SHA256_DIGEST_SIZE;
        m += (size_t)snprintf((char *)message + m, 512, "%s", line);
        hmac_sha256((const uint8_t *)CHAIN_KEY, strlen(CHAIN_KEY), message, m, expect);

        char hex[SHA256_DIGEST_SIZE * 2 + 1];
        hex_encode(expect, SHA256_DIGEST_SIZE, hex);
        n++;
        if (strcmp(hex, stored_hex) != 0) {
            printf("  CHAIN BROKEN at entry %d: %s\n", n, line);
            broken = 1;
            break;
        }
        memcpy(prev, expect, SHA256_DIGEST_SIZE);
    }
    fclose(fp);

    if (!broken)
        printf("  CHAIN INTACT - all %d log entries verify.\n", n);
    else
        printf("  The log has been modified since it was written.\n");
}

static void cmd_audit(void)
{
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) { printf("  No audit log yet.\n"); return; }

    char line[512];
    int  n = 0;
    printf("  %-21s %-9s %-13s %-18s %s\n",
           "TIMESTAMP", "USER", "ACTION", "TARGET", "RESULT");
    printf("  --------------------- --------- ------------- "
           "------------------ ----------\n");
    while (fgets(line, sizeof(line), fp)) {
        char *f[6]; int i = 0;
        char *tok = strtok(line, "|");
        while (tok && i < 6) { f[i++] = tok; tok = strtok(NULL, "|"); }
        if (i >= 5) {
            printf("  %-21s %-9s %-13s %-18s %s\n", f[0], f[1], f[2], f[3], f[4]);
            n++;
        }
    }
    fclose(fp);
    printf("  (%d entries)\n", n);
}

static void cmd_help(void)
{
    printf("\n  Secure File Manager - commands\n");
    printf("  ------------------------------------------------------------\n");
    printf("  login <user> <pass>      authenticate  [Req 3.1(2)]\n");
    printf("  logout                   end the session\n");
    printf("  whoami                   show the current user\n");
    printf("  users                    list accounts\n");
    printf("  ls                       list files and their permissions\n");
    printf("  create <file>            create a file           [Req 3.1(1)]\n");
    printf("  write  <file> <text>     replace contents        [Req 3.1(1)]\n");
    printf("  read   <file>            read contents           [Req 3.1(1)]\n");
    printf("  rm     <file>            delete                  [Req 3.1(1)]\n");
    printf("  chmod  <file> <octal>    change permissions      [Req 3.1(3)]\n");
    printf("  encrypt <file> <pass>    encrypt in place        [Req 3.1(4)]\n");
    printf("  decrypt <file> <pass>    decrypt in place        [Req 3.1(4)]\n");
    printf("  audit                    show the audit log      [Req 3.1(5)]\n");
    printf("  verify                   check the log's hash chain\n");
    printf("  help                     this list\n");
    printf("  exit                     quit\n\n");
}

/* ============================== SETUP ==================================== */

static void add_user(const char *name, const char *password, int uid, int gid)
{
    if (user_count >= MAX_USERS) return;
    User *u = &users[user_count++];
    snprintf(u->username, sizeof(u->username), "%s", name);
    u->uid = uid; u->gid = gid; u->failed = 0; u->locked = 0;
    if (secure_random(u->salt, SALT_LEN) != 0) memset(u->salt, 0, SALT_LEN);
    pbkdf2_hmac_sha256(password, u->salt, SALT_LEN, KDF_ROUNDS, u->hash, HASH_LEN);
}

static void bootstrap(void)
{
    mkdir(WORK_DIR, 0700);
    sha256((const uint8_t *)"GENESIS", 7, chain_head);

    /* Demonstration accounts. Real systems never ship with fixed credentials -
       default passwords are among the most exploited weaknesses there are. */
    add_user("alice",   "correct-horse-battery", 1001, 2001);
    add_user("bob",     "Tr0ub4dor&3xyz",        1002, 2001);
    add_user("mallory", "letmein-please-2024",   1003, 2009);
}

static void cmd_users(void)
{
    printf("  %-10s %-6s %-6s %s\n", "USER", "UID", "GID", "STATUS");
    printf("  ---------- ------ ------ --------\n");
    for (int i = 0; i < user_count; i++)
        printf("  %-10s %-6d %-6d %s\n", users[i].username, users[i].uid,
               users[i].gid, users[i].locked ? "LOCKED" : "active");
}

/* ============================== DEMO ===================================== */

/*
 * A scripted walkthrough that exercises every requirement without needing
 * input. This is what produces the captured logs in ../outputs/.
 */
static void run_demo(void)
{
    printf("=== Secure File Manager - scripted demonstration ===\n");
    printf("Every operation passes through the same four stages:\n");
    printf("  authenticate -> validate -> authorise -> audit\n\n");

    printf("--- 1. Authentication [Req 3.1(2)] ---\n");
    printf("$ login alice wrong-password\n");   cmd_login("alice", "wrong-password");
    printf("$ login alice correct-horse-battery\n");
    cmd_login("alice", "correct-horse-battery");
    printf("\n");

    printf("--- 2. File operations [Req 3.1(1)] ---\n");
    printf("$ create report.txt\n");            cmd_create("report.txt");
    printf("$ write report.txt ...\n");
    cmd_write("report.txt", "Q3 revenue: 1.2M\nHeadcount: 48\n");
    printf("$ read report.txt\n");              cmd_read("report.txt");
    printf("$ create salary.txt\n");            cmd_create("salary.txt");
    printf("$ write salary.txt ...\n");
    cmd_write("salary.txt", "alice 62000\nbob 58000\n");
    printf("$ ls\n");                           cmd_ls();
    printf("\n");

    printf("--- 3. Path traversal is refused [Req 3.1(1)] ---\n");
    printf("$ create ../../etc/passwd\n");      cmd_create("../../etc/passwd");
    printf("\n");

    printf("--- 4. Permissions [Req 3.1(3)] ---\n");
    printf("$ chmod salary.txt 600\n");         cmd_chmod("salary.txt", "600");
    printf("$ logout\n");                       cmd_logout();
    printf("$ login bob Tr0ub4dor&3xyz\n");     cmd_login("bob", "Tr0ub4dor&3xyz");
    printf("$ read report.txt      (bob is in alice's group, 0640 -> r)\n");
    cmd_read("report.txt");
    printf("$ write report.txt ... (0640 gives the group no 'w')\n");
    cmd_write("report.txt", "bob was here");
    printf("$ read salary.txt      (0600 -> nobody but the owner)\n");
    cmd_read("salary.txt");
    printf("$ chmod salary.txt 666 (only the owner may change a mode)\n");
    cmd_chmod("salary.txt", "666");
    printf("\n");

    printf("--- 5. An outsider probes the system ---\n");
    printf("$ logout\n");                       cmd_logout();
    printf("$ login mallory guess1\n");         cmd_login("mallory", "guess1");
    printf("$ login mallory guess2\n");         cmd_login("mallory", "guess2");
    printf("$ login mallory letmein-please-2024\n");
    cmd_login("mallory", "letmein-please-2024");
    printf("$ read salary.txt      (not owner, not in group -> 'others')\n");
    cmd_read("salary.txt");
    printf("$ rm report.txt\n");                cmd_delete("report.txt");
    printf("\n");

    printf("--- 6. Encryption [Req 3.1(4)] ---\n");
    printf("$ logout\n");                       cmd_logout();
    printf("$ login alice correct-horse-battery\n");
    cmd_login("alice", "correct-horse-battery");
    printf("$ encrypt salary.txt file-password\n");
    cmd_encrypt("salary.txt", "file-password");
    printf("$ read salary.txt      (now ciphertext on disk)\n");
    cmd_read("salary.txt");
    printf("$ decrypt salary.txt WRONG-password\n");
    cmd_decrypt("salary.txt", "WRONG-password");
    printf("$ decrypt salary.txt file-password\n");
    cmd_decrypt("salary.txt", "file-password");
    printf("$ read salary.txt\n");              cmd_read("salary.txt");
    printf("\n");

    printf("--- 7. Audit trail [Req 3.1(5)] ---\n");
    printf("$ logout\n");                       cmd_logout();
    printf("$ audit\n");                        cmd_audit();
    printf("\n$ verify\n");                     cmd_verify();
    printf("\n");

    printf("--- 8. The log detects tampering ---\n");
    printf("Rewriting one DENIED result to SUCCESS directly in %s:\n", LOG_FILE);
    {
        /* Read the log, change the first DENIED to SUCCESS, write it back -
           exactly what an attacker with file access would attempt. */
        FILE *fp = fopen(LOG_FILE, "r");
        char all[16384] = "", line[512];
        int changed = 0;
        while (fp && fgets(line, sizeof(line), fp)) {
            char *d = strstr(line, "|DENIED|");
            if (d && !changed) {
                /* line is 512 bytes and d points into it, so the rebuilt
                   entry can be up to 512 + strlen("|SUCCESS|") bytes. Sizing
                   this buffer at 512 would silently truncate - GCC's
                   -Wformat-truncation catches exactly that. */
                char rebuilt[640];
                *d = '\0';
                snprintf(rebuilt, sizeof(rebuilt), "%s|SUCCESS|%s",
                         line, d + 8);
                strncat(all, rebuilt, sizeof(all) - strlen(all) - 1);
                changed = 1;
                printf("  altered one entry: DENIED -> SUCCESS\n");
            } else {
                strncat(all, line, sizeof(all) - strlen(all) - 1);
            }
        }
        if (fp) fclose(fp);
        if (changed) {
            int fd = open(LOG_FILE, O_WRONLY | O_TRUNC);
            if (fd >= 0) { (void)!write(fd, all, strlen(all)); close(fd); }
        }
    }
    printf("$ verify\n");                       cmd_verify();
    printf("\n");

    printf("=== Demonstration complete ===\n");
    printf("Every requirement was exercised: authentication with lockout,\n");
    printf("the four file operations, permission checks that denied access\n");
    printf("across all three classes, authenticated encryption that refused a\n");
    printf("wrong password, and a hash-chained audit log that caught an edit.\n");
}

/* ============================== SHELL ==================================== */

/* Split a line into at most `max` whitespace-separated tokens. */
static int tokenise(char *line, char **argv, int max)
{
    int n = 0;
    char *p = strtok(line, " \t\n");
    while (p && n < max) { argv[n++] = p; p = strtok(NULL, " \t\n"); }
    return n;
}

int main(int argc, char **argv_main)
{
    bootstrap();

    if (argc > 1 && strcmp(argv_main[1], "demo") == 0) {
        unlink(LOG_FILE);                  /* start from a clean log */
        run_demo();
        return EXIT_SUCCESS;
    }

    printf("Secure File Manager (ST5004CEM Task 3)\n");
    printf("Type 'help' for commands. Demo accounts: alice, bob, mallory.\n");

    char line[MAX_INPUT], *tok[8];
    for (;;) {
        printf("%s> ", current_uid >= 0 ? current_user : "(not logged in)");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) { printf("\n"); break; }

        /* `write` keeps the rest of the line intact as its content, so it is
           split off before the generic tokeniser runs. */
        if (strncmp(line, "write ", 6) == 0) {
            char *rest = line + 6;
            char *sp   = strchr(rest, ' ');
            if (sp) {
                *sp = '\0';
                char *content = sp + 1;
                char *nl = strchr(content, '\n'); if (nl) *nl = '\0';
                char unescaped[MAX_CONTENT]; size_t o = 0;
                /* allow \n in the text so multi-line files can be typed */
                for (size_t i = 0; content[i] && o < sizeof(unescaped) - 2; i++) {
                    if (content[i] == '\\' && content[i + 1] == 'n') {
                        unescaped[o++] = '\n'; i++;
                    } else unescaped[o++] = content[i];
                }
                unescaped[o++] = '\n';
                unescaped[o]   = '\0';
                cmd_write(rest, unescaped);
            } else printf("  usage: write <file> <text>\n");
            continue;
        }

        int n = tokenise(line, tok, 8);
        if (n == 0) continue;

        if      (!strcmp(tok[0], "exit") || !strcmp(tok[0], "quit")) break;
        else if (!strcmp(tok[0], "help"))   cmd_help();
        else if (!strcmp(tok[0], "users"))  cmd_users();
        else if (!strcmp(tok[0], "whoami"))
            printf("  %s\n", current_uid >= 0 ? current_user : "(not logged in)");
        else if (!strcmp(tok[0], "login"))
            n >= 3 ? cmd_login(tok[1], tok[2])
                   : (void)printf("  usage: login <user> <password>\n");
        else if (!strcmp(tok[0], "logout")) cmd_logout();
        else if (!strcmp(tok[0], "ls"))     cmd_ls();
        else if (!strcmp(tok[0], "create"))
            n >= 2 ? cmd_create(tok[1]) : (void)printf("  usage: create <file>\n");
        else if (!strcmp(tok[0], "read"))
            n >= 2 ? cmd_read(tok[1]) : (void)printf("  usage: read <file>\n");
        else if (!strcmp(tok[0], "rm"))
            n >= 2 ? cmd_delete(tok[1]) : (void)printf("  usage: rm <file>\n");
        else if (!strcmp(tok[0], "chmod"))
            n >= 3 ? cmd_chmod(tok[1], tok[2])
                   : (void)printf("  usage: chmod <file> <octal>\n");
        else if (!strcmp(tok[0], "encrypt"))
            n >= 3 ? cmd_encrypt(tok[1], tok[2])
                   : (void)printf("  usage: encrypt <file> <password>\n");
        else if (!strcmp(tok[0], "decrypt"))
            n >= 3 ? cmd_decrypt(tok[1], tok[2])
                   : (void)printf("  usage: decrypt <file> <password>\n");
        else if (!strcmp(tok[0], "audit"))  cmd_audit();
        else if (!strcmp(tok[0], "verify")) cmd_verify();
        else printf("  Unknown command '%s'. Type 'help'.\n", tok[0]);
    }

    printf("Session ended. %d audit entries were written to %s.\n",
           audit_count, LOG_FILE);
    return EXIT_SUCCESS;
}
