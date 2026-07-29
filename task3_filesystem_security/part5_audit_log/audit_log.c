/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Part 5 of 5: Audit logging
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 3.1(5): "Audit logging to track file access and modifications."
 *
 * WHAT AN AUDIT LOG IS FOR
 *   Parts 2, 3 and 4 try to PREVENT unauthorised access. No prevention is
 *   perfect, so a secure system also has to be able to answer, afterwards:
 *   what happened, when, and who did it? That is detection and accountability,
 *   and it is the third leg alongside prevention and recovery.
 *
 * THE PROBLEM WITH AN ORDINARY LOG FILE
 *   An attacker's first move after breaking in is to edit the log and remove
 *   the evidence. A plain text log offers no defence at all: any line can be
 *   changed or deleted and the file still looks perfectly ordinary. A log that
 *   can be silently rewritten is worse than useless, because it produces
 *   confident but false assurance.
 *
 * THE SOLUTION USED HERE: A HASH CHAIN
 *   Every entry carries a hash computed over BOTH its own contents AND the
 *   hash of the entry before it:
 *
 *       chain[0] = HMAC(key, "GENESIS")
 *       chain[n] = HMAC(key, chain[n-1] || entry[n])
 *
 *   This links the entries together like blocks in a blockchain (the same
 *   construction, and it long predates cryptocurrency - Haber and Stornetta
 *   published it in 1991 for timestamping documents).
 *
 *   Any tampering breaks the chain and is detected:
 *     - MODIFYING an entry changes its hash, so every later link mismatches
 *     - DELETING an entry breaks the link across the gap
 *     - INSERTING an entry cannot produce a hash consistent with its neighbours
 *     - REORDERING entries breaks the links, because order is part of the input
 *
 *   The chain is keyed with HMAC rather than a bare hash. That distinction
 *   matters: with a plain hash, an attacker who rewrites the whole file can
 *   simply recompute every link and the log verifies again. With HMAC they
 *   cannot produce a single valid link without the key.
 *
 * WHAT THIS STILL DOES NOT SOLVE (stated honestly)
 *   The verification key lives on the same machine. An attacker who gains root
 *   can read it and forge a consistent log. Tamper-evidence is bounded by where
 *   the key is kept, so real deployments ship log entries off the host as they
 *   are produced - to a write-once medium or a separate logging server the
 *   compromised host cannot reach. The chain then means a local attacker can
 *   destroy the local copy but cannot alter the remote one undetectably.
 *
 * WHAT IS DELIBERATELY NOT LOGGED
 *   Passwords, keys and file contents are never written to the log. Logs are
 *   copied, shipped and read far more widely than the data they describe, and
 *   a log containing secrets quietly becomes the softest target in the system.
 *
 * BUILD & RUN
 *   make run
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define LOG_FILE     "audit.log"
#define MAX_ENTRIES  64
#define MAX_LINE     512

/* The key protecting the chain. In a real system this would come from a
   hardware security module or a separate service - never a literal in the
   source, which is exactly the weakness the header comment describes. */
static const char *CHAIN_KEY = "audit-chain-key-demo-only";

/* One log record, held in memory for verification. */
typedef struct {
    char    timestamp[32];
    char    user[32];
    char    action[24];
    char    target[64];
    char    result[16];
    uint8_t chain[SHA256_DIGEST_SIZE];   /* the link for THIS entry */
} LogEntry;

static LogEntry entries[MAX_ENTRIES];
static int      entry_count = 0;

/* ISO-8601-ish UTC timestamp. UTC avoids the ambiguity that local time creates
   twice a year when clocks go back and the same hour occurs twice. */
static void now_utc(char *out, size_t n)
{
    time_t     t  = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", tm);
}

/*
 * Compute the chain link for one entry:
 *     HMAC(key, previous_chain || entry_fields)
 * Including the previous link is what makes the entries inseparable.
 */
static void compute_chain(const uint8_t *prev, const LogEntry *e, uint8_t *out)
{
    uint8_t message[SHA256_DIGEST_SIZE + MAX_LINE];
    size_t  n = 0;

    memcpy(message, prev, SHA256_DIGEST_SIZE);
    n += SHA256_DIGEST_SIZE;

    /* The record's canonical form. Every field is included, so changing any
       one of them changes the link. */
    n += (size_t)snprintf((char *)message + n, MAX_LINE, "%s|%s|%s|%s|%s",
                          e->timestamp, e->user, e->action, e->target, e->result);

    hmac_sha256((const uint8_t *)CHAIN_KEY, strlen(CHAIN_KEY), message, n, out);
}

/*
 * Append one event, both to memory and to the file.
 *
 * O_APPEND makes each write land at the end of the file atomically, even with
 * several processes logging at once. Seeking to the end and then writing would
 * be a race, and interleaved log records are corrupted evidence.
 */
static int log_event(const char *user, const char *action,
                     const char *target, const char *result)
{
    if (entry_count >= MAX_ENTRIES) return -1;

    LogEntry *e = &entries[entry_count];
    now_utc(e->timestamp, sizeof(e->timestamp));
    snprintf(e->user,   sizeof(e->user),   "%s", user);
    snprintf(e->action, sizeof(e->action), "%s", action);
    snprintf(e->target, sizeof(e->target), "%s", target);
    snprintf(e->result, sizeof(e->result), "%s", result);

    /* The first entry chains from a fixed genesis value. */
    uint8_t prev[SHA256_DIGEST_SIZE];
    if (entry_count == 0) sha256((const uint8_t *)"GENESIS", 7, prev);
    else                  memcpy(prev, entries[entry_count - 1].chain,
                                 SHA256_DIGEST_SIZE);

    compute_chain(prev, e, e->chain);

    char hex[SHA256_DIGEST_SIZE * 2 + 1];
    hex_encode(e->chain, SHA256_DIGEST_SIZE, hex);

    char line[MAX_LINE];
    int  n = snprintf(line, sizeof(line), "%s|%s|%s|%s|%s|%s\n",
                      e->timestamp, e->user, e->action, e->target,
                      e->result, hex);

    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", LOG_FILE, strerror(errno));
        return -1;
    }
    if (write(fd, line, (size_t)n) != n) { close(fd); return -1; }
    close(fd);

    entry_count++;
    return 0;
}

/* Print the log as a readable table. */
static void print_log(void)
{
    printf("  %-21s %-9s %-12s %-22s %-8s %s\n",
           "TIMESTAMP", "USER", "ACTION", "TARGET", "RESULT", "CHAIN");
    printf("  --------------------- --------- ------------ "
           "---------------------- -------- ----------------\n");
    for (int i = 0; i < entry_count; i++) {
        char hex[SHA256_DIGEST_SIZE * 2 + 1];
        hex_encode(entries[i].chain, SHA256_DIGEST_SIZE, hex);
        printf("  %-21s %-9s %-12s %-22s %-8s %.16s\n",
               entries[i].timestamp, entries[i].user, entries[i].action,
               entries[i].target, entries[i].result, hex);
    }
}

/*
 * Re-derive every link from the entry contents and compare against what is
 * recorded. Any mismatch localises the first altered entry.
 */
static int verify_chain(void)
{
    uint8_t prev[SHA256_DIGEST_SIZE], expected[SHA256_DIGEST_SIZE];
    sha256((const uint8_t *)"GENESIS", 7, prev);

    for (int i = 0; i < entry_count; i++) {
        compute_chain(prev, &entries[i], expected);
        if (!constant_time_equal(expected, entries[i].chain, SHA256_DIGEST_SIZE)) {
            printf("  CHAIN BROKEN at entry %d\n", i + 1);
            printf("    %s %s %s %s\n", entries[i].timestamp, entries[i].user,
                   entries[i].action, entries[i].target);
            printf("    This entry, or one before it, has been altered.\n");
            return 0;
        }
        memcpy(prev, entries[i].chain, SHA256_DIGEST_SIZE);
    }
    printf("  CHAIN INTACT - all %d entries verify against their neighbours.\n",
           entry_count);
    return 1;
}

int main(void)
{
    printf("=== Audit logging ===\n");
    printf("Requirement 3.1(5)\n\n");
    printf("Every entry is chained to the one before it with\n");
    printf("HMAC-SHA256(key, previous_link || entry), so the log is\n");
    printf("tamper-evident rather than merely descriptive.\n\n");

    /* Start from a clean log so the demonstration is repeatable. */
    unlink(LOG_FILE);

    /* ---- 1. Record a plausible sequence of events ------------------------ */
    printf("1. Recording activity\n\n");
    log_event("alice",   "LOGIN",      "-",             "SUCCESS");
    log_event("alice",   "FILE_CREATE","report.txt",    "SUCCESS");
    log_event("alice",   "FILE_WRITE", "report.txt",    "SUCCESS");
    log_event("bob",     "LOGIN",      "-",             "FAILURE");
    log_event("bob",     "LOGIN",      "-",             "SUCCESS");
    log_event("bob",     "FILE_READ",  "report.txt",    "SUCCESS");
    log_event("mallory", "LOGIN",      "-",             "FAILURE");
    log_event("mallory", "FILE_READ",  "salary.enc",    "DENIED");
    log_event("mallory", "CHMOD",      "salary.enc",    "DENIED");
    log_event("alice",   "ENCRYPT",    "salary.enc",    "SUCCESS");
    log_event("alice",   "FILE_DELETE","old_notes.txt", "SUCCESS");
    log_event("alice",   "LOGOUT",     "-",             "SUCCESS");
    print_log();
    printf("\n  Written to %s (mode 0600, opened O_APPEND)\n\n", LOG_FILE);

    /* ---- 2. Verify an untouched log -------------------------------------- */
    printf("2. Verifying the untouched log\n");
    verify_chain();
    printf("\n");

    /* ---- 3. What the log reveals ----------------------------------------- *
     * The point of an audit log is not the records themselves but what
     * reading them together tells you.                                      */
    printf("3. What the log shows on inspection\n");
    {
        int failures = 0, denials = 0;
        for (int i = 0; i < entry_count; i++) {
            if (strcmp(entries[i].result, "FAILURE") == 0) failures++;
            if (strcmp(entries[i].result, "DENIED")  == 0) denials++;
        }
        printf("    %d entries: %d failed logins, %d denied operations.\n",
               entry_count, failures, denials);
        printf("    mallory failed to log in and was then denied twice while\n");
        printf("    reaching for an encrypted file and trying to change its\n");
        printf("    permissions. Individually each line is unremarkable; the\n");
        printf("    SEQUENCE is what identifies it as probing.\n\n");
    }

    /* ---- 4. Tampering is detected ---------------------------------------- */
    printf("4. An attacker edits the log to hide their tracks\n");
    printf("    mallory rewrites her DENIED read as SUCCESS by someone else:\n");
    printf("    entry 8: mallory/FILE_READ/DENIED -> alice/FILE_READ/SUCCESS\n\n");
    snprintf(entries[7].user,   sizeof(entries[7].user),   "%s", "alice");
    snprintf(entries[7].result, sizeof(entries[7].result), "%s", "SUCCESS");
    verify_chain();
    printf("    The edit is caught. Rewriting the entry did not rewrite the\n");
    printf("    link stored with it, and every later link depends on it.\n\n");

    /* restore, so the following demonstrations start from a valid log */
    snprintf(entries[7].user,   sizeof(entries[7].user),   "%s", "mallory");
    snprintf(entries[7].result, sizeof(entries[7].result), "%s", "DENIED");

    /* ---- 5. Deleting an entry is detected too ---------------------------- */
    printf("5. Deleting an entry outright\n");
    printf("    mallory removes entry 7 (her failed login) completely:\n\n");
    {
        LogEntry saved = entries[6];
        for (int i = 6; i < entry_count - 1; i++) entries[i] = entries[i + 1];
        entry_count--;

        verify_chain();
        printf("    Also caught. The chain records the ORDER of events, so a\n");
        printf("    missing entry leaves a gap the neighbouring links expose.\n");
        printf("    Simply deleting evidence is not enough.\n\n");

        /* restore */
        for (int i = entry_count; i > 6; i--) entries[i] = entries[i - 1];
        entries[6] = saved;
        entry_count++;
    }

    printf("6. Confirming the log is valid again after restoring it\n");
    verify_chain();
    printf("\n");

    printf("Summary\n");
    printf("  The log answers who did what, to which object, when, and whether\n");
    printf("  it succeeded. Chaining each entry to its predecessor with a keyed\n");
    printf("  HMAC means modification, deletion, insertion and reordering are\n");
    printf("  all detectable, and the failure is localised to an entry.\n");
    printf("  Secrets are never logged, since logs travel more widely than the\n");
    printf("  data they describe.\n");
    printf("  The honest limit: the key is on this machine, so an attacker with\n");
    printf("  root could forge a consistent log. Real deployments ship entries\n");
    printf("  off the host as they are written, which is what puts them beyond\n");
    printf("  a local attacker's reach.\n");

    return EXIT_SUCCESS;
}
