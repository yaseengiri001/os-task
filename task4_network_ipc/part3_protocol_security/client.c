/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 3 of 4: Protocol client and security test harness
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   The client half of requirements 4.1(2), 4.1(4) and 4.1(5), and the evidence
 *   for deliverable 4.2(3) - "testing documentation showing successful
 *   communication."
 *
 * WHY THIS CLIENT DELIBERATELY MISBEHAVES
 *   Showing that a correct request gets a correct answer demonstrates almost
 *   nothing about security. What matters is what the server does when the input
 *   is WRONG - because that is the only kind of input an attacker sends. This
 *   client therefore runs a series of NEGATIVE tests alongside the positive
 *   ones, and each has an expected status code that is checked automatically:
 *
 *       - a command before authenticating          -> 401
 *       - RESPONSE without a preceding AUTH        -> 400
 *       - a malformed username                     -> 400
 *       - a response of the wrong length/alphabet  -> 400
 *       - a wrong password                         -> 401
 *       - repeated wrong passwords                 -> 429 and disconnect
 *       - an unknown command                       -> 400
 *       - a payload with control characters        -> 400
 *       - a line far longer than the maximum       -> 400
 *
 *   A test that only ever exercises the happy path would pass against a server
 *   with no validation at all, which is precisely why it proves nothing.
 *
 * THE CHALLENGE-RESPONSE EXCHANGE
 *       -> AUTH alice
 *       <- 331 CHALLENGE 9f2c...            (fresh random nonce)
 *       -> RESPONSE <HMAC-SHA256(password, nonce)>
 *       <- 200 OK authenticated as alice
 *
 *   The password is never transmitted. Because the nonce is different every
 *   time, a recorded RESPONSE cannot be replayed against a later connection.
 *
 * BUILD & RUN
 *   ./client 127.0.0.1 9003
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


#include "../../task3_filesystem_security/common/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024
#define MAX_LINE 2048

static int tests_run = 0, tests_passed = 0;

typedef struct { char data[BUF_SIZE * 4]; size_t len; } LineBuf;

static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) { if (errno == EINTR) continue; return -1; }
        sent += (size_t)n;
    }
    return 0;
}

static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t linelen = i;
                if (linelen > 0 && lb->data[linelen - 1] == '\r') linelen--;
                if (linelen >= outsz) linelen = outsz - 1;
                memcpy(out, lb->data, linelen);
                out[linelen] = '\0';
                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)linelen;
            }
        }
        if (lb->len >= sizeof(lb->data)) return -1;
        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0) return 0;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        lb->len += (size_t)n;
    }
}

/*
 * Send one request line.
 *
 * vsnprintf returns the length the output WOULD have been, which on a
 * truncated write is larger than the buffer. Using it directly as an index
 * (line[n++] = '\n') writes past the end - a buffer overflow that appears only
 * on unusually long input. The value is clamped before use.
 */
static int request(int fd, const char *fmt, ...)
{
    char line[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n > sizeof(line) - 2) n = (int)(sizeof(line) - 2);   /* truncated */
    line[n++] = '\n';
    line[n]   = '\0';
    printf("    -> %.70s%s\n", line, n > 71 ? " ...(truncated in this log)" : "");
    return send_all(fd, line, (size_t)n);
}

/*
 * Read one reply and check that it starts with the expected status code.
 * Asserting the code rather than eyeballing the text is what makes this a
 * test rather than a demonstration.
 */
static int expect(int fd, LineBuf *lb, const char *code, const char *what)
{
    char reply[BUF_SIZE];
    tests_run++;

    ssize_t n = recv_line(fd, lb, reply, sizeof(reply));
    if (n <= 0) {
        printf("    <- (connection closed)\n");
        if (strcmp(code, "CLOSED") == 0) {
            tests_passed++;
            printf("    PASS  %s\n\n", what);
            return 1;
        }
        printf("    FAIL  %s (expected %s)\n\n", what, code);
        return 0;
    }

    printf("    <- %s\n", reply);
    if (strncmp(reply, code, strlen(code)) == 0) {
        tests_passed++;
        printf("    PASS  %s\n\n", what);
        return 1;
    }
    printf("    FAIL  %s (expected %s)\n\n", what, code);
    return 0;
}

/* Connect and read the greeting. Returns the socket, or -1. */
static int connect_to(const char *host, int port, LineBuf *lb)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &server.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));
        if (errno == ECONNREFUSED)
            fprintf(stderr, "(is the server running on port %d?)\n", port);
        close(fd);
        return -1;
    }
    lb->len = 0;

    char greeting[BUF_SIZE];
    if (recv_line(fd, lb, greeting, sizeof(greeting)) > 0)
        printf("    <- %s\n", greeting);
    return fd;
}

/*
 * Complete the challenge-response exchange.
 * Returns 1 if authentication succeeded.
 */
static int authenticate(int fd, LineBuf *lb, const char *user, const char *password)
{
    char reply[BUF_SIZE];

    request(fd, "AUTH %s", user);
    if (recv_line(fd, lb, reply, sizeof(reply)) <= 0) return 0;
    printf("    <- %s\n", reply);

    if (strncmp(reply, "331 CHALLENGE ", 14) != 0) return 0;
    const char *nonce_hex = reply + 14;

    /* The proof of knowledge: HMAC of the server's nonce, keyed by the
       password. The password itself is never sent. */
    uint8_t mac[SHA256_DIGEST_SIZE];
    char    mac_hex[SHA256_DIGEST_SIZE * 2 + 1];
    hmac_sha256((const uint8_t *)password, strlen(password),
                (const uint8_t *)nonce_hex, strlen(nonce_hex), mac);
    hex_encode(mac, SHA256_DIGEST_SIZE, mac_hex);

    request(fd, "RESPONSE %s", mac_hex);
    if (recv_line(fd, lb, reply, sizeof(reply)) <= 0) return 0;
    printf("    <- %s\n", reply);
    return strncmp(reply, "200", 3) == 0;
}

int main(int argc, char **argv)
{
    /* Line-buffer the log. When stdout is a pipe or a file it is fully
       buffered by default, so log lines can sit unwritten for a long time
       and appear out of order relative to the other process. A server log
       is only useful if it appears as events happen. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /*
     * Ignore SIGPIPE. Writing to a socket whose peer has already closed
     * raises SIGPIPE, whose default action is to KILL the process - so a
     * client that sends one more request after the server has hung up simply
     * dies, with no chance to report why. Ignoring it turns the event into an
     * ordinary EPIPE error from send(), which the existing error handling
     * already deals with. Servers need this for the same reason; clients need
     * it just as much.
     */
    signal(SIGPIPE, SIG_IGN);

    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 9003;
    LineBuf     lb;
    int         fd;

    printf("=== Protocol and security test harness ===\n");
    printf("Target: %s:%d\n\n", host, port);

    /* =================== SESSION 1: the happy path ======================= */
    printf("--- Session 1: correct usage ---\n");
    fd = connect_to(host, port, &lb);
    if (fd < 0) return EXIT_FAILURE;
    printf("\n");

    printf("  [1] HELP is available before authenticating\n");
    request(fd, "HELP");
    expect(fd, &lb, "200", "HELP works unauthenticated");

    printf("  [2] A privileged command BEFORE authenticating must be refused\n");
    request(fd, "TIME");
    expect(fd, &lb, "401", "TIME refused without authentication");

    printf("  [3] RESPONSE without a preceding AUTH must be refused\n");
    request(fd, "RESPONSE %064d", 0);
    expect(fd, &lb, "400", "RESPONSE rejected out of sequence");

    printf("  [4] Challenge-response authentication with the correct password\n");
    int ok = authenticate(fd, &lb, "alice", "correct-horse-battery");
    tests_run++;
    if (ok) { tests_passed++; printf("    PASS  authenticated as alice\n\n"); }
    else    { printf("    FAIL  authentication should have succeeded\n\n"); }

    printf("  [5] Privileged commands now work\n");
    request(fd, "WHOAMI");
    expect(fd, &lb, "200", "WHOAMI after authentication");
    request(fd, "TIME");
    expect(fd, &lb, "200", "TIME after authentication");
    request(fd, "ECHO hello protocol world");
    expect(fd, &lb, "200", "ECHO with a valid payload");

    printf("  [6] An unknown command is refused, not ignored\n");
    request(fd, "DROPTABLE users");
    expect(fd, &lb, "400", "unknown command rejected");

    printf("  [7] A payload containing a control character is refused\n");
    request(fd, "ECHO bad\x01payload");
    expect(fd, &lb, "400", "control characters rejected");

    printf("  [8] A payload longer than the 256-character limit is refused\n");
    {
        char big[400];
        memset(big, 'A', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        request(fd, "ECHO %s", big);
        expect(fd, &lb, "400", "over-long payload rejected");
    }

    request(fd, "QUIT");
    expect(fd, &lb, "200", "clean QUIT");
    close(fd);

    /* =================== SESSION 2: bad credentials ====================== */
    printf("--- Session 2: authentication failures and rate limiting ---\n");
    fd = connect_to(host, port, &lb);
    if (fd < 0) return EXIT_FAILURE;
    printf("\n");

    printf("  [9] A malformed username is refused before any work is done\n");
    request(fd, "AUTH ../../etc/passwd");
    expect(fd, &lb, "400", "invalid username format rejected");

    printf("  [10] A response of the wrong shape is refused\n");
    request(fd, "AUTH alice");
    {
        char reply[BUF_SIZE];
        recv_line(fd, &lb, reply, sizeof(reply));
        printf("    <- %s\n", reply);
    }
    request(fd, "RESPONSE nothex");
    expect(fd, &lb, "400", "malformed digest rejected");

    printf("  [11] Three wrong passwords: 401, 401, then 429 and disconnect\n");
    for (int attempt = 1; attempt <= 3; attempt++) {
        request(fd, "AUTH alice");
        char reply[BUF_SIZE];
        if (recv_line(fd, &lb, reply, sizeof(reply)) <= 0) break;
        printf("    <- %s\n", reply);
        if (strncmp(reply, "331 CHALLENGE ", 14) != 0) break;

        uint8_t mac[SHA256_DIGEST_SIZE];
        char    mac_hex[SHA256_DIGEST_SIZE * 2 + 1];
        hmac_sha256((const uint8_t *)"wrong-password", 14,
                    (const uint8_t *)(reply + 14), strlen(reply + 14), mac);
        hex_encode(mac, SHA256_DIGEST_SIZE, mac_hex);

        request(fd, "RESPONSE %s", mac_hex);
        expect(fd, &lb, attempt < 3 ? "401" : "429",
               attempt < 3 ? "wrong password rejected"
                           : "rate limit reached after 3 failures");
    }
    close(fd);

    /* =================== SESSION 3: no user enumeration ================== */
    printf("--- Session 3: an unknown account is indistinguishable ---\n");
    fd = connect_to(host, port, &lb);
    if (fd < 0) return EXIT_FAILURE;
    printf("\n");

    printf("  [12] AUTH for an account that does not exist still gets a\n");
    printf("       challenge, so the reply reveals nothing about who is real\n");
    request(fd, "AUTH nosuchuser");
    expect(fd, &lb, "331", "challenge issued for an unknown account");

    request(fd, "RESPONSE %064d", 1);
    expect(fd, &lb, "401", "failure message identical to a wrong password");

    request(fd, "QUIT");
    expect(fd, &lb, "200", "clean QUIT");
    close(fd);

    /* =================== SESSION 4: an unterminated flood ================ */
    printf("--- Session 4: a line with no terminator at all ---\n");
    printf("  A client that streams bytes without ever sending \\n would make\n");
    printf("  an unbounded server buffer grow until memory ran out. The server\n");
    printf("  caps the line length instead, so the attack costs it nothing.\n\n");
    fd = connect_to(host, port, &lb);
    if (fd < 0) return EXIT_FAILURE;
    printf("\n");

    printf("  [13] 8 KB with no newline: refused and the connection dropped\n");
    {
        char flood[8192];
        memset(flood, 'A', sizeof(flood));
        printf("    -> ECHO followed by %zu bytes and NO newline\n", sizeof(flood));
        send_all(fd, "ECHO ", 5);
        send_all(fd, flood, sizeof(flood));
        expect(fd, &lb, "400", "unterminated flood refused");
    }
    close(fd);

    /* =================== verdict ========================================= */
    printf("=== Test summary ===\n");
    printf("  %d of %d checks passed\n", tests_passed, tests_run);
    if (tests_passed == tests_run) {
        printf("  ALL TESTS PASSED - the server accepted every valid request\n");
        printf("  and refused every invalid one with the correct status code.\n");
        return EXIT_SUCCESS;
    }
    printf("  %d FAILED\n", tests_run - tests_passed);
    return EXIT_FAILURE;
}
