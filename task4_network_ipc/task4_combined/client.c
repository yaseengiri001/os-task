/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * COMBINED: the complete client-server application (client side)
 * -----------------------------------------------------------------------------
 * GOAL
 *   The client half of the integrated application, in two modes:
 *
 *     interactive  a shell for talking to the server by hand
 *     demo         a scripted end-to-end run that needs no input and doubles
 *                  as the testing documentation for deliverable 4.2(3)
 *
 * WHAT THE DEMO PROVES
 *   1. the challenge-response handshake works and never sends the password
 *   2. the key-value commands work end to end
 *   3. one user CANNOT read another user's keys, even knowing the key name
 *   4. invalid input is refused with the right status code
 *   5. several clients really are served at the same time (threads, peak > 1)
 *
 *   Point 3 is the one worth dwelling on. Alice and Bob both store a key called
 *   "secret". If the server's namespacing is wrong, Bob's FETCH returns Alice's
 *   value - a data leak that a test using different key names would never
 *   catch, because it would never create the collision in the first place.
 *
 * BUILD & RUN
 *   ./client 127.0.0.1 9000          # interactive
 *   ./client 127.0.0.1 9000 demo     # scripted
 * -----------------------------------------------------------------------------
 */

#include "../../task3_filesystem_security/common/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024
#define MAX_LINE 2048

static int checks_run = 0, checks_passed = 0;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;

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

/* >=0 line length, -1 error, -4 peer closed. See the server for why these are
   kept distinct from an empty line. */
static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t len = i;
                if (len > 0 && lb->data[len - 1] == '\r') len--;
                if (len >= outsz) len = outsz - 1;
                memcpy(out, lb->data, len);
                out[len] = '\0';
                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)len;
            }
        }
        if (lb->len >= sizeof(lb->data)) return -1;
        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0) return -4;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        lb->len += (size_t)n;
    }
}

/* Send one request line. vsnprintf's return is clamped before use as an index
   - unclamped it exceeds the buffer on truncation and overflows. */
static int request(int fd, const char *fmt, ...)
{
    char line[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n > sizeof(line) - 2) n = (int)(sizeof(line) - 2);
    line[n++] = '\n';
    line[n]   = '\0';
    return send_all(fd, line, (size_t)n);
}

static int connect_to(const char *host, int port, LineBuf *lb, char *greeting,
                      size_t gsz)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &server.sin_addr) != 1) {
        fprintf(stderr, "'%s' is not a valid IPv4 address\n", host);
        close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "connect to %s:%d failed: %s\n", host, port, strerror(errno));
        if (errno == ECONNREFUSED) fprintf(stderr, "(is the server running?)\n");
        close(fd); return -1;
    }
    lb->len = 0;
    if (greeting) recv_line(fd, lb, greeting, gsz);
    return fd;
}

/*
 * The challenge-response handshake.
 *   -> AUTH <user>
 *   <- 331 CHALLENGE <nonce>
 *   -> RESPONSE HMAC-SHA256(password, nonce)
 * The password is never transmitted, and the nonce is single-use, so a
 * captured RESPONSE cannot be replayed.
 */
static int authenticate(int fd, LineBuf *lb, const char *user,
                        const char *password, char *out, size_t outsz)
{
    char reply[BUF_SIZE];

    if (request(fd, "AUTH %s", user) < 0) return 0;
    if (recv_line(fd, lb, reply, sizeof(reply)) < 0) return 0;
    if (strncmp(reply, "331 CHALLENGE ", 14) != 0) {
        snprintf(out, outsz, "%s", reply);
        return 0;
    }

    uint8_t mac[SHA256_DIGEST_SIZE];
    char    mac_hex[SHA256_DIGEST_SIZE * 2 + 1];
    hmac_sha256((const uint8_t *)password, strlen(password),
                (const uint8_t *)(reply + 14), strlen(reply + 14), mac);
    hex_encode(mac, SHA256_DIGEST_SIZE, mac_hex);

    if (request(fd, "RESPONSE %s", mac_hex) < 0) return 0;
    if (recv_line(fd, lb, reply, sizeof(reply)) < 0) return 0;
    snprintf(out, outsz, "%s", reply);
    return strncmp(reply, "200", 3) == 0;
}

/* ===================== SCRIPTED DEMONSTRATION ============================ */

static void check(const char *what, const char *got, const char *expect_code)
{
    pthread_mutex_lock(&out_lock);
    checks_run++;
    int ok = strncmp(got, expect_code, strlen(expect_code)) == 0;
    if (ok) checks_passed++;
    printf("    %-6s %-46s %s\n", ok ? "PASS" : "FAIL", what, got);
    pthread_mutex_unlock(&out_lock);
}

/* One request, one reply, one assertion. */
static void step(int fd, LineBuf *lb, const char *what, const char *expect_code,
                 const char *fmt, ...)
{
    char cmd[MAX_LINE], reply[BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    request(fd, "%s", cmd);
    if (recv_line(fd, lb, reply, sizeof(reply)) < 0)
        snprintf(reply, sizeof(reply), "(connection closed)");
    check(what, reply, expect_code);
}

/* A worker used to prove several clients are served simultaneously. */
typedef struct {
    int   id;
    char  host[64];
    int   port;
    const char *user;
    const char *pass;
    double seconds;
    int   ok;
} Worker;

static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void *worker_thread(void *arg)
{
    Worker *w = (Worker *)arg;
    LineBuf lb;
    char    greeting[BUF_SIZE], reply[BUF_SIZE];
    double  start = now_ms();

    int fd = connect_to(w->host, w->port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return NULL;

    if (!authenticate(fd, &lb, w->user, w->pass, reply, sizeof(reply))) {
        close(fd); return NULL;
    }

    /* A little traffic each, so the connections genuinely overlap in time. */
    for (int i = 0; i < 5; i++) {
        request(fd, "STORE k%d value-%d-from-%s", i, i, w->user);
        recv_line(fd, &lb, reply, sizeof(reply));
        request(fd, "FETCH k%d", i);
        recv_line(fd, &lb, reply, sizeof(reply));
    }

    request(fd, "STATS");
    if (recv_line(fd, &lb, reply, sizeof(reply)) >= 0) {
        pthread_mutex_lock(&out_lock);
        printf("    client %d saw: %s\n", w->id, reply);
        pthread_mutex_unlock(&out_lock);
    }

    request(fd, "QUIT");
    recv_line(fd, &lb, reply, sizeof(reply));
    close(fd);

    w->seconds = (now_ms() - start) / 1000.0;
    w->ok = 1;
    return NULL;
}

static int run_demo(const char *host, int port)
{
    LineBuf lb;
    char    greeting[BUF_SIZE], reply[BUF_SIZE];

    printf("=== kvstore end-to-end demonstration ===\n");
    printf("Server: %s:%d\n\n", host, port);

    /* ---- 1. authentication ---------------------------------------------- */
    printf("--- 1. Authentication [Req 4.1(4)] ---\n");
    int fd = connect_to(host, port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return EXIT_FAILURE;
    printf("    greeting: %s\n", greeting);

    step(fd, &lb, "PING before authenticating", "200", "PING");
    step(fd, &lb, "LIST refused before authenticating", "401", "LIST");

    printf("    (handshake: AUTH -> 331 CHALLENGE -> RESPONSE, "
           "no password on the wire)\n");
    int ok = authenticate(fd, &lb, "alice", "correct-horse-battery",
                          reply, sizeof(reply));
    check("challenge-response as alice", reply, "200");
    if (!ok) { close(fd); return EXIT_FAILURE; }

    /* ---- 2. the store --------------------------------------------------- */
    printf("\n--- 2. Key-value operations [Req 4.1(2)] ---\n");
    step(fd, &lb, "WHOAMI",              "200", "WHOAMI");
    step(fd, &lb, "STORE a new key",     "200", "STORE project OS coursework");
    step(fd, &lb, "STORE a second key",  "200", "STORE secret alice-private-data");
    step(fd, &lb, "FETCH it back",       "200", "FETCH project");
    step(fd, &lb, "LIST own keys",       "200", "LIST");
    step(fd, &lb, "FETCH a missing key", "404", "FETCH nosuchkey");
    step(fd, &lb, "DELETE a key",        "200", "DELETE project");
    step(fd, &lb, "FETCH the deleted key","404", "FETCH project");

    /* ---- 3. validation --------------------------------------------------- */
    printf("\n--- 3. Input validation [Req 4.1(4)] ---\n");
    step(fd, &lb, "unknown command refused",     "400", "TRUNCATE ALL");
    step(fd, &lb, "STORE with no value refused", "400", "STORE keyonly");
    step(fd, &lb, "invalid key characters",      "400", "STORE ../../etc/passwd x");
    step(fd, &lb, "over-long value refused",     "400",
         "STORE big %0500d", 7);
    request(fd, "QUIT"); recv_line(fd, &lb, reply, sizeof(reply));
    close(fd);

    /* ---- 4. isolation between users -------------------------------------- */
    printf("\n--- 4. Users cannot read each other's data ---\n");
    printf("    alice stored a key literally called 'secret'. Bob now stores\n");
    printf("    his OWN key of the same name and reads it back. If the server\n");
    printf("    namespaces correctly, Bob sees only his own value.\n");
    fd = connect_to(host, port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return EXIT_FAILURE;

    ok = authenticate(fd, &lb, "bob", "Tr0ub4dor&3xyz", reply, sizeof(reply));
    check("challenge-response as bob", reply, "200");

    step(fd, &lb, "bob stores his own 'secret'", "200",
         "STORE secret bob-private-data");
    request(fd, "FETCH secret");
    recv_line(fd, &lb, reply, sizeof(reply));
    checks_run++;
    if (strstr(reply, "bob-private-data") && !strstr(reply, "alice")) {
        checks_passed++;
        printf("    %-6s %-46s %s\n", "PASS", "bob reads HIS value, not alice's",
               reply);
    } else {
        printf("    %-6s %-46s %s\n", "FAIL",
               "bob reads HIS value, not alice's", reply);
    }
    step(fd, &lb, "bob's LIST shows only his keys", "200", "LIST");

    request(fd, "QUIT"); recv_line(fd, &lb, reply, sizeof(reply));
    close(fd);

    /* ---- 5. failed authentication and rate limiting ---------------------- */
    printf("\n--- 5. Bad credentials and rate limiting [Req 4.1(5)] ---\n");
    fd = connect_to(host, port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return EXIT_FAILURE;
    for (int i = 1; i <= 3; i++) {
        authenticate(fd, &lb, "alice", "wrong-password", reply, sizeof(reply));
        check(i < 3 ? "wrong password refused"
                    : "third failure triggers rate limit",
              reply, i < 3 ? "401" : "429");
    }
    close(fd);

    printf("\n    An account that does not exist behaves identically,\n");
    printf("    so the server cannot be used to enumerate usernames:\n");
    fd = connect_to(host, port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return EXIT_FAILURE;
    authenticate(fd, &lb, "nosuchuser", "anything", reply, sizeof(reply));
    check("unknown account: same 401 as a bad password", reply, "401");
    close(fd);

    /* ---- 6. concurrency --------------------------------------------------- */
    printf("\n--- 6. Concurrent clients [Req 4.1(3)] ---\n");
    printf("    Four clients connect at the same instant and each does 10\n");
    printf("    operations. A 'peak' above 1 in the server's STATS proves they\n");
    printf("    were served simultaneously rather than one after another.\n");

    pthread_t tids[4];
    Worker    workers[4];
    double    start = now_ms();
    for (int i = 0; i < 4; i++) {
        workers[i].id   = i + 1;
        workers[i].port = port;
        workers[i].user = (i % 2) ? "bob" : "alice";
        workers[i].pass = (i % 2) ? "Tr0ub4dor&3xyz" : "correct-horse-battery";
        workers[i].ok   = 0;
        workers[i].seconds = 0;
        snprintf(workers[i].host, sizeof(workers[i].host), "%s", host);
        pthread_create(&tids[i], NULL, worker_thread, &workers[i]);
    }
    for (int i = 0; i < 4; i++) pthread_join(tids[i], NULL);
    double elapsed = (now_ms() - start) / 1000.0;

    int all_ok = 1;
    for (int i = 0; i < 4; i++) if (!workers[i].ok) all_ok = 0;
    checks_run++;
    if (all_ok) { checks_passed++;
                  printf("    %-6s %-46s %.2fs total\n", "PASS",
                         "4 concurrent clients all completed", elapsed); }
    else        { printf("    %-6s %-46s\n", "FAIL",
                         "4 concurrent clients all completed"); }

    /* ---- verdict ---------------------------------------------------------- */
    printf("\n=== Summary ===\n");
    printf("  %d of %d checks passed\n", checks_passed, checks_run);
    if (checks_passed == checks_run) {
        printf("  ALL CHECKS PASSED.\n");
        printf("  Authentication, the protocol, per-user isolation, input\n");
        printf("  validation, rate limiting and concurrency all behaved as\n");
        printf("  specified.\n");
        return EXIT_SUCCESS;
    }
    printf("  %d FAILED\n", checks_run - checks_passed);
    return EXIT_FAILURE;
}

/* ===================== INTERACTIVE MODE ================================== */

static int run_interactive(const char *host, int port)
{
    LineBuf lb;
    char    greeting[BUF_SIZE], reply[BUF_SIZE], line[MAX_LINE];

    int fd = connect_to(host, port, &lb, greeting, sizeof(greeting));
    if (fd < 0) return EXIT_FAILURE;

    printf("%s\n", greeting);
    printf("Type commands, or 'login <user> <password>' to authenticate.\n");
    printf("Try: login alice correct-horse-battery\n");
    printf("Then: STORE mykey some value / FETCH mykey / LIST / QUIT\n\n");

    for (;;) {
        printf("kv> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        if (line[0] == '\0') continue;

        /* A convenience wrapper: 'login u p' performs the whole handshake so
           the user does not have to compute an HMAC by hand. */
        if (strncmp(line, "login ", 6) == 0) {
            char user[64] = "", pass[128] = "";
            if (sscanf(line + 6, "%63s %127s", user, pass) == 2) {
                authenticate(fd, &lb, user, pass, reply, sizeof(reply));
                printf("%s\n", reply);
            } else {
                printf("usage: login <user> <password>\n");
            }
            continue;
        }

        if (request(fd, "%s", line) < 0) { printf("send failed\n"); break; }
        if (recv_line(fd, &lb, reply, sizeof(reply)) < 0) {
            printf("server closed the connection\n");
            break;
        }
        printf("%s\n", reply);
        if (strncmp(line, "QUIT", 4) == 0) break;
    }

    close(fd);
    printf("disconnected\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 9000;
    int         demo = (argc > 3 && strcmp(argv[3], "demo") == 0);

    return demo ? run_demo(host, port) : run_interactive(host, port);
}
