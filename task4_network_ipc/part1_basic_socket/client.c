/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 1 of 4: A basic TCP client
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 4.1(1), second half: "Create both server and client
 *   applications using sockets."
 *
 * THE CLIENT SIDE IS SHORTER THAN THE SERVER SIDE
 *   socket()   ask the kernel for an endpoint
 *   connect()  reach out to a specific address and port
 *   send/recv  exchange data
 *   close()    hang up
 *
 *   There is no bind(), listen() or accept(): the client does not need a fixed
 *   port of its own, so the kernel assigns it a temporary ("ephemeral") one
 *   automatically. That asymmetry is the whole client/server distinction - the
 *   server waits at a known address, the client knows where to find it.
 *
 * THE MOST IMPORTANT IDEA IN THIS FILE
 *   TCP IS A BYTE STREAM, NOT A MESSAGE STREAM.
 *
 *   Sending "HELLO\n" then "WORLD\n" does NOT guarantee two recv() calls
 *   returning one line each. The receiver may get:
 *       "HELLO\nWORLD\n"   both at once     (coalesced)
 *       "HEL"              a fragment       (split)
 *       "LO\nWOR" ...      an arbitrary cut anywhere
 *
 *   TCP guarantees the bytes arrive in order and without corruption. It
 *   guarantees NOTHING about where one recv() ends and the next begins. Code
 *   that assumes "one send = one recv" works perfectly on localhost, where
 *   messages are small and fast, and then fails in production across a real
 *   network. It is the single most common networking bug.
 *
 *   The fix is FRAMING: the application must mark where messages end. This
 *   client uses a newline as the delimiter and recv_line() below reassembles
 *   whole lines from however the bytes actually arrive. Part 3 formalises this
 *   into a documented protocol.
 *
 * BUILD & RUN
 *   ./client 127.0.0.1 9001
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024

/* Send a whole buffer, looping because send() may be partial. */
static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Read exactly one newline-terminated line, however the bytes arrive.
 *
 * This is the framing layer described in the header. A static buffer holds
 * whatever was received but not yet consumed, so data belonging to the NEXT
 * line is never thrown away. Without this, a recv() that happened to return
 * one and a half lines would silently lose the half.
 *
 * Returns the line length, 0 on clean disconnect, -1 on error.
 */
static ssize_t recv_line(int fd, char *out, size_t outsz)
{
    static char   buffer[BUF_SIZE * 4];
    static size_t buffered = 0;

    for (;;) {
        /* Is a complete line already sitting in the buffer? */
        for (size_t i = 0; i < buffered; i++) {
            if (buffer[i] == '\n') {
                size_t linelen = i;
                if (linelen >= outsz) linelen = outsz - 1;
                memcpy(out, buffer, linelen);
                out[linelen] = '\0';

                /* Shift the remainder down; it belongs to the next line. */
                memmove(buffer, buffer + i + 1, buffered - i - 1);
                buffered -= i + 1;
                return (ssize_t)linelen;
            }
        }

        if (buffered >= sizeof(buffer)) {
            /* A line longer than the buffer. Refusing is the safe response -
               growing without limit is how a peer exhausts our memory. */
            fprintf(stderr, "[client] line too long, refusing\n");
            return -1;
        }

        ssize_t n = recv(fd, buffer + buffered, sizeof(buffer) - buffered, 0);
        if (n == 0)  return 0;                       /* peer closed cleanly */
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        buffered += (size_t)n;
    }
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
    int         port = (argc > 2) ? atoi(argv[2]) : 9001;

    /* ---- 1. socket() ----------------------------------------------------- */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* ---- 2. Build the server's address ----------------------------------- */
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons((uint16_t)port);

    /* inet_pton parses dotted-quad text into a binary address. It returns 0
       for a malformed address and -1 for a bad family, so both are checked -
       treating "not 1" as success would silently connect to address 0. */
    int rc = inet_pton(AF_INET, host, &server.sin_addr);
    if (rc != 1) {
        fprintf(stderr, "[client] '%s' is not a valid IPv4 address\n", host);
        close(fd);
        return EXIT_FAILURE;
    }

    /* ---- 3. connect() ----------------------------------------------------
     * This performs the TCP three-way handshake (SYN, SYN-ACK, ACK). It fails
     * with ECONNREFUSED if nothing is listening on that port - which is the
     * error to expect if the server has not been started yet.               */
    printf("[client] connecting to %s:%d ...\n", host, port);
    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "[client] connect failed: %s\n", strerror(errno));
        if (errno == ECONNREFUSED)
            fprintf(stderr, "[client] (is the server running on port %d?)\n", port);
        close(fd);
        return EXIT_FAILURE;
    }
    printf("[client] connected\n\n");

    /* ---- 4. Exchange some messages --------------------------------------- */
    const char *messages[] = {
        "Hello from the client",
        "Operating Systems and Security",
        "Task 4: network programming",
        "QUIT"
    };
    int count = (int)(sizeof(messages) / sizeof(messages[0]));

    for (int i = 0; i < count; i++) {
        char line[BUF_SIZE];
        int  len = snprintf(line, sizeof(line), "%s\n", messages[i]);

        printf("[client] sending  : \"%s\"\n", messages[i]);
        if (send_all(fd, line, (size_t)len) < 0) {
            perror("[client] send");
            break;
        }

        char reply[BUF_SIZE];
        ssize_t n = recv_line(fd, reply, sizeof(reply));
        if (n == 0) {
            printf("[client] server closed the connection\n");
            break;
        }
        if (n < 0) {
            perror("[client] recv");
            break;
        }
        printf("[client] received : \"%s\"\n\n", reply);
    }

    /* ---- 5. close() ------------------------------------------------------
     * Closing sends FIN, telling the server we are finished. The server's
     * recv() then returns 0, which is how it learns to stop.                */
    close(fd);
    printf("[client] disconnected cleanly\n");
    return EXIT_SUCCESS;
}
