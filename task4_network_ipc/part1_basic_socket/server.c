/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 1 of 4: A basic TCP server (one client at a time)
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 4.1(1), first half: "Create both server and client
 *   applications using sockets."
 *
 * WHAT A SOCKET IS
 *   A socket is the operating system's endpoint for communication. Like a file,
 *   it is referred to by a small integer descriptor, and the same read() and
 *   write() calls work on it - which is exactly why Unix models it that way.
 *   The difference is that the other end may be a process on another machine.
 *
 * THE FIVE CALLS EVERY TCP SERVER MAKES
 *   socket()   ask the kernel for an endpoint
 *   bind()     claim a specific port number on this machine
 *   listen()   mark the socket passive: start queueing incoming connections
 *   accept()   take the next queued connection; returns a NEW descriptor
 *   close()    release it
 *
 *   The client's side is much shorter: socket(), then connect().
 *
 * THE DETAIL THAT CONFUSES EVERYONE FIRST TIME
 *   accept() does NOT return the listening socket. It returns a brand-new
 *   descriptor for THIS ONE conversation, while the listening socket stays open
 *   to receive the next client. Two descriptors, two different jobs: one is a
 *   receptionist, the other is the actual phone call.
 *
 * THE LIMITATION THIS PART DELIBERATELY HAS
 *   The loop below handles one client through to completion before calling
 *   accept() again. A second client simply waits, and one slow client blocks
 *   everybody. That is the problem Part 2 solves with threads - the same way
 *   Task 1 Part 1 avoided shared data so that Part 2 could show why
 *   synchronization is needed.
 *
 * WHY SO_REUSEADDR IS SET
 *   After a server closes, the port sits in TIME_WAIT for up to two minutes.
 *   This is not a bug: TCP holds it so that late packets from the old
 *   connection cannot be delivered to a new one. Without SO_REUSEADDR a
 *   restarted server fails with "Address already in use", which is why almost
 *   every server sets it.
 *
 * BUILD & RUN
 *   make                       # builds server and client
 *   ./server 9001              # terminal 1  (serves 3 clients then exits)
 *   ./client 127.0.0.1 9001    # terminal 2
 *   ./server 9001 2            # serve exactly 2 clients then exit
 *   make demo                  # runs both automatically
 *
 *   The client limit exists only so the program terminates on its own and can
 *   be captured in a log; a real server would loop until it was stopped.
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 9001
#define BACKLOG      8      /* how many connections may queue awaiting accept */
#define BUF_SIZE     1024
#define DEFAULT_MAX_CLIENTS 3   /* stop after this many, so the demo terminates */

/* Set by the signal handler so the accept loop can exit cleanly.
   volatile sig_atomic_t is the only type it is safe to touch from a handler. */
static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

/*
 * Send a whole buffer.
 *
 * This helper exists because send() may transmit FEWER bytes than asked - the
 * kernel's send buffer can simply be full. Assuming one send() call transmits
 * everything is one of the most common and most intermittent networking bugs,
 * because it only shows up under load or with large messages.
 */
static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;      /* interrupted: just retry */
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv)
{
    /* Line-buffer the log. When stdout is a pipe or a file it is fully
       buffered by default, so log lines can sit unwritten for a long time
       and appear out of order relative to the other process. A server log
       is only useful if it appears as events happen. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int port        = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    int max_clients = (argc > 2) ? atoi(argv[2]) : DEFAULT_MAX_CLIENTS;

    signal(SIGINT, handle_sigint);

    /*
     * Ignore SIGPIPE. If we write to a socket whose peer has already closed,
     * the default action is to KILL the process. For a server that means one
     * client disconnecting at the wrong moment takes the whole service down.
     * Ignoring it turns the event into an EPIPE error we can handle.
     */
    signal(SIGPIPE, SIG_IGN);

    /* ---- 1. socket() ------------------------------------------------------
     * AF_INET = IPv4, SOCK_STREAM = TCP (reliable, ordered byte stream).
     * The alternative, SOCK_DGRAM, would be UDP: faster, but messages can be
     * lost, duplicated or reordered, and the application must cope.          */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* ---- 2. SO_REUSEADDR - see the header note on TIME_WAIT -------------- */
    int yes = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    /* ---- 3. bind() - claim the port --------------------------------------
     * htons() converts the port to network byte order (big-endian). Machines
     * differ in how they store integers, so every multi-byte value on the wire
     * has an agreed order; forgetting this conversion is why a server can
     * appear on port 4383 when 9001 was intended.                            */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);   /* accept on any interface */
    addr.sin_port        = htons((uint16_t)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind to port %d failed: %s\n", port, strerror(errno));
        close(listen_fd);
        return EXIT_FAILURE;
    }

    /* ---- 4. listen() - become a passive socket ---------------------------
     * BACKLOG is the length of the queue of connections the kernel completes
     * on our behalf before we have called accept(). If it fills, further
     * connection attempts are refused.                                       */
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    printf("[server] listening on port %d (backlog %d)\n", port, BACKLOG);
    printf("[server] one client at a time - this is what Part 2 fixes\n");
    printf("[server] will exit after %d client(s), or on Ctrl-C\n\n", max_clients);

    int served = 0;

    while (keep_running && served < max_clients) {
        struct sockaddr_in client_addr;
        socklen_t          client_len = sizeof(client_addr);

        /* ---- 5. accept() - returns a NEW descriptor for this client ------ */
        int client_fd = accept(listen_fd,
                               (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;       /* Ctrl-C interrupted us */
            perror("accept");
            break;
        }

        /* Turn the client's address into readable text for the log. */
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        printf("[server] client %d connected from %s:%d\n",
               served + 1, ip, ntohs(client_addr.sin_port));

        /* ---- Serve this one client: echo whatever it sends --------------- */
        char buf[BUF_SIZE];
        for (;;) {
            ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);

            if (n == 0) {
                /* An orderly shutdown by the peer. Zero from recv() means
                   end-of-stream, NOT an error - a distinction that matters. */
                printf("[server] client disconnected\n");
                break;
            }
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("[server] recv");
                break;
            }

            buf[n] = '\0';
            /* Strip the trailing newline for tidy logging. */
            char *nl = strpbrk(buf, "\r\n");
            if (nl) *nl = '\0';

            printf("[server]   received: \"%s\" (%zd bytes)\n", buf, n);

            if (strcmp(buf, "QUIT") == 0) {
                send_all(client_fd, "BYE\n", 4);
                printf("[server]   client asked to quit\n");
                break;
            }

            char reply[BUF_SIZE + 16];
            int  rlen = snprintf(reply, sizeof(reply), "ECHO %s\n", buf);
            if (send_all(client_fd, reply, (size_t)rlen) < 0) {
                perror("[server] send");
                break;
            }
        }

        /* Always close the per-client descriptor. Leaking it exhausts the
           process's file-descriptor limit and the server eventually stops
           being able to accept anyone at all. */
        close(client_fd);
        served++;
        printf("[server] connection closed (%d of %d served)\n\n",
               served, max_clients);
    }

    close(listen_fd);
    printf("[server] shut down cleanly after %d client(s)\n", served);
    return EXIT_SUCCESS;
}
