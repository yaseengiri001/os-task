# Makefile for Task 4 - the combined client-server application
#
# The HMAC used by the challenge-response handshake is the SAME implementation
# written for Task 3. Cryptographic code is linked, never copied, so a defect
# found later has exactly one place to be fixed.
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -pthread
CRYPTO  = ../../task3_filesystem_security/common/sha256.c
PORT    = 9000

all: server client

server: server.c $(CRYPTO)
	$(CC) $(CFLAGS) -o server server.c $(CRYPTO)

client: client.c $(CRYPTO)
	$(CC) $(CFLAGS) -o client client.c $(CRYPTO)

# Scripted end-to-end run: starts the server, runs every check, stops.
demo: all
	@./server $(PORT) 12 & \
	 SRV=$$!; sleep 1; ./client 127.0.0.1 $(PORT) demo; RC=$$?; \
	 wait $$SRV; exit $$RC

clean:
	rm -f server client

.PHONY: all demo clean
