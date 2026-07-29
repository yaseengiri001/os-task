# Makefile for Task 4 - Part 3 (protocol, authentication, validation)
#
# The HMAC used by the challenge-response handshake is the SAME implementation
# written for Task 3. Cryptographic code is linked, never copied: a defect
# found later must have exactly one place to be fixed.
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -pthread
CRYPTO  = ../../task3_filesystem_security/common/sha256.c
PORT    = 9003

all: server client

server: server.c $(CRYPTO)
	$(CC) $(CFLAGS) -o server server.c $(CRYPTO)

client: client.c $(CRYPTO)
	$(CC) $(CFLAGS) -o client client.c $(CRYPTO)

demo: all
	@./server $(PORT) 4 & \
	 SRV=$$!; sleep 1; ./client 127.0.0.1 $(PORT); wait $$SRV

clean:
	rm -f server client

.PHONY: all demo clean
