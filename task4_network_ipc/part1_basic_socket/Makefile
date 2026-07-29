# Makefile for Task 4 - Part 1 (basic TCP socket, one client at a time)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
PORT    = 9001

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

# Start the server in the background, run one client, then wait for the
# server to finish. This is how the captured output logs are produced.
demo: all
	@./server $(PORT) & \
	 SRV=$$!; sleep 1; ./client 127.0.0.1 $(PORT); wait $$SRV

clean:
	rm -f server client

.PHONY: all demo clean
