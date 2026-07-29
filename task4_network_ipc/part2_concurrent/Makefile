# Makefile for Task 4 - Part 2 (concurrent server, thread per client)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -pthread
PORT    = 9002
N       = 4

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

# Start the server, then launch N clients at once against it.
demo: all
	@./server $(PORT) $(N) & \
	 SRV=$$!; sleep 1; ./client 127.0.0.1 $(PORT) $(N); wait $$SRV

clean:
	rm -f server client

.PHONY: all demo clean
