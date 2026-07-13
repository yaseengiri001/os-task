# Makefile for Task 1 - Part 2 (synchronization)
# NOTE: no -O optimisation, so the race condition stays visible.
CC      = cc
CFLAGS  = -Wall -Wextra -pthread -std=c11
TARGET  = sync_demo

$(TARGET): sync_demo.c
	$(CC) $(CFLAGS) -o $(TARGET) sync_demo.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
