# Makefile for Task 1 - Part 4 (deadlock prevention)
CC      = cc
CFLAGS  = -Wall -Wextra -pthread -std=c11
TARGET  = deadlock

$(TARGET): deadlock.c
	$(CC) $(CFLAGS) -o $(TARGET) deadlock.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
