# Makefile for Task 2 - Part 3 (LRU page replacement)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = lru

$(TARGET): lru.c
	$(CC) $(CFLAGS) -o $(TARGET) lru.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
