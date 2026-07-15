# Makefile for Task 1 - Part 3 (round-robin scheduler simulation)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = round_robin

$(TARGET): round_robin.c
	$(CC) $(CFLAGS) -o $(TARGET) round_robin.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
