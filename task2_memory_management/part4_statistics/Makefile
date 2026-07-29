# Makefile for Task 2 - Part 4 (statistics and algorithm comparison)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = statistics

$(TARGET): statistics.c
	$(CC) $(CFLAGS) -o $(TARGET) statistics.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
