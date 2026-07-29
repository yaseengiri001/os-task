# Makefile for Task 2 - Part 2 (FIFO page replacement)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = fifo

$(TARGET): fifo.c
	$(CC) $(CFLAGS) -o $(TARGET) fifo.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
