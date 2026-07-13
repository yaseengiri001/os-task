# Makefile for Task 1 - Part 1 (thread creation)
CC      = cc
CFLAGS  = -Wall -Wextra -pthread -std=c11
TARGET  = threads_demo

$(TARGET): threads_demo.c
	$(CC) $(CFLAGS) -o $(TARGET) threads_demo.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
