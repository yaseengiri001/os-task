# Makefile for Task 1 - Combined (all four parts in one menu program)
# -O0 keeps the race condition in demo 2 visible; an optimiser can hoist the
# increment out of the loop and hide it.
CC      = cc
CFLAGS  = -Wall -Wextra -pthread -std=c11 -O0
TARGET  = task1_combined

$(TARGET): task1_combined.c
	$(CC) $(CFLAGS) -o $(TARGET) task1_combined.c

run: $(TARGET)
	./$(TARGET)

# Non-interactive: runs demos 1-4 back to back (used to capture output logs)
all-demos: $(TARGET)
	./$(TARGET) all

clean:
	rm -f $(TARGET)

.PHONY: run all-demos clean
