# Makefile for Task 2 - combined menu-driven simulator
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = task2_combined

$(TARGET): task2_combined.c
	$(CC) $(CFLAGS) -o $(TARGET) task2_combined.c

run: $(TARGET)
	./$(TARGET)

# Non-interactive: runs every demo back to back (used to capture output logs).
all-demos: $(TARGET)
	./$(TARGET) all

clean:
	rm -f $(TARGET)

.PHONY: run all-demos clean
