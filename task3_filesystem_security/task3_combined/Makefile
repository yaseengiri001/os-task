# Makefile for Task 3 - combined secure file manager
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = task3_combined
SRCS    = task3_combined.c ../common/sha256.c ../common/chacha20.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

run: $(TARGET)
	./$(TARGET)

# Non-interactive scripted walkthrough (used to capture output logs).
demo: $(TARGET)
	./$(TARGET) demo

clean:
	rm -f $(TARGET)
	rm -rf secure_files audit.log

.PHONY: run demo clean
