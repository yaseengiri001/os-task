# Makefile for Task 3 - Part 4 (encryption)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = encryption
SRCS    = encryption.c ../common/sha256.c ../common/chacha20.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf secure_files shadow.db audit.log salary.enc perm_demo.txt

.PHONY: run clean
