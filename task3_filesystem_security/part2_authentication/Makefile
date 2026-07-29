# Makefile for Task 3 - Part 2 (authentication)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = auth
SRCS    = auth.c ../common/sha256.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf secure_files shadow.db audit.log salary.enc perm_demo.txt

.PHONY: run clean
