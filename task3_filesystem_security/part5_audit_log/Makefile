# Makefile for Task 3 - Part 5 (audit logging)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = audit_log
SRCS    = audit_log.c ../common/sha256.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf secure_files shadow.db audit.log salary.enc perm_demo.txt

.PHONY: run clean
