# Makefile for Task 3 - shared crypto module self-test
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = test_vectors

$(TARGET): test_vectors.c sha256.c chacha20.c sha256.h chacha20.h
	$(CC) $(CFLAGS) -o $(TARGET) test_vectors.c sha256.c chacha20.c

test: $(TARGET)
	./$(TARGET)

run: test

clean:
	rm -f $(TARGET)

.PHONY: test run clean
