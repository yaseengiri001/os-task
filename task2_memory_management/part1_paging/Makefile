# Makefile for Task 2 - Part 1 (paging system with configurable page size)
CC      = cc
CFLAGS  = -Wall -Wextra -std=c11
TARGET  = paging

$(TARGET): paging.c
	$(CC) $(CFLAGS) -o $(TARGET) paging.c

run: $(TARGET)
	./$(TARGET)

# Show the page-size trade-off by running the same workload at three sizes.
compare: $(TARGET)
	./$(TARGET) 128
	./$(TARGET) 256
	./$(TARGET) 512

clean:
	rm -f $(TARGET)

.PHONY: run compare clean
