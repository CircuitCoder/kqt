CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = test-runner

all: $(TARGET)

$(TARGET): test-runner.c
	$(CC) $(CFLAGS) -o $(TARGET) test-runner.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
