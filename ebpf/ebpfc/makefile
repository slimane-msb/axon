# Compiler
CC = gcc

# Flags
CFLAGS = -Wall -Wextra -O2

# Target binary
TARGET = l3block

# Source file
SRC = l3block.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean install