# Makefile for axon BPF unit tests
CC       = gcc
BPF_CC   = clang
CFLAGS   = -O2 -Wall -Wextra
LDFLAGS  = -lbpf -lelf -lz
BPF_FLAGS = -O2 -g -target bpf -I /usr/include/$(shell uname -m)-linux-gnu

# Files
BPF_SRC  = xdp_firewall.c
BPF_OBJ  = /tmp/xdp_firewall.o
TEST_SRC = test_firewall.c
TARGET   = test_firewall

.PHONY: all test clean deps run_all

# The default 'make' now builds both the BPF object and the test runner
all: $(BPF_OBJ) $(TARGET)

# Rule to compile the BPF program
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CC) $(BPF_FLAGS) -c $< -o $@

# Rule to compile the Userspace test runner
$(TARGET): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build, Run, and Clean immediately after
run_all: clean all
	sudo ./$(TARGET) $(BPF_OBJ)
	$(MAKE) clean

# Standard test runner
test: all
	sudo ./$(TARGET) $(BPF_OBJ)

deps:
	sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev clang llvm

clean:
	rm -f $(TARGET) $(BPF_OBJ)