# Makefile for axon BPF firewall tests
# Usage:
#   make test-xdp    — compile BPF + userspace, run BPF_PROG_TEST_RUN unit tests
#   make test-lo     — compile BPF + live runner, attach to lo, real UDP packet tests
#   make test-wifi   — compile BPF + live runner, lo tests + wlp8s0 attach/detach
#   make all         — build everything (no run)
#   make clean       — remove all build artifacts
#   make deps        — install required packages

CC        = gcc
BPF_CC    = clang
CFLAGS    = -O2 -Wall -Wextra
LDFLAGS   = -lbpf -lelf -lz
BPF_FLAGS = -O2 -g -target bpf -I /usr/include/$(shell uname -m)-linux-gnu

WIFI_IFACE ?= wlp8s0

BPF_SRC       = xdp_firewall.c
BPF_OBJ       = /tmp/xdp_firewall.o
TEST_XDP_SRC  = test_firewall.c
TEST_XDP_BIN  = test_firewall
TEST_LIVE_SRC = test_firewall_live.c
TEST_LIVE_BIN = test_firewall_live

.PHONY: all test-xdp test-lo test-wifi clean deps

# ── Build targets ────────────────────────────────────────────

all: $(BPF_OBJ) $(TEST_XDP_BIN) $(TEST_LIVE_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CC) $(BPF_FLAGS) -c $< -o $@

$(TEST_XDP_BIN): $(TEST_XDP_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TEST_LIVE_BIN): $(TEST_LIVE_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# ── Test targets ─────────────────────────────────────────────

# BPF_PROG_TEST_RUN unit tests (no real interface, no pinning)
test-xdp: $(BPF_OBJ) $(TEST_XDP_BIN)
	sudo ./$(TEST_XDP_BIN) $(BPF_OBJ)

# Live packet tests on loopback only
test-lo: $(BPF_OBJ) $(TEST_LIVE_BIN)
	sudo ./$(TEST_LIVE_BIN) $(BPF_OBJ)

# Live packet tests on loopback + attach/detach on WiFi interface
test-wifi: $(BPF_OBJ) $(TEST_LIVE_BIN)
	sudo ./$(TEST_LIVE_BIN) $(BPF_OBJ) $(WIFI_IFACE)

# ── Utilities ────────────────────────────────────────────────

deps:
	sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev clang llvm

clean:
	rm -f $(TEST_XDP_BIN) $(TEST_LIVE_BIN) $(BPF_OBJ)