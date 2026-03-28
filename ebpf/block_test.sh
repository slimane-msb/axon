#!/bin/bash

INTERFACE="wlp8s0"
IP="185.99.197.3"

# Helper to check ping and return 0 (reachable) or 1 (blocked)
is_reachable() {
    ping -c 1 -W 1 "$IP" > /dev/null 2>&1
}

# 1. Initial State (Expected: Reachable)
echo "[LOG] Step 1: Initial connectivity check..."
if is_reachable; then
    echo "[PASS] $IP is reachable as expected."
else
    echo "[FAIL] $IP is blocked before test started."
    exit 1
fi

# 2. Add Block (Expected: Blocked)
echo -e "\n[LOG] Step 2: Applying eBPF block..."
sudo ./block_ip "$INTERFACE" "$IP" add
if ! is_reachable; then
    echo "[PASS] $IP is successfully blocked."
else
    echo "[FAIL] $IP is still reachable after block command."
    exit 1
fi

# 3. Remove Block (Expected: Reachable)
echo -e "\n[LOG] Step 3: Removing eBPF block..."
sudo ./block_ip "$INTERFACE" "$IP" remove
if is_reachable; then
    echo "[PASS] $IP is reachable again."
else
    echo "[FAIL] $IP remains blocked after removal."
    exit 1
fi

echo -e "\n[RESULT] All tests passed successfully."