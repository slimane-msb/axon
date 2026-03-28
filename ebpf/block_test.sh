#!/bin/bash

INTERFACE="wlp8s0"
BAD_IP="185.99.197.3"
GOOD_IP="8.8.8.8"

# Helper to check ping
is_reachable() {
    ping -c 1 -W 1 "$1" > /dev/null 2>&1
}

echo "--- Starting eBPF IP Blocker Test ---"

# 1. Initial State: Both should be reachable
echo "[LOG] Step 1: Initial connectivity check..."
for IP in "$BAD_IP" "$GOOD_IP"; do
    if is_reachable "$IP"; then
        echo "[PASS] $IP is reachable."
    else
        echo "[FAIL] $IP is unreachable before test. Check your internet connection."
        exit 1
    fi
done

# 2. Add Block: Bad IP should be blocked, Good IP should remain reachable
echo -e "\n[LOG] Step 2: Blocking $BAD_IP..."
sudo ./block_ip "$INTERFACE" "$BAD_IP" add

if ! is_reachable "$BAD_IP"; then
    echo "[PASS] $BAD_IP is successfully blocked."
else
    echo "[FAIL] $BAD_IP is still reachable after block command."
    exit 1
fi

if is_reachable "$GOOD_IP"; then
    echo "[PASS] $GOOD_IP remains reachable (No collateral damage)."
else
    echo "[FAIL] $GOOD_IP was accidentally blocked!"
    sudo ./block_ip "$INTERFACE" "$BAD_IP" remove # Cleanup
    exit 1
fi

# 3. Remove Block: Both should be reachable again
echo -e "\n[LOG] Step 3: Removing block from $BAD_IP..."
sudo ./block_ip "$INTERFACE" "$BAD_IP" remove

if is_reachable "$BAD_IP"; then
    echo "[PASS] $BAD_IP is reachable again."
else
    echo "[FAIL] $BAD_IP remains blocked after removal."
    exit 1
fi

if is_reachable "$GOOD_IP"; then
    echo "[PASS] $GOOD_IP is still reachable."
else
    echo "[FAIL] $GOOD_IP is suddenly unreachable."
    exit 1
fi

echo -e "\n[RESULT] All tests passed! The eBPF program is selective and reversible."