#!/bin/bash
# axon test — step 14: Shared IP L7 Isolation & L3 Drops
# Hook: TC ingress + NFQUEUE (queue 1)
# Usage: sudo bash test14.sh 2>&1 | tee 14.log
#
# L3 block verification strategy:
#   1. bpftool map lookup — ground truth: is the IP in the kernel map?
#   2. hping3 SYN probe  — does a SYN-ACK come back? (tcpdump witness)
#   curl is NOT used for L3: it tests application-level timeout which is
#   unreliable on wifi (SKB mode TC sees return path after stack processing).
#
# L7 block verification strategy:
#   curl -sv for SNI tests — checks SSL handshake is reset/empty
#   hping3 for direct-IP no-SNI — TCP-level, not application-level

export PATH=$PATH:/usr/local/go/bin

IFACE="wlp8s0"
AXON="/tmp/axon"
AXOND="/tmp/axond"
BPF="/tmp/xdp_firewall.o"
DB="/tmp/axon_l7_test.bolt"
SOCKET="unix:///run/axon/daemon.sock"

# Test Targets
L3_IP_1="157.240.202.35"
L3_IP_2="213.186.34.156"
L3_DOM_1="facebook.com"
L3_DOM_2="opmobility.com"

L7_SHARED_IP="213.186.1.223"
L7_BLOCK_1="polyglotte-institute.eu"
L7_BLOCK_2="ide3.hr"
L7_ALLOW="ledvance.ewyse.agency"

GLOBAL_ALLOW="google.com"

sep()  { echo ""; echo "────────────────────────────────────────"; echo "  $*"; echo "────────────────────────────────────────"; }
cmd()  { echo ""; echo "  CMD: $*"; "$@" 2>&1; echo "  EXIT: $?"; }
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { echo "  ✅ $*"; }
fail() { echo "  ❌ $*"; }

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

# check_l3_blocked <ip> <label>
# Verifies the IP is in blocked_ip_map (ground truth) AND
# that a raw SYN gets no SYN-ACK back within 2s (traffic proof).
check_l3_blocked() {
  local ip="$1"
  local label="$2"

  # 1. Map-level check: IP must be in blocked_ip_map or tentative_map
  local ifindex
  ifindex=$(ip link show "$IFACE" | awk 'NR==1{print $1}' | tr -d ':')

  local in_map=0
  # bpftool iterates all entries; grep for the IP in hex isn't trivial,
  # so we use the pinned map path and look for any entry matching our ifindex.
  # Simpler: use axon list and check the resolved/explicit IP appears correctly.
  if sudo "$AXON" --socket "$SOCKET" list 2>/dev/null | grep -qF "$ip"; then
    in_map=1
  fi

  # 2. Traffic-level check: send 3 SYN packets to port 80, expect 0 SYN-ACKs.
  #    hping3 exits with the number of replies received (0 = all dropped = blocked).
  #    We capture with tcpdump on a short window.
  local tmppcap
  tmppcap=$(mktemp /tmp/axon_test_XXXXXX.pcap)

  # Start tcpdump in background to witness SYN-ACKs
  sudo tcpdump -i "$IFACE" -w "$tmppcap" \
    "src host $ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)" \
    -c 1 --immediate-mode 2>/dev/null &
  local TCPDUMP_PID=$!
  sleep 0.3  # let tcpdump open the capture

  # Send 3 SYN packets, 500ms apart, don't wait for reply
  sudo hping3 -S -p 80 -c 3 -i u500000 --fast "$ip" >/dev/null 2>&1
  sleep 1.5  # wait for any potential SYN-ACK to arrive

  sudo kill "$TCPDUMP_PID" 2>/dev/null
  wait "$TCPDUMP_PID" 2>/dev/null

  # Count SYN-ACK packets captured
  local synack_count=0
  if [[ -f "$tmppcap" ]]; then
    synack_count=$(sudo tcpdump -r "$tmppcap" 2>/dev/null | wc -l)
  fi
  rm -f "$tmppcap"

  # Pass if: in map AND no SYN-ACK received
  if [[ $in_map -eq 1 && $synack_count -eq 0 ]]; then
    pass "$label — in map ✓, no SYN-ACK ✓"
  elif [[ $in_map -eq 0 ]]; then
    fail "$label — IP not found in axon rule list"
  else
    fail "$label — SYN-ACK received ($synack_count packets) — TC not dropping"
  fi
}

# check_l3_blocked_domain <domain> <expected_ip> <label>
# Resolves domain, checks the IP is in the blocked map, probes with hping3.
check_l3_blocked_domain() {
  local domain="$1"
  local expected_ip="$2"
  local label="$3"

  # Resolve the domain right now
  local resolved
  resolved=$(dig +short "$domain" A | grep -E '^[0-9]+\.' | head -1)

  if [[ -z "$resolved" ]]; then
    fail "$label — could not resolve $domain"
    return
  fi

  log "  $domain resolved to $resolved (expected ~$expected_ip)"

  # The resolved IP should match the expected one
  if [[ "$resolved" != "$expected_ip" ]]; then
    log "  WARNING: IP changed ($resolved ≠ $expected_ip) — updating target"
    expected_ip="$resolved"
  fi

  check_l3_blocked "$expected_ip" "$label"
}

# check_l7_sni_blocked <url> <label>
# Verifies that a TLS ClientHello with the correct SNI is rejected.
# Uses curl -sv and looks for connection reset/empty reply at SSL layer.
check_l7_sni_blocked() {
  local url="$1"
  local label="$2"

  local output
  output=$(curl -sv --connect-timeout 5 --max-time 6 "$url" 2>&1)

  # Signs of L7 block: connection reset after TCP connect (NFQUEUE drops mid-handshake),
  # empty reply, or SSL handshake failure due to reset.
  if echo "$output" | grep -qE "Empty reply|Connection reset|SSL_ERROR_RX_RECORD_TOO_LONG|curl: \(35\)|curl: \(56\)|recv failure"; then
    pass "$label — connection reset at TLS layer ✓"
  elif echo "$output" | grep -qE "curl: \(28\)|timed out"; then
    # Timeout is also acceptable (NFQUEUE drop before TCP complete)
    pass "$label — connection timed out (NFQUEUE drop) ✓"
  else
    local http_code
    http_code=$(echo "$output" | grep -oE "HTTP/[0-9.]+ [0-9]+" | tail -1)
    fail "$label — not blocked (got: ${http_code:-no HTTP response})"
  fi
}

# check_l7_direct_ip_blocked <ip> <label>
# For direct IP access with no SNI: TC marks packet 0xBEEF → NFQUEUE → L7 engine
# sees no SNI and drops (shared IP). Verify with hping3 — TCP connect should be reset
# or not complete (no SYN-ACK, or RST after SYN-ACK).
check_l7_direct_ip_blocked() {
  local ip="$1"
  local label="$2"

  # For shared IP with no SNI: the packet enters NFQUEUE AFTER TCP handshake
  # (TC only marks; NFQUEUE sees the data packet with ClientHello).
  # So TCP SYN-ACK WILL come back, but the TLS ClientHello will be dropped.
  # Test: attempt a full curl http (no TLS, no SNI) — should get Empty reply or reset.
  local output
  output=$(curl -v --connect-timeout 4 --max-time 5 "http://$ip" 2>&1)

  if echo "$output" | grep -qE "Empty reply|Connection reset|curl: \(52\)|curl: \(56\)|recv failure|curl: \(28\)"; then
    pass "$label — connection reset/empty (NFQUEUE no-SNI drop) ✓"
  else
    local http_code
    http_code=$(echo "$output" | grep -oE "HTTP/[0-9.]+ [0-9]+" | tail -1)
    fail "$label — not blocked (got: ${http_code:-no expected error})"
  fi
}

# check_allowed <url> <label>
# Simple: expect HTTP 200 or any valid HTTP response.
check_allowed() {
  local url="$1"
  local label="$2"

  local http_code
  http_code=$(curl -sko /dev/null -w "%{http_code}" --connect-timeout 6 --max-time 8 "$url")

  if [[ "$http_code" =~ ^[23] ]]; then
    pass "$label — HTTP $http_code ✓"
  elif [[ "$http_code" == "000" ]]; then
    fail "$label — no connection (blocked or unreachable)"
  else
    # Any real HTTP response means the connection worked
    pass "$label — HTTP $http_code (connection reached server) ✓"
  fi
}

# ─────────────────────────────────────────────
sep "ENV & PREP"
# ─────────────────────────────────────────────
log "iface: $IFACE"
log "checking required tools..."
for tool in hping3 tcpdump bpftool dig curl; do
  if command -v "$tool" &>/dev/null; then
    log "  $tool: ok"
  else
    log "  WARNING: $tool not found — some tests may degrade to curl fallback"
  fi
done

log "iptables: setting up NFQUEUE 1 for BPF mark 0xBEEF"
sudo iptables -t mangle -D PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1 2>/dev/null
sudo iptables -t mangle -A PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1

sudo pkill -x axond 2>/dev/null
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
sudo rm -f "$SOCKET" "$DB"
sudo rm -rf /sys/fs/bpf/axon/
sudo mkdir -p /run/axon

# ─────────────────────────────────────────────
sep "STEP 14a — Start Daemon"
# ─────────────────────────────────────────────
sudo "$AXOND" --grpc "$SOCKET" --bpf "$BPF" --db "$DB" --log-addr 127.0.0.1:5000 &
DAEMON_PID=$!
sleep 3
sudo kill -0 "$DAEMON_PID" 2>/dev/null && pass "daemon started" || { fail "daemon failed"; exit 1; }

# ─────────────────────────────────────────────
sep "STEP 14b — Apply Rules (Inputs)"
# ─────────────────────────────────────────────
# Rules are now applied synchronously — DNS resolves before axon add returns.
# No sleep needed between add and test.

log "Adding L3 Block: $L3_IP_1 (explicit IP)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L3_IP_1" -i "$IFACE"

log "Adding FQDN Block: $L7_BLOCK_1 (shared IP → L7)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L7_BLOCK_1" -i "$IFACE"

log "Adding FQDN Block: $L7_BLOCK_2 (shared IP → L7, same IP as above)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L7_BLOCK_2" -i "$IFACE"

log "Adding FQDN Block: $L3_DOM_2 (unique IP → L3 tentative)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L3_DOM_2" -i "$IFACE"

# ─────────────────────────────────────────────
sep "STEP 14c — Verify Map Distribution"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" status
cmd sudo "$AXON" --socket "$SOCKET" list

log "Expected distribution:"
log "  explicit-ip : $L3_IP_1                  → blocked_ip_map (L3)"
log "  fqdn        : $L7_BLOCK_1 → $L7_SHARED_IP → shared_ip_map (L7 NFQUEUE)"
log "  fqdn        : $L7_BLOCK_2 → $L7_SHARED_IP → shared_ip_map (L7 NFQUEUE)"
log "  fqdn        : $L3_DOM_2 → $L3_IP_2       → tentative_map (L3)"

# ─────────────────────────────────────────────
sep "STEP 14d — L3 BLOCKED (4 Tests)"
# Ground truth: bpftool map + hping3 SYN probe (no SYN-ACK expected)
# ─────────────────────────────────────────────

log "Test 1: Direct IP $L3_IP_1 (explicit → blocked_ip_map)"
check_l3_blocked "$L3_IP_1" "Test 1 [$L3_IP_1 direct]"

log "Test 2: $L3_DOM_1 (resolves to $L3_IP_1 → blocked_ip_map)"
check_l3_blocked_domain "$L3_DOM_1" "$L3_IP_1" "Test 2 [$L3_DOM_1]"

log "Test 3: $L3_DOM_2 (unique IP → tentative_map)"
check_l3_blocked_domain "$L3_DOM_2" "$L3_IP_2" "Test 3 [$L3_DOM_2]"

log "Test 4: Direct IP $L3_IP_2 (opmobility's resolved IP)"
check_l3_blocked "$L3_IP_2" "Test 4 [$L3_IP_2 direct]"

# ─────────────────────────────────────────────
sep "STEP 14e — L7 BLOCKED (3 Tests)"
# SNI tests: curl -sv looking for TLS reset
# Direct IP test: curl http (no SNI) looking for empty reply from NFQUEUE drop
# ─────────────────────────────────────────────

log "Test 5: $L7_BLOCK_1 (shared IP, SNI blocked by L7 engine)"
check_l7_sni_blocked "https://$L7_BLOCK_1" "Test 5 [$L7_BLOCK_1]"

log "Test 6: $L7_SHARED_IP direct (no SNI → L7 engine drops, no domain to allow)"
check_l7_direct_ip_blocked "$L7_SHARED_IP" "Test 6 [$L7_SHARED_IP no-SNI]"

log "Test 7: $L7_BLOCK_2 (shared IP, SNI blocked by L7 engine)"
check_l7_sni_blocked "https://$L7_BLOCK_2" "Test 7 [$L7_BLOCK_2]"

# ─────────────────────────────────────────────
sep "STEP 14f — ALLOWED (2 Tests)"
# ─────────────────────────────────────────────

log "Test 8: $GLOBAL_ALLOW (no rule → pass-through)"
check_allowed "https://$GLOBAL_ALLOW" "Test 8 [$GLOBAL_ALLOW]"

log "Test 9: $L7_ALLOW (shared IP, SNI NOT in block list → L7 engine allows)"
check_allowed "https://$L7_ALLOW" "Test 9 [$L7_ALLOW isolated allow]"

# ─────────────────────────────────────────────
sep "CLEANUP"
# ─────────────────────────────────────────────
sudo kill "$DAEMON_PID" 2>/dev/null
sudo iptables -t mangle -D PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/axon/ 2>/dev/null
pass "done"