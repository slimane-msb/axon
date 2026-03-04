#!/bin/bash
# axon test — step 14: Shared IP L7 Isolation & L3 Drops
# Hook: TC egress (outgoing ClientHello) + NFQUEUE OUTPUT chain
# Usage: sudo bash test14.sh 2>&1 | tee 14.log
#
# Direction fix:
#   BEFORE (broken): TC ingress marks incoming packets → NFQUEUE sees SYN-ACK/response,
#                    never sees the outgoing ClientHello SNI → always accepts.
#   AFTER  (fixed):  TC egress marks outgoing packets → NFQUEUE sees outgoing ClientHello
#                    containing the SNI → engine can block by domain name.
#
#   iptables chain: OUTPUT (not PREROUTING)

export PATH=$PATH:/usr/local/go/bin

IFACE="wlp8s0"
AXON="/tmp/axon"
AXOND="/tmp/axond"
BPF="/tmp/xdp_firewall.o"
DB="/tmp/axon_l7_test.bolt"
SOCKET="unix:///run/axon/daemon.sock"

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

check_l3_blocked() {
  local ip="$1" label="$2"

  local in_map=0
  sudo "$AXON" --socket "$SOCKET" list 2>/dev/null | grep -qF "$ip" && in_map=1

  local tmppcap
  tmppcap=$(mktemp /tmp/axon_test_XXXXXX.pcap)

  sudo tcpdump -i "$IFACE" -w "$tmppcap" \
    "src host $ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)" \
    -c 1 --immediate-mode 2>/dev/null &
  local TDPID=$!
  sleep 0.3

  sudo hping3 -S -p 80 -c 3 -i u500000 "$ip" >/dev/null 2>&1
  sleep 1.5

  sudo kill "$TDPID" 2>/dev/null
  wait "$TDPID" 2>/dev/null

  local synack=0
  [[ -f "$tmppcap" ]] && synack=$(sudo tcpdump -r "$tmppcap" 2>/dev/null | wc -l)
  rm -f "$tmppcap"

  if [[ $in_map -eq 1 && $synack -eq 0 ]]; then
    pass "$label — in map ✓, no SYN-ACK ✓"
  elif [[ $in_map -eq 0 ]]; then
    fail "$label — IP not in axon rule list"
  else
    fail "$label — SYN-ACK received ($synack pkts) — TC not dropping"
  fi
}

check_l3_blocked_domain() {
  local domain="$1" expected_ip="$2" label="$3"
  local resolved
  resolved=$(dig +short "$domain" A | grep -E '^[0-9]+\.' | head -1)
  if [[ -z "$resolved" ]]; then
    fail "$label — could not resolve $domain"
    return
  fi
  log "  $domain → $resolved (expected ~$expected_ip)"
  [[ "$resolved" != "$expected_ip" ]] && expected_ip="$resolved"
  check_l3_blocked "$expected_ip" "$label"
}

check_l7_sni_blocked() {
  local url="$1" label="$2"
  local out
  out=$(curl -sv --connect-timeout 5 --max-time 6 "$url" 2>&1)
  if echo "$out" | grep -qE "Empty reply|Connection reset|curl: \(35\)|curl: \(56\)|recv failure|curl: \(28\)"; then
    pass "$label — TLS reset/empty ✓"
  else
    local code
    code=$(echo "$out" | grep -oE "HTTP/[0-9.]+ [0-9]+" | tail -1)
    fail "$label — not blocked (${code:-no expected error})"
  fi
}

check_l7_direct_ip_blocked() {
  local ip="$1" label="$2"
  # Plain HTTP to shared IP → TCP connects (TC only marks, doesn't block at L3)
  # then the outgoing GET goes to NFQUEUE → engine sees no SNI/Host for the
  # first packet if it's a raw connect, or Host header for plain HTTP → drop.
  # We expect Empty reply or recv failure.
  local out
  out=$(curl -v --connect-timeout 4 --max-time 5 "http://$ip" 2>&1)
  if echo "$out" | grep -qE "Empty reply|Connection reset|curl: \(52\)|curl: \(56\)|recv failure|curl: \(28\)"; then
    pass "$label — NFQUEUE no-identifier drop ✓"
  else
    local code
    code=$(echo "$out" | grep -oE "HTTP/[0-9.]+ [0-9]+" | tail -1)
    fail "$label — not blocked (${code:-no expected error})"
  fi
}

check_allowed() {
  local url="$1" label="$2"
  local code
  code=$(curl -sko /dev/null -w "%{http_code}" --connect-timeout 6 --max-time 8 "$url")
  if [[ "$code" =~ ^[23] ]]; then
    pass "$label — HTTP $code ✓"
  elif [[ "$code" == "000" ]]; then
    fail "$label — no connection (blocked or unreachable)"
  else
    pass "$label — HTTP $code (connection reached server) ✓"
  fi
}

# ─────────────────────────────────────────────
sep "ENV & PREP"
# ─────────────────────────────────────────────
log "iface: $IFACE"
log "checking tools..."
for t in hping3 tcpdump bpftool dig curl; do
  command -v "$t" &>/dev/null && log "  $t: ok" || log "  WARNING: $t not found"
done

# OUTPUT chain (not PREROUTING) — we inspect outgoing packets (ClientHello)
log "iptables: OUTPUT chain, mark 0xBEEF → NFQUEUE 1"
sudo iptables -t mangle -D OUTPUT -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1 2>/dev/null
sudo iptables -t mangle -D PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1 2>/dev/null
sudo iptables -t mangle -A OUTPUT -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1

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
sep "STEP 14b — Apply Rules"
# ─────────────────────────────────────────────
# addFQDN is now synchronous: DNS resolves before axon add returns.

log "Adding L3 Block: $L3_IP_1 (explicit IP)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L3_IP_1" -i "$IFACE"

log "Adding FQDN Block: $L7_BLOCK_1 (shared IP → L7)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L7_BLOCK_1" -i "$IFACE"

log "Adding FQDN Block: $L7_BLOCK_2 (shared IP → L7)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L7_BLOCK_2" -i "$IFACE"

log "Adding FQDN Block: $L3_DOM_2 (unique IP → L3 tentative)"
cmd sudo "$AXON" --socket "$SOCKET" add "$L3_DOM_2" -i "$IFACE"

# ─────────────────────────────────────────────
sep "STEP 14c — Verify Map Distribution"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" status
cmd sudo "$AXON" --socket "$SOCKET" list

log "Expected:"
log "  157.240.202.35           → blocked_ip_map  (L3 explicit)"
log "  $L7_BLOCK_1 → $L7_SHARED_IP → shared_ip_map   (L7 NFQUEUE)"
log "  $L7_BLOCK_2       → $L7_SHARED_IP → shared_ip_map   (L7 NFQUEUE)"
log "  $L3_DOM_2      → $L3_IP_2  → tentative_map  (L3 FQDN-unique)"

# ─────────────────────────────────────────────
sep "STEP 14d — L3 BLOCKED (4 Tests)"
# Ground truth: axon list + hping3 SYN probe (no SYN-ACK = TC dropped)
# ─────────────────────────────────────────────

log "Test 1: Direct IP $L3_IP_1 (explicit → blocked_ip_map)"
check_l3_blocked "$L3_IP_1" "Test 1 [$L3_IP_1]"

log "Test 2: $L3_DOM_1 (resolves to $L3_IP_1)"
check_l3_blocked_domain "$L3_DOM_1" "$L3_IP_1" "Test 2 [$L3_DOM_1]"

log "Test 3: $L3_DOM_2 (unique IP → tentative_map)"
check_l3_blocked_domain "$L3_DOM_2" "$L3_IP_2" "Test 3 [$L3_DOM_2]"

log "Test 4: Direct IP $L3_IP_2"
check_l3_blocked "$L3_IP_2" "Test 4 [$L3_IP_2]"

# ─────────────────────────────────────────────
sep "STEP 14e — L7 BLOCKED (3 Tests)"
# TC egress marks the outgoing ClientHello → NFQUEUE OUTPUT → engine reads SNI
# ─────────────────────────────────────────────

log "Test 5: $L7_BLOCK_1 (shared IP, SNI blocked)"
check_l7_sni_blocked "https://$L7_BLOCK_1" "Test 5 [$L7_BLOCK_1]"

log "Test 6: $L7_SHARED_IP direct (no SNI → engine drops, shared IP rule)"
check_l7_direct_ip_blocked "$L7_SHARED_IP" "Test 6 [$L7_SHARED_IP no-SNI]"

log "Test 7: $L7_BLOCK_2 (shared IP, SNI blocked)"
check_l7_sni_blocked "https://$L7_BLOCK_2" "Test 7 [$L7_BLOCK_2]"

# ─────────────────────────────────────────────
sep "STEP 14f — ALLOWED (2 Tests)"
# ─────────────────────────────────────────────

log "Test 8: $GLOBAL_ALLOW (no rule → pass-through)"
check_allowed "https://$GLOBAL_ALLOW" "Test 8 [$GLOBAL_ALLOW]"

log "Test 9: $L7_ALLOW (shared IP, SNI not in block list → allowed)"
check_allowed "https://$L7_ALLOW" "Test 9 [$L7_ALLOW]"

# ─────────────────────────────────────────────
sep "CLEANUP"
# ─────────────────────────────────────────────
sudo kill "$DAEMON_PID" 2>/dev/null
sudo iptables -t mangle -D OUTPUT -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/axon/ 2>/dev/null
pass "done"