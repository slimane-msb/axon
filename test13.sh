#!/bin/bash
# axon test — step 13: TC BPF firewall attach
# Hook: TC ingress (clsact qdisc) — works on lo, wlp8s0, eth0, veth
# Usage: sudo bash test13.sh 2>&1 | tee 13.log

export PATH=$PATH:/usr/local/go/bin

IFACE="wlp8s0"
AXON="/tmp/axon"
AXOND="/tmp/axond"
BPF="/tmp/xdp_firewall.o"
DB="/tmp/axon_test13.bolt"
SOCKET="unix:///run/axon/daemon.sock"

sep()  { echo ""; echo "────────────────────────────────────────"; echo "  $*"; echo "────────────────────────────────────────"; }
cmd()  { echo ""; echo "  CMD: $*"; "$@" 2>&1; echo "  EXIT: $?"; }
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { echo "  ✅ $*"; }
fail() { echo "  ❌ $*"; }

check_tc() {
    local iface="$1"
    tc filter show dev "$iface" ingress 2>/dev/null | grep -q "axon_tc_firewall"
}

# ─────────────────────────────────────────────
sep "ENV"
# ─────────────────────────────────────────────
log "kernel: $(uname -r)"
log "user: $(whoami)"
log "iface: $IFACE"
log "hook: TC ingress (clsact qdisc) — replaces XDP for lo/wifi compatibility"
cmd ls -lh "$BPF"
cmd ls -lh "$AXON"
cmd ls -lh "$AXOND"

# ─────────────────────────────────────────────
sep "STEP 13a — rebuild binaries"
# ─────────────────────────────────────────────
go build -o /tmp/axond ./cmd/axond/ && pass "axond built" || { fail "axond FAILED"; exit 1; }
go build -o /tmp/axon  ./cmd/axon/  && pass "axon built"  || { fail "axon FAILED"; exit 1; }

# ─────────────────────────────────────────────
sep "STEP 13b — interface exists + TC state (pre-attach)"
# ─────────────────────────────────────────────
cmd ip link show "$IFACE"
cmd ip link show lo
echo ""
echo "  TC filters on $IFACE before attach:"
tc filter show dev "$IFACE" ingress 2>&1 || echo "  (no ingress filters)"
echo ""
echo "  TC filters on lo before attach:"
tc filter show dev lo ingress 2>&1 || echo "  (no ingress filters)"

# ─────────────────────────────────────────────
sep "STEP 13c — bpf filesystem"
# ─────────────────────────────────────────────
cmd ls /sys/fs/bpf/
mountpoint -q /sys/fs/bpf 2>/dev/null \
    && pass "bpffs already mounted" \
    || (sudo mount -t bpf bpf /sys/fs/bpf 2>&1 && pass "bpffs mounted")

# ─────────────────────────────────────────────
sep "STEP 13d — kill stale + prep"
# ─────────────────────────────────────────────
sudo pkill -x axond 2>/dev/null; sleep 1
# Clean up any leftover TC state from previous runs
sudo tc qdisc del dev lo    clsact 2>/dev/null || true
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
sudo rm -f /run/axon/daemon.sock
sudo rm -f "$DB"
sudo rm -rf /sys/fs/bpf/axon/
sudo mkdir -p /run/axon
pass "stale state cleared"

# ─────────────────────────────────────────────
sep "STEP 13e — start daemon (TC BPF will attach on first rule)"
# ─────────────────────────────────────────────
sudo "$AXOND" \
    --grpc "$SOCKET" \
    --log-addr 127.0.0.1:5000 \
    --bpf "$BPF" \
    --db "$DB" \
    --dns-interval 30s &
DAEMON_PID=$!
sleep 3

sudo kill -0 "$DAEMON_PID" 2>/dev/null \
    && pass "daemon alive PID=$DAEMON_PID" \
    || { fail "daemon DIED"; exit 1; }

# ─────────────────────────────────────────────
sep "STEP 13f — status (no interfaces yet, cold start)"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" status

# ─────────────────────────────────────────────
sep "STEP 13g — add rule on loopback, verify TC attach"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" add 127.0.0.1 -i lo

echo ""
echo "  TC qdisc on lo:"
cmd tc qdisc show dev lo

echo ""
echo "  TC filters on lo (expect axon_tc_firewall):"
cmd tc filter show dev lo ingress

if check_tc lo; then
    pass "TC BPF filter attached on lo"
else
    fail "TC BPF filter NOT found on lo — check daemon logs"
fi

# ─────────────────────────────────────────────
sep "STEP 13h — verify BPF pins"
# ─────────────────────────────────────────────
cmd ls -la /sys/fs/bpf/axon/ 2>&1 || echo "  /sys/fs/bpf/axon/ not found"
echo ""
echo "  Expected pins: blocked_ip_map, tentative_map, shared_ip_map, mode_map, events, tc_lo"

# ─────────────────────────────────────────────
sep "STEP 13i — ping test on loopback (block-all mode)"
# ─────────────────────────────────────────────
echo "  Ping before block-all (expect success — allow-all is default):"
cmd ping -c 2 -W 1 127.0.0.1

echo ""
echo "  Switching to block-all mode..."
cmd sudo "$AXON" --socket "$SOCKET" mode block-all
sleep 1

echo ""
echo "  Ping in block-all mode (expect FAIL — TC filter should drop):"
ping -c 2 -W 1 127.0.0.1 2>&1
PING_EXIT=$?
if [ $PING_EXIT -ne 0 ]; then
    pass "Ping correctly blocked (exit $PING_EXIT) — TC BPF is working"
else
    fail "Ping succeeded — TC filter is NOT dropping packets (exit $PING_EXIT)"
fi

# ─────────────────────────────────────────────
sep "STEP 13j — restore allow-all, verify ping recovers"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" mode allow-all
sleep 1

echo "  Ping after restore (expect success):"
cmd ping -c 2 -W 1 127.0.0.1

cmd sudo "$AXON" --socket "$SOCKET" remove 127.0.0.1 -i lo
sleep 1

echo ""
echo "  TC filters on lo after remove:"
tc filter show dev lo ingress 2>&1

# ─────────────────────────────────────────────
sep "STEP 13k — attach on real interface $IFACE"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" add 1.2.3.4 -i "$IFACE"
sleep 1

echo ""
echo "  TC qdisc on $IFACE:"
cmd tc qdisc show dev "$IFACE"

echo ""
echo "  TC filters on $IFACE (expect axon_tc_firewall):"
cmd tc filter show dev "$IFACE" ingress

if check_tc "$IFACE"; then
    pass "TC BPF filter attached on $IFACE (wifi — SKB mode, works correctly)"
else
    fail "TC BPF filter NOT found on $IFACE"
fi

cmd sudo "$AXON" --socket "$SOCKET" list
cmd sudo "$AXON" --socket "$SOCKET" status

# ─────────────────────────────────────────────
sep "STEP 13l — note on ip link vs tc"
# ─────────────────────────────────────────────
echo ""
echo "  NOTE: 'ip link show' no longer shows hook state (that was XDP-specific)."
echo "  Use 'tc filter show dev <iface> ingress' to verify attachment."
echo ""
cmd ip link show "$IFACE"
echo ""
echo "  TC filter check (canonical verification):"
cmd tc filter show dev "$IFACE" ingress

# ─────────────────────────────────────────────
sep "CLEANUP"
# ─────────────────────────────────────────────
sudo kill "$DAEMON_PID" 2>/dev/null
sleep 1

echo "  TC state after daemon stop:"
tc filter show dev lo      ingress 2>&1 | grep axon && fail "TC filter still on lo"      || pass "TC filter detached from lo"
tc filter show dev "$IFACE" ingress 2>&1 | grep axon && fail "TC filter still on $IFACE" || pass "TC filter detached from $IFACE"

sudo rm -rf /sys/fs/bpf/axon/ 2>/dev/null
sudo rm -f "$DB"
echo ""
pass "done"