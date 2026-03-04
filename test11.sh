#!/bin/bash
# axon test — step 11 (updated)
# Usage: sudo bash test11.sh 2>&1 | tee a.log

SOCKET="unix:///run/axon/daemon.sock"
AXON="/tmp/axon"
AXOND="/tmp/axond"
DB="/var/lib/axon/db.bolt"
BPF="/tmp/xdp_firewall.o"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
sep()  { echo ""; echo "────────────────────────────────────────"; echo "  $*"; echo "────────────────────────────────────────"; }
cmd()  {
    echo ""
    echo "  CMD: $*"
    "$@" 2>&1
    echo "  EXIT: $?"
}

# ─────────────────────────────────────────────
sep "ENV"
# ─────────────────────────────────────────────
log "kernel: $(uname -r)"
log "user: $(whoami)"
ls -lh "$AXON"  2>&1
ls -lh "$AXOND" 2>&1

# ─────────────────────────────────────────────
sep "STEP 1 — rebuild both binaries"
# ─────────────────────────────────────────────

echo "  Building axond..."
go build -o /tmp/axond ./cmd/axond/ 2>&1
echo "  axond exit: $?"

echo "  Building axon..."
go build -o /tmp/axon ./cmd/axon/ 2>&1
echo "  axon exit: $?"

ls -lh /tmp/axon /tmp/axond

# ─────────────────────────────────────────────
sep "STEP 2 — kill stale + prep"
# ─────────────────────────────────────────────
sudo pkill -x axond 2>/dev/null; sleep 1
sudo rm -f /run/axon/daemon.sock
sudo mkdir -p /var/lib/axon /run/axon
log "dirs ready"

# ─────────────────────────────────────────────
sep "STEP 3 — start daemon on UNIX socket"
# ─────────────────────────────────────────────
sudo "$AXOND" \
    --grpc "$SOCKET" \
    --log-addr 127.0.0.1:5000 \
    --bpf "$BPF" \
    --db "$DB" \
    --dns-interval 30s &
DAEMON_PID=$!
sleep 2

sudo kill -0 "$DAEMON_PID" 2>/dev/null \
    && echo "  daemon alive PID=$DAEMON_PID" \
    || echo "  daemon DIED"

cmd ls -la /run/axon/

# ─────────────────────────────────────────────
sep "STEP 4 — CLI status via UNIX socket (the fix under test)"
# ─────────────────────────────────────────────
cmd sudo "$AXON" --socket "$SOCKET" status
cmd sudo "$AXON" --socket "$SOCKET" list
cmd sudo "$AXON" --socket "$SOCKET" add 1.2.3.4
cmd sudo "$AXON" --socket "$SOCKET" add google.com
cmd sudo "$AXON" --socket "$SOCKET" list
cmd sudo "$AXON" --socket "$SOCKET" remove 1.2.3.4
cmd sudo "$AXON" --socket "$SOCKET" list
cmd sudo "$AXON" --socket "$SOCKET" mode allow-all
cmd sudo "$AXON" --socket "$SOCKET" sync
cmd sudo "$AXON" --socket "$SOCKET" log-endpoint 127.0.0.1:5000
cmd sudo "$AXON" --socket "$SOCKET" status

# ─────────────────────────────────────────────
sep "STEP 5 — log server"
# ─────────────────────────────────────────────
cmd nc -z 127.0.0.1 5000
echo "  (reading log server for 2s...)"
timeout 2 nc 127.0.0.1 5000 2>&1 || true

# ─────────────────────────────────────────────
sep "CLEANUP"
# ─────────────────────────────────────────────
sudo kill "$DAEMON_PID" 2>/dev/null
sleep 1
echo "done"