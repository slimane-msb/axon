#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# axon build script
# Compiles Go binaries + eBPF C program and produces a .deb package
#
# Usage:
#   ./build.sh              # full build (requires Go 1.21+ and clang)
#   ./build.sh --no-bpf     # skip BPF compilation (Go only)
#   ./build.sh --deb-only   # only package (if binaries already built)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Config ───────────────────────────────────────────────────────────────────
PKG_NAME="axon"
VERSION="1.0.0"
ARCH="amd64"
DEB_NAME="${PKG_NAME}_${VERSION}_${ARCH}.deb"
BUILD_DIR="$SCRIPT_DIR/build"
PKG_DIR="$BUILD_DIR/pkg"
SKIP_BPF=false
DEB_ONLY=false

for arg in "$@"; do
    case $arg in
        --no-bpf)   SKIP_BPF=true ;;
        --deb-only) DEB_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--no-bpf] [--deb-only]"
            echo "  --no-bpf    Skip eBPF C compilation"
            echo "  --deb-only  Only re-package (binaries must exist in build/)"
            exit 0
            ;;
    esac
done

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
fail() { echo -e "${RED}❌ $*${NC}"; exit 1; }
step() { echo -e "\n${YELLOW}── $* ──${NC}"; }

echo "════════════════════════════════════════════════════════════"
echo "  axon v${VERSION} build"
echo "════════════════════════════════════════════════════════════"

# ── Check prerequisites ───────────────────────────────────────────────────────
step "Checking prerequisites"

if ! $DEB_ONLY; then
    if ! command -v go &>/dev/null; then
        fail "Go not found. Install from https://go.dev/dl/\n  wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz\n  sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz\n  export PATH=\$PATH:/usr/local/go/bin"
    fi
    GO_VERSION=$(go version | awk '{print $3}' | tr -d 'go')
    ok "Go ${GO_VERSION}"
fi

if ! command -v dpkg-deb &>/dev/null; then
    fail "dpkg-deb not found. Install: sudo apt install dpkg"
fi
ok "dpkg-deb found"

if ! $SKIP_BPF && ! $DEB_ONLY; then
    if command -v clang &>/dev/null; then
        ok "clang $(clang --version | head -1 | awk '{print $3}')"
    else
        warn "clang not found — BPF compilation will be skipped"
        warn "Install: sudo apt install clang llvm linux-headers-\$(uname -r)"
        SKIP_BPF=true
    fi
fi

# ── Prepare directories ───────────────────────────────────────────────────────
step "Preparing build directories"
mkdir -p "$BUILD_DIR"
rm -rf "$PKG_DIR"

# Mirror the Debian package structure
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/axon"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/etc/axon"
mkdir -p "$PKG_DIR/var/lib/axon"
mkdir -p "$PKG_DIR/usr/share/doc/axon"

# ── Download Go dependencies ─────────────────────────────────────────────────
if ! $DEB_ONLY; then
    step "Downloading Go dependencies"
    cd "$SCRIPT_DIR"

    # Create go.sum if it doesn't exist
    if [ ! -f go.sum ]; then
        go mod tidy || warn "go mod tidy failed — some dependencies may be missing"
    fi

    go mod download || fail "go mod download failed"
    ok "Dependencies downloaded"
fi

# ── Build Go binaries ────────────────────────────────────────────────────────
if ! $DEB_ONLY; then
    step "Building axond (daemon)"
    cd "$SCRIPT_DIR"
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
        -ldflags="-s -w -X github.com/axon/internal/daemon.Version=${VERSION}" \
        -trimpath \
        -o "$BUILD_DIR/axond" \
        ./cmd/axond/
    ok "axond built ($(du -sh "$BUILD_DIR/axond" | cut -f1))"

    step "Building axon (CLI)"
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
        -ldflags="-s -w" \
        -trimpath \
        -o "$BUILD_DIR/axon" \
        ./cmd/axon/
    ok "axon CLI built ($(du -sh "$BUILD_DIR/axon" | cut -f1))"
fi

# ── Compile eBPF/XDP program ─────────────────────────────────────────────────
if ! $SKIP_BPF && ! $DEB_ONLY; then
    step "Compiling eBPF/XDP program"

    KERNEL_VER=$(uname -r)
    HEADERS_PATH="/usr/src/linux-headers-${KERNEL_VER}/include"
    if [ ! -d "$HEADERS_PATH" ]; then
        HEADERS_PATH="/usr/include"
    fi

    clang -O2 -g -target bpf \
        -I"$HEADERS_PATH" \
        -I/usr/include \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c "$SCRIPT_DIR/internal/ebpf/xdp_firewall.c" \
        -o "$BUILD_DIR/xdp_firewall.o" 2>&1 || {
            warn "eBPF compilation failed — package will include C source only"
            warn "It will be compiled on the target machine during installation"
            SKIP_BPF=true
        }

    if ! $SKIP_BPF; then
        ok "eBPF compiled: xdp_firewall.o ($(du -sh "$BUILD_DIR/xdp_firewall.o" | cut -f1))"
    fi
fi

# ── Assemble package ─────────────────────────────────────────────────────────
step "Assembling Debian package"

# Copy DEBIAN control files
cp -r "$SCRIPT_DIR/packaging/DEBIAN/"* "$PKG_DIR/DEBIAN/"
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Copy binaries
cp "$BUILD_DIR/axond" "$PKG_DIR/usr/bin/axond"
cp "$BUILD_DIR/axon"  "$PKG_DIR/usr/bin/axon"
chmod 755 "$PKG_DIR/usr/bin/axond"
chmod 755 "$PKG_DIR/usr/bin/axon"

# Copy BPF C source (always included for on-target compilation)
cp "$SCRIPT_DIR/internal/ebpf/xdp_firewall.c" "$PKG_DIR/usr/lib/axon/"

# Copy pre-compiled BPF object if available
if [ -f "$BUILD_DIR/xdp_firewall.o" ]; then
    cp "$BUILD_DIR/xdp_firewall.o" "$PKG_DIR/usr/lib/axon/"
    ok "Pre-compiled xdp_firewall.o included"
fi

# Copy systemd service
cp "$SCRIPT_DIR/packaging/lib/systemd/system/axon.service" \
   "$PKG_DIR/lib/systemd/system/"

# Copy config
cp "$SCRIPT_DIR/packaging/etc/axon/axon.conf" \
   "$PKG_DIR/etc/axon/"

# Create doc files
cat > "$PKG_DIR/usr/share/doc/axon/changelog" << 'EOF'
axon (1.0.0) unstable; urgency=medium

  * Initial release
  * Per-interface XDP L3 firewall
  * FQDN-centric rules with DNS grace periods
  * L7 inspection via NFQUEUE (TLS SNI + HTTP Host)
  * gRPC control plane
  * bbolt persistent storage with cold start recovery
  * Fan-out JSON log server (default: localhost:5000)

 -- axon <axon@localhost>  Wed, 04 Mar 2026 00:00:00 +0000
EOF

cat > "$PKG_DIR/usr/share/doc/axon/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: axon
License: MIT
EOF

# ── Update installed size in control ─────────────────────────────────────────
INSTALLED_SIZE=$(du -sk "$PKG_DIR" | cut -f1)
sed -i "s/^Installed-Size:.*/Installed-Size: ${INSTALLED_SIZE}/" "$PKG_DIR/DEBIAN/control"

# ── Build .deb ───────────────────────────────────────────────────────────────
step "Building .deb package"

DEB_OUT="$BUILD_DIR/$DEB_NAME"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_OUT"

DEB_SIZE=$(du -sh "$DEB_OUT" | cut -f1)
ok "Package built: $DEB_OUT ($DEB_SIZE)"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Package:  $DEB_OUT"
echo "  Size:     $DEB_SIZE"
echo ""
echo "  INSTALL:"
echo "    sudo dpkg -i $DEB_OUT"
echo "    sudo apt-get install -f   # fix any dependency issues"
echo ""
echo "  QUICK START:"
echo "    systemctl status axon"
echo "    axon status"
echo "    axon add 1.2.3.4 -i eth0"
echo "    axon add evil.example.com -i eth0"
echo "    axon list"
echo "    axon logs -f --addr 127.0.0.1:5000"
echo "    axon log-endpoint 0.0.0.0:9000"
echo "    axon mode block-all -i eth0"
echo "    axon sync"
echo ""
echo "  LOG CONSUMER (another terminal):"
echo "    nc 127.0.0.1 5000   # JSON log stream"
echo ""
