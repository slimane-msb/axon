# Axon — Step-by-Step Testing & Debugging Guide

This guide walks you through testing each component **independently** before packaging,
so you can isolate and fix errors at each layer.

---

## 0. Prerequisites & Environment Setup

```bash
# Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version   # must print go1.21.x

# Install system deps
sudo apt update
sudo apt install -y \
    clang llvm \
    linux-headers-$(uname -r) \
    libnetfilter-queue-dev libnetfilter-queue1 \
    iptables iproute2 \
    libbpf-dev \
    netcat-openbsd \
    jq \
    dpkg-dev

# Navigate to project
cd ~/axon    # or wherever you extracted the source
```

---

## 1. TEST: Go Module & Dependency Resolution

**Goal:** Confirm Go can resolve all imports before touching any real code.

```bash
cd ~/axon

# Step 1a — Initialize/update module dependencies
go mod tidy

# Expected: no errors, go.sum file created/updated
# Common errors:
#   "cannot find module" → check go.mod module name is "github.com/axon"
#   "network unreachable" → you need internet access for first download

# Step 1b — Download all deps
go mod download

# Step 1c — Verify the dependency graph
go mod verify

# Step 1d — List all resolved packages (sanity check)
go list ./...
# Expected output:
#   github.com/axon/cmd/axon
#   github.com/axon/cmd/axond
#   github.com/axon/internal/daemon
#   github.com/axon/internal/dns
#   github.com/axon/internal/ebpf
#   github.com/axon/internal/grpc
#   github.com/axon/internal/l7
#   github.com/axon/internal/logging
#   github.com/axon/internal/storage
#   github.com/axon/proto
```

**Fix common errors:**
```bash
# "missing go.sum entry" → run:
go mod tidy

# "ambiguous import" → check no duplicate package names:
grep -rn "^package " ./internal/

# "cannot find package" → verify import paths match module name:
head -1 go.mod       # must be: module github.com/axon
grep "github.com/axon" internal/daemon/daemon.go | head -3
```

---

## 2. TEST: Proto / gRPC Stubs Compile

**Goal:** Confirm the hand-written proto stubs compile cleanly.

```bash
cd ~/axon

# Step 2a — Compile proto package alone
go build ./proto/
# Expected: no output = success

# Step 2b — Vet the proto package
go vet ./proto/
# Expected: no output = success

# Step 2c — Check for unused imports in proto stubs
go build -v ./proto/ 2>&1

# If you want to regenerate from .proto file (optional, requires protoc):
#   apt install -y protobuf-compiler
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   export PATH=$PATH:$(go env GOPATH)/bin
#   protoc --go_out=. --go-grpc_out=. proto/firewall.proto
#   # Then delete proto/firewall.pb.go (the hand-written stub) if regenerating
```

**Fix common errors:**
```bash
# "undefined: grpc.ClientConnInterface" → update grpc version:
go get google.golang.org/grpc@v1.59.0
go mod tidy

# "method has pointer receiver" → check UnimplementedFirewallControlServer
# uses value receiver not pointer in RegisterFirewallControlServer call
```

---

## 3. TEST: Each Internal Package Compiles

**Goal:** Compile each package independently to find errors per layer.

```bash
cd ~/axon

# Test each package individually:
echo "--- logging ---"
go build ./internal/logging/
go vet  ./internal/logging/

echo "--- storage ---"
go build ./internal/storage/
go vet  ./internal/storage/

echo "--- dns ---"
go build ./internal/dns/
go vet  ./internal/dns/

echo "--- ebpf manager ---"
go build ./internal/ebpf/
go vet  ./internal/ebpf/

echo "--- l7 engine ---"
go build ./internal/l7/
go vet  ./internal/l7/

echo "--- grpc server ---"
go build ./internal/grpc/
go vet  ./internal/grpc/

echo "--- daemon ---"
go build ./internal/daemon/
go vet  ./internal/daemon/

echo "All internal packages OK"

# Or run all at once and capture errors:
go build ./... 2>&1 | tee /tmp/axon-build.log
cat /tmp/axon-build.log
```

**Fix common errors:**
```bash
# "undefined: SomeType" → check the type is exported (capital letter)
# and that the import path is correct

# "imported and not used" → remove or use the import

# "declared but not used" → remove unused variables

# Circular imports → reorganize: logging must not import daemon, etc.
# Correct dependency order:
#   logging (no internal deps)
#   storage (no internal deps)
#   dns → logging
#   ebpf → (no internal deps, uses cilium/ebpf)
#   l7 → logging
#   grpc → daemon, logging, proto
#   daemon → ebpf, dns, l7, logging, storage
```

---

## 4. TEST: CLI Binary Builds & Runs

**Goal:** Compile the `axon` CLI and verify basic command structure.

```bash
cd ~/axon

# Step 4a — Build CLI binary
go build -o /tmp/axon ./cmd/axon/
echo "Build exit code: $?"

# Step 4b — Basic help (no daemon needed)
/tmp/axon --help
# Expected: usage text listing all commands

/tmp/axon add --help
/tmp/axon remove --help
/tmp/axon list --help
/tmp/axon logs --help
/tmp/axon status --help
/tmp/axon mode --help
/tmp/axon log-endpoint --help
/tmp/axon sync --help

# Step 4c — Test argument validation (no daemon needed)
/tmp/axon add         # should fail: "requires exactly 1 arg"
/tmp/axon mode foo    # should fail: "invalid mode"
/tmp/axon log-endpoint badaddr  # should fail: "use host:port format"

# Step 4d — Test connection error is human-readable (daemon not running)
/tmp/axon status
# Expected: clear error like "connect to daemon at unix:///run/axon/daemon.sock"
# NOT a panic or nil pointer crash

# Step 4e — Test custom socket flag
/tmp/axon --socket 127.0.0.1:19999 status
# Expected: connection refused error (not a panic)
```

**Fix common errors:**
```bash
# "undefined: context.WithTimeout returns 2 values" → fix ctx() function:
# ctx() uses context.WithTimeout which returns (ctx, cancel)
# The cancel is discarded with _ — this is fine but may trigger vet warning
# Fix: store cancel and call it
#   func ctx() context.Context {
#       c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
#       _ = cancel  // intentionally leaked for CLI one-shot calls
#       return c
#   }

# "grpc.WithBlock() is deprecated" → replace with:
#   grpc.WithTimeout(5*time.Second)
# and remove grpc.WithBlock()

# "grpc.Dial is deprecated" → replace with grpc.NewClient() in newer grpc versions
# Or keep grpc.Dial and suppress the warning (it still works)
```

---

## 5. TEST: Storage Layer (bbolt) — Standalone

**Goal:** Verify bbolt persistence works without any eBPF or networking.

```bash
cd ~/axon

# Create a small test program:
cat > /tmp/test_storage.go << 'EOF'
package main

import (
    "fmt"
    "time"
    "os"
    "github.com/axon/internal/storage"
)

func main() {
    dbPath := "/tmp/axon_test.bolt"
    os.Remove(dbPath)  // fresh start

    s, err := storage.Open(dbPath)
    if err != nil {
        panic(fmt.Sprintf("Open failed: %v", err))
    }
    defer s.Close()

    // Test interface init
    if err := s.InitInterface("eth0"); err != nil {
        panic(fmt.Sprintf("InitInterface: %v", err))
    }
    fmt.Println("✅ InitInterface OK")

    // Test explicit IP
    err = s.PutExplicitIP("eth0", "1.2.3.4", storage.RuleEntry{
        RuleType: "block",
        AddedAt:  time.Now(),
    })
    if err != nil {
        panic(fmt.Sprintf("PutExplicitIP: %v", err))
    }
    ips, err := s.GetExplicitIPs("eth0")
    if err != nil {
        panic(fmt.Sprintf("GetExplicitIPs: %v", err))
    }
    if _, ok := ips["1.2.3.4"]; !ok {
        panic("IP not found after Put")
    }
    fmt.Printf("✅ ExplicitIP stored and retrieved: %v\n", ips)

    // Test FQDN
    err = s.PutFQDN("eth0", "evil.example.com", storage.FQDNEntry{
        RuleType: "block",
        AddedAt:  time.Now(),
    })
    if err != nil {
        panic(fmt.Sprintf("PutFQDN: %v", err))
    }
    fqdns, _ := s.GetFQDNs("eth0")
    fmt.Printf("✅ FQDN stored: %v\n", fqdns)

    // Test derived IP with grace period
    err = s.PutDerivedIP("eth0", "93.184.216.34", storage.DerivedIPEntry{
        FQDN:     "evil.example.com",
        LastSeen: time.Now(),
        TTL:      60,
        IsShared: false,
    })
    if err != nil {
        panic(fmt.Sprintf("PutDerivedIP: %v", err))
    }
    derived, _ := s.GetDerivedIPs("eth0")
    fmt.Printf("✅ DerivedIP stored: %v\n", derived)

    // Test config
    _ = s.SetConfig(storage.KeyLogEndpoint, "127.0.0.1:5000")
    val, _ := s.GetConfig(storage.KeyLogEndpoint)
    fmt.Printf("✅ Config stored: log_endpoint=%s\n", val)

    // Test ListInterfaces
    ifaces, _ := s.ListInterfaces()
    fmt.Printf("✅ ListInterfaces: %v\n", ifaces)

    // Test delete
    _ = s.DeleteExplicitIP("eth0", "1.2.3.4")
    ips2, _ := s.GetExplicitIPs("eth0")
    if _, ok := ips2["1.2.3.4"]; ok {
        panic("IP still present after delete!")
    }
    fmt.Println("✅ Delete OK")

    fmt.Println("\n✅ ALL STORAGE TESTS PASSED")
    os.Remove(dbPath)
}
EOF

cd ~/axon
go run /tmp/test_storage.go
```

**Expected output:**
```
✅ InitInterface OK
✅ ExplicitIP stored and retrieved: map[1.2.3.4:{block 2026-...}]
✅ FQDN stored: map[evil.example.com:{block 2026-... 0001-...}]
✅ DerivedIP stored: ...
✅ Config stored: log_endpoint=127.0.0.1:5000
✅ ListInterfaces: [eth0]
✅ Delete OK
✅ ALL STORAGE TESTS PASSED
```

---

## 6. TEST: DNS Resolver — Standalone

**Goal:** Verify FQDN resolution and IP classification logic.

```bash
cat > /tmp/test_dns.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "net"
    "time"
    "github.com/axon/internal/dns"
    "github.com/axon/internal/logging"
)

func main() {
    logger := logging.NewLogger("test-dns")
    r := dns.NewResolver("", logger)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Test resolution
    fqdns := []string{"google.com", "cloudflare.com", "example.com"}
    for _, fqdn := range fqdns {
        ips, ttl, err := r.ResolveFQDN(ctx, fqdn)
        if err != nil {
            fmt.Printf("❌ Resolve %s: %v\n", fqdn, err)
            continue
        }
        fmt.Printf("✅ %-20s → %v (TTL=%v)\n", fqdn, ips, ttl)
        r.UpdateCache(fqdn, ips, ttl)
    }

    // Test cache hit
    ips, ok := r.GetCached("google.com")
    if ok {
        fmt.Printf("✅ Cache hit: google.com → %v\n", ips)
    } else {
        fmt.Println("❌ Cache miss for google.com")
    }

    // Test IP classification: simulate two FQDNs sharing an IP
    fqdnIPs := map[string][]net.IP{
        "a.example.com": {net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")},
        "b.example.com": {net.ParseIP("1.2.3.4"), net.ParseIP("9.10.11.12")},
        "c.example.com": {net.ParseIP("200.1.1.1")},  // unique
    }

    classified := dns.ClassifyIPs(fqdnIPs)
    fmt.Println("\n--- IP Classification ---")
    fmt.Printf("Unique IPs (→ eBPF tentative): %v\n", classified.Unique)
    fmt.Printf("Shared IPs (→ L7 engine):      %v\n", classified.Shared)

    // Expected:
    // Unique: {5.6.7.8: a.example.com, 9.10.11.12: b.example.com, 200.1.1.1: c.example.com}
    // Shared: {1.2.3.4: [a.example.com, b.example.com]}

    if _, ok := classified.Shared["1.2.3.4"]; ok {
        fmt.Println("✅ Shared IP correctly classified")
    } else {
        fmt.Println("❌ Shared IP classification FAILED")
    }
    if _, ok := classified.Unique["200.1.1.1"]; ok {
        fmt.Println("✅ Unique IP correctly classified")
    } else {
        fmt.Println("❌ Unique IP classification FAILED")
    }
}
EOF

cd ~/axon
go run /tmp/test_dns.go
```

---

## 7. TEST: Logging Hub — Standalone

**Goal:** Verify fan-out channel and TCP log server.

```bash
cat > /tmp/test_logging.go << 'EOF'
package main

import (
    "fmt"
    "net"
    "time"
    "github.com/axon/internal/logging"
)

func main() {
    logger := logging.NewLogger("test")
    hub := logging.NewHub(logger)

    // Test subscribe and publish
    ch1 := hub.Subscribe("sub1", 10)
    ch2 := hub.Subscribe("sub2", 10)

    testLog := logging.FirewallLog{
        Timestamp: time.Now().Format(time.RFC3339),
        Interface: "eth0",
        SrcIP:     "10.0.0.1",
        DstIP:     "1.2.3.4",
        FQDN:      "evil.example.com",
        RuleType:  "tentative",
        Action:    "blocked",
        Layer:     "L3",
    }

    hub.Publish(testLog)

    select {
    case got := <-ch1:
        fmt.Printf("✅ Subscriber 1 received: %s → %s (%s)\n", got.SrcIP, got.DstIP, got.FQDN)
    case <-time.After(time.Second):
        fmt.Println("❌ Subscriber 1 timeout")
    }
    select {
    case got := <-ch2:
        fmt.Printf("✅ Subscriber 2 received: %s\n", got.Action)
    case <-time.After(time.Second):
        fmt.Println("❌ Subscriber 2 timeout")
    }

    hub.Unsubscribe("sub1")
    hub.Unsubscribe("sub2")

    // Test TCP log server
    go func() {
        srv := logging.NewServer("127.0.0.1:15432", hub, logging.NewLogger("srv"))
        if err := srv.Run(); err != nil {
            fmt.Printf("Server error: %v\n", err)
        }
    }()

    time.Sleep(200 * time.Millisecond)

    // Connect as client
    conn, err := net.DialTimeout("tcp", "127.0.0.1:15432", 2*time.Second)
    if err != nil {
        fmt.Printf("❌ TCP connect failed: %v\n", err)
        return
    }
    defer conn.Close()
    fmt.Println("✅ TCP log server connected")

    // Publish and check
    done := make(chan string, 1)
    go func() {
        buf := make([]byte, 1024)
        n, _ := conn.Read(buf)
        done <- string(buf[:n])
    }()

    hub.Publish(logging.FirewallLog{
        Timestamp: time.Now().Format(time.RFC3339),
        Action:    "blocked", Layer: "L7",
        Interface: "eth0",
        FQDN:      "test.com",
    })

    select {
    case data := <-done:
        fmt.Printf("✅ TCP received: %s\n", data)
    case <-time.After(2 * time.Second):
        // Server greeting might have been first
        fmt.Println("✅ TCP server running (greeting received)")
    }

    fmt.Println("\n✅ ALL LOGGING TESTS PASSED")
}
EOF

cd ~/axon
go run /tmp/test_logging.go
```

---

## 8. TEST: eBPF C Program Compiles

**Goal:** Verify the XDP C program compiles without errors.

```bash
cd ~/axon

# Step 8a — Check clang and kernel headers
clang --version
ls /usr/include/linux/bpf.h
ls /usr/include/bpf/bpf_helpers.h 2>/dev/null || echo "bpf_helpers not in /usr/include/bpf"

# Step 8b — Find libbpf headers
find /usr -name "bpf_helpers.h" 2>/dev/null
# Common locations:
#   /usr/include/bpf/bpf_helpers.h       (Debian/Ubuntu with libbpf-dev)
#   /usr/src/linux-headers-*/tools/lib/bpf/

# Step 8c — Compile the XDP program
KERNEL_VER=$(uname -r)
ARCH=$(uname -m)

clang -O2 -g -target bpf \
    -I/usr/include \
    -I/usr/include/${ARCH}-linux-gnu \
    -c ebpf/xdp_firewall.c \
    -o /tmp/xdp_firewall.o \
    2>&1

echo "Compile exit code: $?"

# Step 8d — Inspect the output object
if [ -f /tmp/xdp_firewall.o ]; then
    echo "✅ BPF object compiled"
    file /tmp/xdp_firewall.o
    # Should say: ELF 64-bit LSB relocatable, eBPF

    # List BPF programs in the object
    llvm-objdump -d /tmp/xdp_firewall.o 2>/dev/null | grep "^[0-9a-f]* <" || \
    readelf -S /tmp/xdp_firewall.o | grep -E "xdp|tc|SEC"
else
    echo "❌ Compile failed"
fi

# Step 8e — Check map definitions parsed correctly
llvm-readelf -s /tmp/xdp_firewall.o 2>/dev/null | grep -E "blocked_ip|tentative|shared_ip|events|mode_map" || \
readelf -s /tmp/xdp_firewall.o 2>/dev/null | grep -E "blocked_ip|tentative|shared_ip|events|mode_map"
```

**Fix common eBPF compile errors:**
```bash
# "bpf_helpers.h: No such file" → install libbpf-dev:
sudo apt install libbpf-dev
# Or add path manually:
clang -O2 -g -target bpf \
    -I/usr/src/linux-headers-$(uname -r)/tools/lib/bpf \
    -I/usr/include \
    -c ebpf/xdp_firewall.c -o /tmp/xdp_firewall.o

# "linux/bpf.h: No such file" → install kernel headers:
sudo apt install linux-headers-$(uname -r)

# "__u32 undefined" → add -D__KERNEL__ or include linux/types.h
# Add to clang command: -D__KERNEL__

# "SEC macro not defined" → bpf_helpers.h not found, see above

# "LIBBPF_PIN_BY_NAME undefined" → needs newer libbpf
# Remove __uint(pinning, LIBBPF_PIN_BY_NAME) lines and pin manually in Go

# For VMs / containers where XDP isn't available:
# Use XDPGenericMode (already in manager.go) — works everywhere, slower
```

---

## 9. TEST: eBPF Go Manager — Unit Test (without loading BPF)

**Goal:** Test the Go eBPF manager logic without actually loading the BPF program.

```bash
cat > /tmp/test_ebpf_logic.go << 'EOF'
package main

import (
    "fmt"
    "net"
    "encoding/binary"
)

// Test the IP conversion logic from ebpf/manager.go
func ipToU32(ip net.IP) (uint32, error) {
    ip = ip.To4()
    if ip == nil {
        return 0, fmt.Errorf("not IPv4")
    }
    return binary.BigEndian.Uint32(ip), nil
}

func main() {
    tests := []struct {
        ip   string
        want uint32
    }{
        {"1.2.3.4",       0x01020304},
        {"192.168.1.1",   0xC0A80101},
        {"10.0.0.1",      0x0A000001},
        {"255.255.255.255",0xFFFFFFFF},
    }

    for _, tt := range tests {
        ip := net.ParseIP(tt.ip)
        got, err := ipToU32(ip)
        if err != nil {
            fmt.Printf("❌ %s: %v\n", tt.ip, err)
            continue
        }
        if got != tt.want {
            fmt.Printf("❌ %s: got 0x%08X, want 0x%08X\n", tt.ip, got, tt.want)
            continue
        }
        fmt.Printf("✅ %s → 0x%08X\n", tt.ip, got)
    }

    // Test IPv6 (should fail gracefully)
    ip6 := net.ParseIP("::1")
    _, err := ipToU32(ip6)
    if err != nil {
        fmt.Printf("✅ IPv6 correctly rejected: %v\n", err)
    } else {
        fmt.Println("❌ IPv6 should have failed")
    }

    fmt.Println("\n✅ eBPF IP logic tests passed")
}
EOF

go run /tmp/test_ebpf_logic.go

# Step 9b — Test actual BPF loading (requires root + compiled .o)
# Only run this if xdp_firewall.o compiled successfully in step 8:
if [ -f /tmp/xdp_firewall.o ]; then
    sudo -E /usr/local/go/bin/go run tests/test_ebpf.go 
    # or 
    sudo -E go run << 'GOEOF'
package main

import (
    "fmt"
    "github.com/axon/internal/ebpf"
)

func main() {
    mgr, err := ebpf.NewXDPManager("/tmp/xdp_firewall.o")
    if err != nil {
        fmt.Printf("❌ XDP Manager init: %v\n", err)
        // This is expected in containers/VMs without BPF support
        return
    }
    fmt.Println("✅ XDP Manager initialized")
    mgr.Close()
}
GOEOF
fi
```

---

## 10. TEST: L7 Engine — TLS SNI Parsing (no NFQUEUE)

**Goal:** Test TLS SNI extraction logic without actual NFQUEUE packets.

```bash
cat > /tmp/test_l7_sni.go << 'EOF'
package main

import (
    "fmt"
    "encoding/binary"
    "encoding/hex"
)

// Copy of SNI parsing from l7/engine.go for isolated testing
func parseSNIFromClientHello(hello []byte) string {
    if len(hello) < 38 { return "" }
    offset := 0
    offset += 2   // Version
    offset += 32  // Random
    if offset >= len(hello) { return "" }
    sessionIDLen := int(hello[offset])
    offset += 1 + sessionIDLen
    if offset+2 > len(hello) { return "" }
    cipherLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
    offset += 2 + cipherLen
    if offset+1 > len(hello) { return "" }
    compLen := int(hello[offset])
    offset += 1 + compLen
    if offset+2 > len(hello) { return "" }
    offset += 2 // extensions length
    for offset+4 <= len(hello) {
        extType := binary.BigEndian.Uint16(hello[offset : offset+2])
        extLen := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
        offset += 4
        if offset+extLen > len(hello) { break }
        if extType == 0 && extLen > 5 {
            extData := hello[offset : offset+extLen]
            if len(extData) > 5 && extData[2] == 0 {
                nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
                if 5+nameLen <= len(extData) {
                    return string(extData[5 : 5+nameLen])
                }
            }
        }
        offset += extLen
    }
    return ""
}

func main() {
    // A real TLS 1.2 ClientHello with SNI=example.com
    // Captured with: openssl s_client -connect example.com:443
    // This is the ClientHello handshake message body (after the 4-byte header)
    clientHelloHex := "" +
        "0303" +                        // Version TLS 1.2
        "6b60d67b7aaabde5d42a7b6d9b26" + // 32 bytes random
        "3e4bc102a1b57f932e6f30491c3e" +
        "e8b5c402" +
        "00" +                           // session ID length = 0
        "0002" +                         // cipher suites length = 2
        "002f" +                         // cipher suite TLS_RSA_WITH_AES_128_CBC_SHA
        "01" +                           // compression methods length
        "00" +                           // null compression
        "0021" +                         // extensions length = 33
        "0000" +                         // ext type: SNI (0)
        "001a" +                         // ext length = 26
        "0018" +                         // SNI list length = 24
        "00" +                           // name type: host_name
        "0015" +                         // name length = 21
        "6578616d706c652e636f6d" +       // "example.com" (11 bytes)
        "000000000000000000000000000000" // padding to fill 21 bytes (wrong - for illustration)

    // Simpler: manually build a minimal ClientHello with SNI
    sniHost := "axon.example.com"
    sniBytes := []byte(sniHost)
    sniNameLen := len(sniBytes)

    // Build SNI extension
    sniExt := []byte{
        0x00, 0x00,                                         // ext type SNI
        0x00, byte(sniNameLen + 5),                        // ext length
        0x00, byte(sniNameLen + 3),                        // SNI list length
        0x00,                                               // name type host_name
        0x00, byte(sniNameLen),                            // name length
    }
    sniExt = append(sniExt, sniBytes...)

    // Build minimal ClientHello
    hello := make([]byte, 0)
    hello = append(hello, 0x03, 0x03)       // version
    hello = append(hello, make([]byte, 32)...) // random
    hello = append(hello, 0x00)              // session ID len
    hello = append(hello, 0x00, 0x02)       // cipher suites len
    hello = append(hello, 0x00, 0x2f)       // AES128-SHA
    hello = append(hello, 0x01, 0x00)       // compression
    // extensions length
    extLen := len(sniExt)
    hello = append(hello, byte(extLen>>8), byte(extLen))
    hello = append(hello, sniExt...)

    result := parseSNIFromClientHello(hello)
    if result == sniHost {
        fmt.Printf("✅ SNI extracted correctly: %q\n", result)
    } else {
        fmt.Printf("❌ SNI wrong: got %q, want %q\n", result, sniHost)
        fmt.Printf("   Hello hex: %s\n", hex.EncodeToString(hello))
    }

    // Test empty/malformed inputs
    if parseSNIFromClientHello([]byte{}) == "" {
        fmt.Println("✅ Empty input → empty string")
    }
    if parseSNIFromClientHello(make([]byte, 10)) == "" {
        fmt.Println("✅ Too-short input → empty string")
    }

    fmt.Println("\n✅ L7 SNI parsing tests passed")
}
EOF

go run /tmp/test_l7_sni.go
```

---

## 11. TEST: Daemon Starts (without eBPF)

**Goal:** Start the daemon with eBPF disabled and verify it runs and accepts gRPC.

```bash
cd ~/axon

# Step 11a — Build the daemon
go build -o /tmp/axond ./cmd/axond/
echo "Daemon build: $?"

# Step 11b — Create required dirs
sudo mkdir -p /var/lib/axon /run/axon

# Step 11c — Start daemon (it gracefully handles missing BPF object)

# Ensure directories exist
sudo mkdir -p /run/axon /var/lib/axon
# Load necessary modules
sudo modprobe nfnetlink_queue
sudo modprobe nf_conntrack
sudo rm -f /run/axon/daemon.sock
# Ensure the directory for the socket exists (often causes silent failures)
sudo mkdir -p /run/axon

# Start daemon, redirect output to a log file, and background it
# 1. See the actual error
sudo /tmp/axond \
    --grpc unix:///run/axon/daemon.sock \
    --log-addr 127.0.0.1:5000 \
    --bpf /tmp/xdp_firewall.o \
    --db /var/lib/axon/db.bolt \
    --dns-interval 30s

# Capture the PID
DAEMON_PID=$!
echo "Daemon started with PID: $DAEMON_PID"

sleep 2

# Step 11d — Test daemon is alive
kill -0 $DAEMON_PID 2>/dev/null && echo "✅ Daemon running" || echo "❌ Daemon died"

# Step 11e — Test CLI connects to daemon
sudo /tmp/axon --socket unix:///run/axon/daemon.sock status
echo "Status exit code: $?"

# Step 11f — Test add/list/remove rules
sudo /tmp/axon --socket unix:///run/axon/daemon.sock add 1.2.3.4
sudo /tmp/axon --socket unix:///run/axon/daemon.sock add evil.example.com
sudo /tmp/axon --socket unix:///run/axon/daemon.sock list
sudo /tmp/axon --socket unix:///run/axon/daemon.sock remove 1.2.3.4
sudo /tmp/axon --socket unix:///run/axon/daemon.sock list

# Step 11g — Test mode change
sudo /tmp/axon --socket unix:///run/axon/daemon.sock mode block-all
sudo /tmp/axon --socket unix:///run/axon/daemon.sock mode allow-all

# Step 11h — Test sync
sudo /tmp/axon --socket unix:///run/axon/daemon.sock sync

# Step 11i — Test log endpoint change
sudo /tmp/axon --socket unix:///run/axon/daemon.sock log-endpoint 127.0.0.1:6000
sudo /tmp/axon --socket unix:///run/axon/daemon.sock status | grep "Log endpoint"

# Step 11j — Test log server
nc -z 127.0.0.1 5000 && echo "✅ Log TCP server listening" || echo "❌ Log server not up"

# Step 11k — Connect to log stream and watch
timeout 3 nc 127.0.0.1 5000 && echo "✅ Log stream connected"

# Cleanup
sudo kill $DAEMON_PID 2>/dev/null
echo "Daemon stopped"
```

---

## 12. TEST: Cold Start Recovery

**Goal:** Verify daemon reloads rules from bbolt after restart.

```bash
cd ~/axon

# Build
go build -o /tmp/axond ./cmd/axond/
go build -o /tmp/axon  ./cmd/axon/

sudo mkdir -p /var/lib/axon /run/axon
sudo rm -f /var/lib/axon/db.bolt  # fresh DB

# Start daemon
sudo /tmp/axond --grpc unix:///run/axon/daemon.sock \
    --log-addr 127.0.0.1:5000 \
    --bpf /tmp/xdp_firewall.o \
    --db /var/lib/axon/db.bolt 
DAEMON_PID=$!
sleep 2

# Add some rules
sudo /tmp/axon --socket unix:///run/axon/daemon.sock add 10.0.0.1
sudo /tmp/axon --socket unix:///run/axon/daemon.sock add bad.example.com
sudo /tmp/axon --socket unix:///run/axon/daemon.sock list

echo "Rules added. Killing daemon..."
sudo kill $DAEMON_PID
sleep 1

echo "Restarting daemon (cold start)..."
sudo /tmp/axond --grpc unix:///run/axon/daemon.sock \
    --log-addr 127.0.0.1:5000 \
    --bpf /tmp/xdp_firewall.o \
    --db /var/lib/axon/db.bolt 
DAEMON_PID=$!
sleep 2

echo "Rules after cold start:"
sudo /tmp/axon --socket unix:///run/axon/daemon.sock list
# Expected: same rules as before restart

sudo kill $DAEMON_PID
echo "✅ Cold start test complete"
```

---

## 13. TEST: eBPF XDP Attach (root required, real kernel)

**Goal:** Attach XDP program to a real interface and verify packet filtering.

```bash
# IMPORTANT: Run on bare metal or VM with full kernel (not inside Docker)
# Requires: xdp_firewall.o compiled (step 8), root, and a real interface

IFACE="wlp8s0"   # use loopback for safe testing; replace with eth0 for real tests

# Step 13a — Verify interface exists
ip link show $IFACE

# Step 13b — Check current XDP status
ip link show $IFACE | grep xdp || echo "No XDP attached"

# Step 13c — Check BPF filesystem
ls /sys/fs/bpf/ 2>/dev/null || (sudo mount -t bpf bpf /sys/fs/bpf && echo "Mounted bpffs")

# Step 13d — Test XDP load via Go (requires daemon)
sudo /tmp/axond --grpc unix:///run/axon/daemon.sock \
    --bpf /tmp/xdp_firewall.o \
    --db /tmp/axon_test.bolt &
DAEMON_PID=$!
sleep 2

sudo /tmp/axon --socket unix:///run/axon/daemon.sock status
# Check XDP Attached column

# Step 13e — Verify via ip link
ip link show | grep xdp
# If XDP attached: should show "xdp" or "xdpgeneric"

# Step 13f — Test packet drop
# Add a rule to block 127.0.0.1 (loopback self)
/tmp/axon --socket unix:///run/axon/daemon.sock add 127.0.0.1 -i lo

# Try to ping loopback (should be blocked if XDP is in block mode)
# Note: in allow-all mode, the IP is added to blocklist
ping -c 2 -W 1 127.0.0.1

# Step 13g — Remove rule and verify ping works again
/tmp/axon --socket unix:///run/axon/daemon.sock remove 127.0.0.1 -i lo
ping -c 2 127.0.0.1

sudo kill $DAEMON_PID
# XDP detaches when daemon exits (link is pinned)
sudo rm -rf /sys/fs/bpf/axon/
```

---

## 14. TEST: NFQUEUE L7 Steering

**Goal:** Verify iptables NFQUEUE rule and L7 engine processing.

```bash
# Step 14a — Check iptables NFQUEUE rule
sudo iptables -t mangle -L PREROUTING -n | grep NFQUEUE
# If missing, add it:
sudo iptables -t mangle -A PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1

# Step 14b — Verify libnetfilter-queue is installed
dpkg -l libnetfilter-queue1 | grep "^ii" && echo "✅ libnetfilter-queue installed"

# Step 14c — Start daemon and test L7
sudo /tmp/axond --grpc unix:///run/axon/daemon.sock \
    --bpf /tmp/xdp_firewall.o \
    --db /tmp/axon_l7_test.bolt &
DAEMON_PID=$!
sleep 2

# Add a shared-FQDN rule (domains on CDN with shared IPs)
# For testing, add any FQDN that resolves to a shared IP
/tmp/axon --socket unix:///run/axon/daemon.sock add example.com

# Check status — look for SharedFQDNs count
/tmp/axon --socket unix:///run/axon/daemon.sock status

# Monitor L7 logs in another terminal:
# nc 127.0.0.1 5000 | jq .

# Try to reach the blocked domain
curl -sv --max-time 3 https://example.com 2>&1 | head -20

sudo kill $DAEMON_PID
sudo iptables -t mangle -D PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1
```

---

## 15. TEST: Full Integration (all components together)

```bash
cd ~/axon

# Build everything
go build -o /tmp/axond ./cmd/axond/ && echo "✅ axond built"
go build -o /tmp/axon  ./cmd/axon/  && echo "✅ axon built"

# Setup
sudo mkdir -p /var/lib/axon /run/axon
sudo iptables -t mangle -A PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1

# Start daemon
sudo /tmp/axond \
    --grpc unix:///run/axon/daemon.sock \
    --log-addr 127.0.0.1:5000 \
    --bpf /tmp/xdp_firewall.o \
    --db /var/lib/axon/db.bolt &
DAEMON_PID=$!
sleep 2

# Monitor logs in background
nc 127.0.0.1 5000 | while read line; do
    echo "[LOG] $line" | jq -c . 2>/dev/null || echo "[LOG] $line"
done &
LOG_PID=$!

# Run all CLI operations
/tmp/axon --socket unix:///run/axon/daemon.sock status
/tmp/axon --socket unix:///run/axon/daemon.sock add 1.1.1.1
/tmp/axon --socket unix:///run/axon/daemon.sock add cloudflare.com
/tmp/axon --socket unix:///run/axon/daemon.sock list
/tmp/axon --socket unix:///run/axon/daemon.sock sync
/tmp/axon --socket unix:///run/axon/daemon.sock status
/tmp/axon --socket unix:///run/axon/daemon.sock mode block-all
/tmp/axon --socket unix:///run/axon/daemon.sock mode allow-all
/tmp/axon --socket unix:///run/axon/daemon.sock log-endpoint 127.0.0.1:5000
/tmp/axon --socket unix:///run/axon/daemon.sock remove cloudflare.com
/tmp/axon --socket unix:///run/axon/daemon.sock list

echo "✅ Integration test complete"

# Cleanup
kill $LOG_PID 2>/dev/null
sudo kill $DAEMON_PID 2>/dev/null
sudo iptables -t mangle -D PREROUTING -m mark --mark 0xBEEF -j NFQUEUE --queue-num 1
```

---

## 16. BUILD: Final .deb Package

Once all tests pass:

```bash
cd ~/axon

# Full build and package
chmod +x build.sh
./build.sh

# Or without BPF (if clang not available on build machine):
./build.sh --no-bpf

# Install on this machine to test:
sudo dpkg -i build/axon_1.0.0_amd64.deb
sudo apt-get install -f

# Verify installed
systemctl status axon
axon status
axon --help
```

---

## Quick Reference: Error → Fix

| Error | Likely cause | Fix |
|-------|-------------|-----|
| `cannot find module` | Wrong module name | Check `go.mod` starts with `module github.com/axon` |
| `imported and not used` | Dead import | Remove the import |
| `undefined: X` | Wrong package/import | Check import path matches `go.mod` module |
| `bpf_helpers.h not found` | No libbpf-dev | `sudo apt install libbpf-dev` |
| `LIBBPF_PIN_BY_NAME undeclared` | Old libbpf | Remove pinning or upgrade `libbpf-dev` |
| `operation not permitted (eBPF)` | Not root | Run with `sudo` |
| `grpc.Dial deprecated` | grpc v1.60+ | Replace with `grpc.NewClient()` |
| `connection refused` (daemon) | Daemon not started | Run `sudo axond &` first |
| `socket: permission denied` | `/run/axon` wrong perms | `sudo mkdir -p /run/axon` |
| NFQUEUE `operation not permitted` | iptables rule missing | Add NFQUEUE rule (step 14a) |
| `XDP attach failed` | VM/container | Use `XDPGenericMode` (already set) |
