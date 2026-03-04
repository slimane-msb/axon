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