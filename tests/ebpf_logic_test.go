package tests

import (
    "encoding/binary"
    "fmt"
    "net"
    "testing"
)

// IPToU32 converts a net.IP to a uint32 (Big Endian).
// Note: In eBPF, the kernel often expects Network Byte Order (Big Endian).
func IPToU32(ip net.IP) (uint32, error) {
    ip = ip.To4()
    if ip == nil {
        return 0, fmt.Errorf("not a valid IPv4 address")
    }
    return binary.BigEndian.Uint32(ip), nil
}

func TestIPConversion(t *testing.T) {
    tests := []struct {
        ip       string
        expected uint32
        shouldFail bool
    }{
        {"1.2.3.4",         0x01020304, false},
        {"192.168.1.1",     0xC0A80101, false},
        {"10.0.0.1",        0x0A000001, false},
        {"255.255.255.255", 0xFFFFFFFF, false},
        {"::1",             0,          true},  // IPv6 should fail
        {"not-an-ip",       0,          true},  // Garbage should fail
    }

    for _, tt := range tests {
        t.Run(tt.ip, func(t *testing.T) {
            parsedIP := net.ParseIP(tt.ip)
            got, err := IPToU32(parsedIP)

            if tt.shouldFail {
                if err == nil {
                    t.Errorf("Expected error for input %s, but got nil", tt.ip)
                }
                return
            }

            if err != nil {
                t.Errorf("Unexpected error for %s: %v", tt.ip, err)
                return
            }

            if got != tt.expected {
                t.Errorf("IP %s: got 0x%08X, want 0x%08X", tt.ip, got, tt.expected)
            }
        })
    }
}