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