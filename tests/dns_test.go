package tests

import (
    "context"
    "net"
    "testing"
    "time"
    "github.com/axon/internal/dns"
    "github.com/axon/internal/logging"
)

func TestDNSResolverAndClassification(t *testing.T) {
    logger := logging.NewLogger("test-dns")
    r := dns.NewResolver("", logger)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // 1. Test Real Resolution (Google)
    domain := "google.com"
    ips, ttl, err := r.ResolveFQDN(ctx, domain)
    if err != nil {
        t.Skipf("Skipping live DNS check: %v (Check your internet connection)", err)
    } else {
        r.UpdateCache(domain, ips, ttl)
        
        // 2. Test Cache Hit
        cachedIPs, ok := r.GetCached(domain)
        if !ok || len(cachedIPs) == 0 {
            t.Errorf("Expected cache hit for %s, but got miss", domain)
        }
    }

    // 3. Test IP Classification Logic (The "Axon" Core Logic)
    // We simulate a scenario where two domains resolve to the same IP.
    fqdnIPs := map[string][]net.IP{
        "a.example.com": {net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")},
        "b.example.com": {net.ParseIP("1.2.3.4"), net.ParseIP("9.10.11.12")},
        "c.example.com": {net.ParseIP("200.1.1.1")},
    }

    classified := dns.ClassifyIPs(fqdnIPs)

    // Check for Shared IP: 1.2.3.4 should be shared by a and b
    if domains, ok := classified.Shared["1.2.3.4"]; ok {
        if len(domains) != 2 {
            t.Errorf("Expected 2 domains for shared IP 1.2.3.4, got %d", len(domains))
        }
    } else {
        t.Error("IP 1.2.3.4 should have been classified as SHARED")
    }

    // Check for Unique IP: 200.1.1.1 should belong only to c.example.com
    if origin, ok := classified.Unique["200.1.1.1"]; ok {
        if origin != "c.example.com" {
            t.Errorf("Expected 200.1.1.1 to belong to c.example.com, got %s", origin)
        }
    } else {
        t.Error("IP 200.1.1.1 should have been classified as UNIQUE")
    }
}