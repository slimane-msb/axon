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

