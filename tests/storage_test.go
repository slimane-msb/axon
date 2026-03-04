package tests

import (
    "os"
    "testing"
    "time"
    "github.com/axon/internal/storage"
)

func TestStorageWorkflow(t *testing.T) {
    dbPath := "/tmp/axon_test.bolt"
    os.Remove(dbPath) // Clean start
    // Clean up after the test finishes
    defer os.Remove(dbPath)

    s, err := storage.Open(dbPath)
    if err != nil {
        t.Fatalf("Failed to open storage: %v", err)
    }
    defer s.Close()

    // 1. Test Interface Init
    if err := s.InitInterface("eth0"); err != nil {
        t.Errorf("InitInterface failed: %v", err)
    }

    // 2. Test Explicit IP
    targetIP := "1.2.3.4"
    err = s.PutExplicitIP("eth0", targetIP, storage.RuleEntry{
        RuleType: "block",
        AddedAt:  time.Now(),
    })
    if err != nil {
        t.Fatalf("PutExplicitIP failed: %v", err)
    }

    ips, err := s.GetExplicitIPs("eth0")
    if err != nil {
        t.Errorf("GetExplicitIPs failed: %v", err)
    }
    if _, ok := ips[targetIP]; !ok {
        t.Errorf("Expected IP %s not found in storage", targetIP)
    }

    // 3. Test FQDN
    domain := "evil.example.com"
    err = s.PutFQDN("eth0", domain, storage.FQDNEntry{
        RuleType: "block",
        AddedAt:  time.Now(),
    })
    if err != nil {
        t.Errorf("PutFQDN failed: %v", err)
    }

    // 4. Test Derived IP
    err = s.PutDerivedIP("eth0", "93.184.216.34", storage.DerivedIPEntry{
        FQDN:     domain,
        LastSeen: time.Now(),
        TTL:      60,
        IsShared: false,
    })
    if err != nil {
        t.Errorf("PutDerivedIP failed: %v", err)
    }

    // 5. Test Config
    expectedEndpoint := "127.0.0.1:5000"
    _ = s.SetConfig(storage.KeyLogEndpoint, expectedEndpoint)
    val, _ := s.GetConfig(storage.KeyLogEndpoint)
    if val != expectedEndpoint {
        t.Errorf("Config mismatch: expected %s, got %s", expectedEndpoint, val)
    }

    // 6. Test Delete
    _ = s.DeleteExplicitIP("eth0", targetIP)
    ipsAfterDelete, _ := s.GetExplicitIPs("eth0")
    if _, ok := ipsAfterDelete[targetIP]; ok {
        t.Error("IP still present after deletion")
    }
}