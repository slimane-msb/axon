package tests

import (
    "net"
    "testing"
    "time"
    "github.com/axon/internal/logging"
)

func TestLoggingHubAndServer(t *testing.T) {
    logger := logging.NewLogger("test")
    hub := logging.NewHub(logger)

    // 1. Test Subscribe and Publish
    ch1 := hub.Subscribe("sub1", 10)
    defer hub.Unsubscribe("sub1")

    testLog := logging.FirewallLog{
        Timestamp: time.Now().Format(time.RFC3339),
        Interface: "eth0",
        SrcIP:     "10.0.0.1",
        DstIP:     "1.2.3.4",
        FQDN:      "evil.example.com",
        Action:    "blocked",
    }

    hub.Publish(testLog)

    select {
    case got := <-ch1:
        if got.SrcIP != "10.0.0.1" {
            t.Errorf("Expected SrcIP 10.0.0.1, got %s", got.SrcIP)
        }
    case <-time.After(1 * time.Second):
        t.Fatal("Timeout: Subscriber 1 did not receive the log")
    }

    // 2. Test TCP Log Server
    serverAddr := "127.0.0.1:15432"
    srv := logging.NewServer(serverAddr, hub, logging.NewLogger("srv"))
    
    // Run server in background
    go func() {
        if err := srv.Run(); err != nil {
            // This might trigger when we close the test, so we just log it
            t.Logf("Server stopped: %v", err)
        }
    }()

    // Give the server a moment to bind to the port
    time.Sleep(100 * time.Millisecond)

    // 3. Connect as Client
    conn, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
    if err != nil {
        t.Fatalf("TCP connect failed: %v", err)
    }
    defer conn.Close()

    // 4. Verify TCP Transmission
    done := make(chan bool, 1)
    go func() {
        buf := make([]byte, 1024)
        _, err := conn.Read(buf)
        if err != nil {
            return
        }
        done <- true
    }()

    // Trigger another publish for the TCP client
    hub.Publish(logging.FirewallLog{Action: "blocked", FQDN: "test.com"})

    select {
    case <-done:
        t.Log("TCP received log successfully")
    case <-time.After(2 * time.Second):
        t.Error("TCP server failed to stream log to client within timeout")
    }
}