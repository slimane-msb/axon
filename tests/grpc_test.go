package tests

import (
    "context"
    "net"
    "os"
    "testing"
    "time"

    pb "github.com/axon/proto" 
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func TestGRPCStatus(t *testing.T) {
    socketPath := "/run/axon/daemon.sock"

    // Check if the socket exists. If not, skip the test instead of failing.
    if _, err := os.Stat(socketPath); os.IsNotExist(err) {
        t.Skipf("Skipping gRPC test: socket %s not found. Is the daemon running?", socketPath)
    }

    // Define a custom dialer for Unix Sockets
    dialer := func(ctx context.Context, addr string) (net.Conn, error) {
        return net.Dial("unix", addr)
    }

    // Connect to the socket with a timeout
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    conn, err := grpc.DialContext(ctx, socketPath, 
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithContextDialer(dialer),
        grpc.WithBlock(), // Wait until connection is established or timeout
    )
    if err != nil {
        t.Fatalf("Failed to connect to gRPC socket: %v", err)
    }
    defer conn.Close()

    client := pb.NewFirewallControlClient(conn)

    // Call GetStatus
    resp, err := client.GetStatus(ctx, &pb.StatusRequest{})
    if err != nil {
        t.Fatalf("gRPC GetStatus call failed: %v", err)
    }

    // Verify response (adjust based on your expected defaults)
    if resp.DaemonVersion == "" {
        t.Error("Received empty DaemonVersion from gRPC")
    }

    t.Logf("Daemon Status: Version=%s, Mode=%s, Rules=%d", 
        resp.DaemonVersion, resp.Mode, resp.TotalRules)
}