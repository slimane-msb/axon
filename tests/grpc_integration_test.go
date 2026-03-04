package tests

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/axon/internal/grpc"
	"github.com/axon/internal/daemon"
	pb "github.com/axon/proto"
	standardgrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestFullGRPCIntegration(t *testing.T) {
	socketPath := "/tmp/axon_integration.sock"
	os.Remove(socketPath)
	defer os.Remove(socketPath)

	// 1. Properly initialize the Daemon
	// Use a dummy config so it doesn't try to load real BPF or DB files
	cfg := daemon.Config{
		DBPath:      "/tmp/test_axon.db",
		BPFObjPath:  "/dev/null", // Dummy path
		DNSInterval: 30 * time.Second,
	}
	
	d, err := daemon.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create daemon for test: %v", err)
	}

	srv := grpc.NewServer(d)

	// 2. Start Server
	go func() {
		if err := srv.Listen("unix://" + socketPath); err != nil {
			return
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Dial (Unix)
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", socketPath)
	}

	conn, err := standardgrpc.Dial(socketPath,
		standardgrpc.WithTransportCredentials(insecure.NewCredentials()),
		standardgrpc.WithContextDialer(dialer),
		standardgrpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// 4. Execute Request
	client := pb.NewFirewallControlClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.GetStatus(ctx, &pb.StatusRequest{})
	if err != nil {
		t.Errorf("RPC failed: %v", err)
	} else {
		t.Log("✅ Success: gRPC round-trip completed over Unix Socket!")
	}
}