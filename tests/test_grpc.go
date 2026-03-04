package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	pb "github.com/axon/proto" // Adjust this path to your proto package
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	socketPath := "/run/axon/daemon.sock"

	// Define a custom dialer for Unix Sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", addr)
	}

	// Connect to the socket
	conn, err := grpc.Dial(socketPath, 
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		log.Fatalf("❌ Did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewFirewallControlClient(conn)

	// Set a timeout for the request
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Call GetStatus
	resp, err := client.GetStatus(ctx, &pb.StatusRequest{})
	if err != nil {
		log.Fatalf("❌ gRPC Call Failed: %v", err)
	}

	fmt.Println("✅ gRPC Daemon is ALIVE")
	fmt.Printf("   Version: %s\n", resp.DaemonVersion)
	fmt.Printf("   Mode:    %s\n", resp.Mode)
	fmt.Printf("   Rules:   %d\n", resp.TotalRules)
}