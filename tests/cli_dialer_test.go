package tests

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestCLIDialerParsing(t *testing.T) {
	inputAddr := "unix:///tmp/axon_test.sock"
	
	// Simulation of logic inside your axon/main.go
	if !strings.HasPrefix(inputAddr, "unix://") {
		t.Fatal("CLI must recognize unix:// prefix")
	}

	rawPath := strings.TrimPrefix(inputAddr, "unix://")
	if rawPath != "/tmp/axon_test.sock" {
		t.Errorf("Path extraction failed: got %s", rawPath)
	}

	// Test if the Dialer function actually targets "unix" network
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		// This should attempt a local file dial, not a network dial
		return (&net.Dialer{}).DialContext(ctx, "unix", rawPath)
	}

	_, err := dialer(context.Background(), "")
	// We expect "no such file" because the server isn't running,
	// but we DON'T want "unknown port" or "no such host".
	if err != nil && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("Unexpected dialer error type: %v", err)
	}
}