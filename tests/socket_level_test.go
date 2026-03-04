package tests

import (
	"net"
	"os"
	"testing"
)

func TestSocketPermissionsAndCleanup(t *testing.T) {
	// 1. Setup a temp directory to simulate /run/axon
	tmpDir, err := os.MkdirTemp("", "axon_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := tmpDir + "/daemon.sock"

	// 2. Test Cleanup Logic (simulate a stale file from a crash)
	os.WriteFile(socketPath, []byte("stale"), 0644)
	if err := os.Remove(socketPath); err != nil {
		t.Errorf("Failed to remove stale socket: %v", err)
	}

	// 3. Test Bind (Listen)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to bind to unix socket: %v", err)
	}
	defer ln.Close()

	// 4. Test Permissions Logic (ensure non-root can talk to it)
	if err := os.Chmod(socketPath, 0666); err != nil {
		t.Errorf("Failed to set 0666 permissions: %v", err)
	}

	fileInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	
	// Verify it is actually a socket (mode bit 'S')
	if fileInfo.Mode()&os.ModeSocket == 0 {
		t.Error("File exists but is not a Unix socket")
	}
}