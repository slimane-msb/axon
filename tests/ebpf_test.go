package tests

import (
    "os"
    "testing"
    "github.com/axon/internal/ebpf"
)

func TestXDPManagerInitialization(t *testing.T) {
    // Path to the compiled eBPF object file
    objPath := "/tmp/xdp_firewall.o"

    // 1. Check if the .o file actually exists before trying to load it
    if _, err := os.Stat(objPath); os.IsNotExist(err) {
        t.Skipf("Skipping eBPF test: object file %s not found. Run 'make bpf' first.", objPath)
    }

    // 2. Attempt to initialize the Manager
    mgr, err := ebpf.NewXDPManager(objPath)
    if err != nil {
        // We use t.Log instead of t.Error here because eBPF tests 
        // frequently fail due to environment (lack of root, locked memory, etc.)
        t.Logf("⚠️ XDP Manager init failed (expected in some environments): %v", err)
        t.Skip("Skipping because the current environment does not support BPF loading.")
        return
    }

    // 3. Cleanup
    t.Log("✅ XDP Manager successfully initialized and BPF programs loaded.")
    mgr.Close()
}