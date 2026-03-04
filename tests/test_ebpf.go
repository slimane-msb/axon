package main

import (
    "fmt"
    "github.com/axon/internal/ebpf"
)

func main() {
    mgr, err := ebpf.NewXDPManager("/tmp/xdp_firewall.o")
    if err != nil {
        fmt.Printf("❌ XDP Manager init: %v\n", err)
        // This is expected in containers/VMs without BPF support
        return
    }
    fmt.Println("✅ XDP Manager initialized")
    mgr.Close()
}