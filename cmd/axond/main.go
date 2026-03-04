// axond - Hybrid L3/L7 Firewall Daemon
// Per-interface, FQDN-centric with DNS grace periods and L7 steering
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/axon/internal/daemon"
	grpcserver "github.com/axon/internal/grpc"
	"github.com/axon/internal/logging"
)

const defaultLogAddr = "127.0.0.1:5000"

func main() {
	var (
		grpcAddr    = flag.String("grpc", "unix:///run/axon/daemon.sock", "gRPC listen address")
		logAddr     = flag.String("log-addr", defaultLogAddr, "TCP log server address (host:port)")
		bpfObj      = flag.String("bpf", "/usr/lib/axon/xdp_firewall.o", "Path to compiled BPF object")
		dbPath      = flag.String("db", "/var/lib/axon/db.bolt", "Path to bbolt database")
		nameserver  = flag.String("nameserver", "", "Custom DNS nameserver (empty = system)")
		dnsInterval = flag.Duration("dns-interval", 30*time.Second, "DNS refresh interval")
		version     = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Printf("axond v%s\n", daemon.Version)
		os.Exit(0)
	}

	// Ensure required directories exist
	for _, dir := range []string{"/var/lib/axon", "/run/axon"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: create dir %s: %v\n", dir, err)
			os.Exit(1)
		}
	}

	logger := logging.NewLogger("main")
	logger.Infof("Starting axon daemon v%s", daemon.Version)
	logger.Infof("gRPC: %s | Log server: %s | BPF: %s", *grpcAddr, *logAddr, *bpfObj)

	cfg := daemon.Config{
		BPFObjPath:  *bpfObj,
		DBPath:      *dbPath,
		GRPCAddr:    *grpcAddr,
		LogAddr:     *logAddr,
		Nameserver:  *nameserver,
		DNSInterval: *dnsInterval,
	}

	d, err := daemon.New(cfg)
	if err != nil {
		logger.Errorf("Daemon init failed: %v", err)
		os.Exit(1)
	}

	if err := d.Start(); err != nil {
		logger.Errorf("Daemon start failed: %v", err)
		os.Exit(1)
	}

	// Set default log addr from stored config or flag
	if d.GetLogEndpoint() == "" {
		_ = d.SetLogEndpoint(*logAddr)
	}

	// Start gRPC server
	grpcSrv := grpcserver.NewServer(d)
	go func() {
		if err := grpcSrv.Listen(*grpcAddr); err != nil {
			logger.Errorf("gRPC server error: %v", err)
		}
	}()

	// Start TCP log server
	logServer := logging.NewServer(*logAddr, d.Hub(), logging.NewLogger("log-server"))
	go func() {
		if err := logServer.Run(); err != nil {
			logger.Errorf("Log server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Infof("Received signal %s, shutting down...", sig)

	d.Stop()
	logger.Infof("Shutdown complete")
}
