package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "axon/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const grpcAddr = "127.0.0.1:50051"

var needsVal = map[string]bool{
	"add-ip": true, "remove-ip": true,
	"add-web": true, "remove-web": true,
	"add-web-file": true, "remove-web-file": true,
}

func send(m *pb.Request) error {
	log.Printf("[cli] connecting to %s", grpcAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	defer conn.Close()

	log.Printf("[cli] sending cmd=%s iface=%s val=%s", m.Cmd, m.Iface, m.Val)
	resp, err := pb.NewAxonClient(conn).Exec(ctx, m)
	if err != nil {
		return err
	}
	if !resp.Ok {
		return fmt.Errorf("%s", resp.Err)
	}
	if resp.Data != "" {
		fmt.Println(resp.Data)
	} else {
		fmt.Println("ok")
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: axon <cmd> [iface] [val]
  add-iface        <iface>
  remove-iface     <iface>
  add-ip           <iface> <ip>
  remove-ip        <iface> <ip>
  add-web          <iface> <domain>
  remove-web       <iface> <domain>
  add-web-file     <iface> <file>
  remove-web-file  <iface> <file>
  status           [iface]`)
	os.Exit(1)
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
	}
	cmd := args[0]
	if cmd != "status" && len(args) < 2 {
		usage()
	}
	if needsVal[cmd] && len(args) < 3 {
		fmt.Fprintf(os.Stderr, "error: '%s' requires both <iface> and <val>\n", cmd)
		usage()
	}
	m := &pb.Request{Cmd: cmd}
	if len(args) > 1 {
		m.Iface = args[1]
	}
	if len(args) > 2 {
		m.Val = args[2]
	}
	if err := send(m); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}