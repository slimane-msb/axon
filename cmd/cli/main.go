package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
)

const sockPath = "/tmp/blockd.sock"

type Msg struct {
	Cmd   string `json:"cmd"`
	Iface string `json:"iface"`
	Val   string `json:"val"`
}

type Resp struct {
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Data string `json:"data,omitempty"`
}

var needsVal = map[string]bool{
	"add-ip": true, "remove-ip": true,
	"add-web": true, "remove-web": true,
	"add-web-file": true, "remove-web-file": true,
}

func send(m Msg) error {
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	var r Resp
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("%s", r.Err)
	}
	if r.Data != "" {
		fmt.Println(r.Data)
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
	m := Msg{Cmd: cmd}
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