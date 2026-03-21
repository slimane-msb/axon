package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	sockPath = "/tmp/blockd.sock"
	xdpBin   = "./ebpf/block_ip"
	l7Bin    = "./sinkhole/block"
)

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

type IFState struct {
	IPs       map[string]bool
	FQDNs     map[string]bool
	AppliedL3 map[string]bool
	AppliedL7 map[string]bool
}

func newIFS() *IFState {
	return &IFState{
		IPs:       map[string]bool{},
		FQDNs:     map[string]bool{},
		AppliedL3: map[string]bool{},
		AppliedL7: map[string]bool{},
	}
}

var (
	mu sync.Mutex
	db = map[string]*IFState{}
)

func resolveIPv4(fqdn string) string {
	addrs, err := net.LookupHost(fqdn)
	if err != nil {
		log.Printf("[daemon] resolve %s: %v", fqdn, err)
		return ""
	}
	for _, a := range addrs {
		if !strings.Contains(a, ":") {
			log.Printf("[daemon] resolve %s -> %s", fqdn, a)
			return a
		}
	}
	log.Printf("[daemon] resolve %s: no IPv4 result", fqdn)
	return ""
}

func runBin(tag, bin, iface, val, op string) error {
	abs, err := filepath.Abs(bin)
	if err != nil {
		return err
	}
	args := []string{abs, iface, val, op}
	log.Printf("[%s] exec: sudo %s", tag, strings.Join(args, " "))
	cmd := exec.Command("sudo", args...)
	cmd.Dir = filepath.Dir(abs)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			log.Printf("[%s] %s", tag, line)
		}
	}
	if err != nil {
		log.Printf("[%s] error: %v", tag, err)
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[%s] ok: %s %s %s", tag, iface, val, op)
	return nil
}

func syncIface(iface string, s *IFState) error {
	log.Printf("[daemon] sync %s: ips=%v fqdns=%v", iface, keys(s.IPs), keys(s.FQDNs))
	wantL3 := map[string]bool{}
	wantL7 := map[string]bool{}

	for ip := range s.IPs {
		wantL3[ip] = true
	}

	ipToFQDNs := map[string][]string{}
	for fqdn := range s.FQDNs {
		if ip := resolveIPv4(fqdn); ip != "" {
			ipToFQDNs[ip] = append(ipToFQDNs[ip], fqdn)
		}
	}

	for ip, fqdns := range ipToFQDNs {
		if len(fqdns) > 1 {
			log.Printf("[daemon] ip %s shared by %v -> L7", ip, fqdns)
			for _, f := range fqdns {
				wantL7[f] = true
			}
		} else {
			log.Printf("[daemon] fqdn %s -> ip %s unique -> L3", fqdns[0], ip)
			wantL3[ip] = true
		}
	}

	log.Printf("[daemon] sync %s: wantL3=%v wantL7=%v", iface, keys(wantL3), keys(wantL7))

	var delL3 []string
	for ip := range s.AppliedL3 {
		if !wantL3[ip] {
			delL3 = append(delL3, ip)
		}
	}
	for _, ip := range delL3 {
		log.Printf("[daemon] remove L3 %s on %s", ip, iface)
		runBin("ebpf", xdpBin, iface, ip, "remove")
		delete(s.AppliedL3, ip)
	}
	for ip := range wantL3 {
		if !s.AppliedL3[ip] {
			log.Printf("[daemon] add L3 %s on %s", ip, iface)
			if err := runBin("ebpf", xdpBin, iface, ip, "add"); err != nil {
				return err
			}
			s.AppliedL3[ip] = true
		}
	}

	var delL7 []string
	for f := range s.AppliedL7 {
		if !wantL7[f] {
			delL7 = append(delL7, f)
		}
	}
	for _, f := range delL7 {
		log.Printf("[daemon] remove L7 %s on %s", f, iface)
		runBin("sinkhole", l7Bin, iface, f, "remove")
		delete(s.AppliedL7, f)
	}
	for f := range wantL7 {
		if !s.AppliedL7[f] {
			log.Printf("[daemon] add L7 %s on %s", f, iface)
			if err := runBin("sinkhole", l7Bin, iface, f, "add"); err != nil {
				return err
			}
			s.AppliedL7[f] = true
		}
	}

	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

func getOrCreate(iface string) *IFState {
	if db[iface] == nil {
		db[iface] = newIFS()
	}
	return db[iface]
}

func handle(m Msg) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	log.Printf("[daemon] cmd=%s iface=%s val=%s", m.Cmd, m.Iface, m.Val)

	switch m.Cmd {
	case "add-iface":
		getOrCreate(m.Iface)
		log.Printf("[daemon] added iface %s", m.Iface)

	case "remove-iface":
		s := db[m.Iface]
		if s == nil {
			log.Printf("[daemon] remove-iface: %s not found", m.Iface)
			return "", nil
		}
		for ip := range s.AppliedL3 {
			runBin("ebpf", xdpBin, m.Iface, ip, "remove")
		}
		for f := range s.AppliedL7 {
			runBin("sinkhole", l7Bin, m.Iface, f, "remove")
		}
		delete(db, m.Iface)
		log.Printf("[daemon] removed iface %s", m.Iface)

	case "add-ip":
		s := getOrCreate(m.Iface)
		s.IPs[m.Val] = true
		return "", syncIface(m.Iface, s)

	case "remove-ip":
		s := db[m.Iface]
		if s == nil {
			log.Printf("[daemon] remove-ip: iface %s not found", m.Iface)
			return "", nil
		}
		delete(s.IPs, m.Val)
		return "", syncIface(m.Iface, s)

	case "add-web":
		s := getOrCreate(m.Iface)
		s.FQDNs[m.Val] = true
		return "", syncIface(m.Iface, s)

	case "remove-web":
		s := db[m.Iface]
		if s == nil {
			log.Printf("[daemon] remove-web: iface %s not found", m.Iface)
			return "", nil
		}
		delete(s.FQDNs, m.Val)
		return "", syncIface(m.Iface, s)

	case "add-web-file":
		lines, err := readLines(m.Val)
		if err != nil {
			return "", err
		}
		log.Printf("[daemon] add-web-file: %d entries from %s", len(lines), m.Val)
		s := getOrCreate(m.Iface)
		for _, l := range lines {
			s.FQDNs[l] = true
		}
		return "", syncIface(m.Iface, s)

	case "remove-web-file":
		s := db[m.Iface]
		if s == nil {
			return "", nil
		}
		lines, err := readLines(m.Val)
		if err != nil {
			return "", err
		}
		log.Printf("[daemon] remove-web-file: %d entries from %s", len(lines), m.Val)
		for _, l := range lines {
			delete(s.FQDNs, l)
		}
		return "", syncIface(m.Iface, s)

	case "status":
		type ifaceStatus struct {
			IPs   []string `json:"ips"`
			FQDNs []string `json:"fqdns"`
			L3    []string `json:"l3_applied"`
			L7    []string `json:"l7_applied"`
		}
		result := map[string]ifaceStatus{}
		for iface, s := range db {
			if m.Iface != "" && m.Iface != iface {
				continue
			}
			st := ifaceStatus{}
			for ip := range s.IPs {
				st.IPs = append(st.IPs, ip)
			}
			for f := range s.FQDNs {
				st.FQDNs = append(st.FQDNs, f)
			}
			for ip := range s.AppliedL3 {
				st.L3 = append(st.L3, ip)
			}
			for f := range s.AppliedL7 {
				st.L7 = append(st.L7, f)
			}
			result[iface] = st
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		return string(b), nil

	default:
		return "", fmt.Errorf("unknown cmd: %s", m.Cmd)
	}
	return "", nil
}

func serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			var m Msg
			if err := json.NewDecoder(c).Decode(&m); err != nil {
				log.Printf("[daemon] decode error: %v", err)
				json.NewEncoder(c).Encode(Resp{OK: false, Err: err.Error()})
				return
			}
			data, err := handle(m)
			if err != nil {
				log.Printf("[daemon] handle error: %v", err)
				json.NewEncoder(c).Encode(Resp{OK: false, Err: err.Error()})
			} else {
				json.NewEncoder(c).Encode(Resp{OK: true, Data: data})
			}
		}(c)
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		ln.Close()
		os.Remove(sockPath)
		os.Exit(0)
	}()
	log.Printf("[daemon] listening on %s", sockPath)
	serve(ln)
}