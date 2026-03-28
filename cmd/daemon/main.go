package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "axon/proto"

	"google.golang.org/grpc"
)

const (
	grpcAddr     = "127.0.0.1:50051"
	xdpBin       = "./ebpf/block_ip"
	l7Bin        = "./sinkhole/target/release/ctl"
	syncInterval = 60 * 5 * time.Second
)

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
	log.Printf("[daemon] resolve %s: no IPv4", fqdn)
	return ""
}

func revdns(ip string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[daemon] revdns %s: %v", ip, err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	result := strings.TrimSpace(string(body))
	if strings.Contains(result, "error") || strings.Contains(result, "No records") || result == "" {
		log.Printf("[daemon] revdns %s: no neighbors", ip)
		return nil
	}
	neighbors := strings.Split(result, "\n")
	log.Printf("[daemon] revdns %s: %d neighbors", ip, len(neighbors))
	return neighbors
}

func fqdnIsShared(fqdn, ip string) bool {
	neighbors := revdns(ip)
	for _, n := range neighbors {
		if strings.TrimSpace(n) != fqdn {
			return true
		}
	}
	return false
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

func runL7(val, op string) error {
	abs, err := filepath.Abs(l7Bin)
	if err != nil {
		return err
	}
	log.Printf("[sinkhole] exec: %s %s %s", abs, op, val)
	cmd := exec.Command(abs, op, val)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			log.Printf("[sinkhole] %s", line)
		}
	}
	if err != nil {
		log.Printf("[sinkhole] error: %v", err)
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[sinkhole] ok: %s %s", op, val)
	return nil
}

func syncIface(iface string, s *IFState) error {
	log.Printf("[daemon] sync %s", iface)
	wantL3 := map[string]bool{}
	wantL7 := map[string]bool{}

	for ip := range s.IPs {
		wantL3[ip] = true
	}

	for fqdn := range s.FQDNs {
		ip := resolveIPv4(fqdn)
		if ip == "" {
			continue
		}
		if fqdnIsShared(fqdn, ip) {
			log.Printf("[daemon] %s shares ip %s -> L7", fqdn, ip)
			wantL7[fqdn] = true
		} else {
			log.Printf("[daemon] %s alone on ip %s -> L3", fqdn, ip)
			wantL3[ip] = true
		}
	}

	log.Printf("[daemon] sync %s: wantL3=%v wantL7=%v", iface, keys(wantL3), keys(wantL7))

	for ip := range s.AppliedL3 {
		if !wantL3[ip] {
			log.Printf("[daemon] remove L3 %s on %s", ip, iface)
			runBin("ebpf", xdpBin, iface, ip, "remove")
			delete(s.AppliedL3, ip)
		}
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

	for f := range s.AppliedL7 {
		if !wantL7[f] {
			log.Printf("[daemon] remove L7 %s on %s", f, iface)
			runL7(f, "remove")
			delete(s.AppliedL7, f)
		}
	}
	for f := range wantL7 {
		if !s.AppliedL7[f] {
			log.Printf("[daemon] add L7 %s on %s", f, iface)
			if err := runL7(f, "add"); err != nil {
				return err
			}
			s.AppliedL7[f] = true
		}
	}

	return nil
}

func syncAll() {
	mu.Lock()
	defer mu.Unlock()
	log.Printf("[daemon] periodic sync: %d interfaces", len(db))
	for iface, s := range db {
		syncIface(iface, s)
	}
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

func handle(m *pb.Request) (string, error) {
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
			return "", nil
		}
		for ip := range s.AppliedL3 {
			runBin("ebpf", xdpBin, m.Iface, ip, "remove")
		}
		for f := range s.AppliedL7 {
			runL7(f, "remove")
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

type server struct {
	pb.UnimplementedAxonServer
}

func (s *server) Exec(_ context.Context, req *pb.Request) (*pb.Response, error) {
	data, err := handle(req)
	if err != nil {
		log.Printf("[daemon] handle error: %v", err)
		return &pb.Response{Ok: false, Err: err.Error()}, nil
	}
	return &pb.Response{Ok: true, Data: data}, nil
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	ln, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal(err)
	}

	gs := grpc.NewServer()
	pb.RegisterAxonServer(gs, &server{})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Printf("[daemon] shutting down")
		gs.GracefulStop()
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(syncInterval)
		for range t.C {
			syncAll()
		}
	}()

	log.Printf("[daemon] listening on %s", grpcAddr)
	if err := gs.Serve(ln); err != nil {
		log.Fatal(err)
	}
}