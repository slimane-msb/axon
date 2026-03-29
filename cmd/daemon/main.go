package main

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"time"

	pb "axon/proto"

	"google.golang.org/grpc"
)

const (
	grpcAddr     = "127.0.0.1:50051"
	xdpBin       = "./ebpf/block_ip"
	l7Bin        = "./sinkhole/target/release/ctl"
	syncInterval = 5 * 60 * time.Second
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

func isSharedInfrastructure(fqdn, ip string, peers map[string]bool) bool {
	for otherF := range peers {
		if otherF != fqdn && resolveIPv4(otherF) == ip {
			log.Printf("[daemon] local conflict: %s and %s share %s -> shared", fqdn, otherF, ip)
			return true
		}
	}

	conf := &tls.Config{InsecureSkipVerify: true, ServerName: fqdn}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", conf)
	if err != nil {
		log.Printf("[daemon] tls probe %s (%s): %v -> dedicated (L3)", fqdn, ip, err)
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Printf("[daemon] tls probe %s: no certs -> shared (L7)", fqdn)
		return true
	}

	leaf := certs[0]

	if len(leaf.DNSNames) > 5 {
		log.Printf("[daemon] tls probe %s: %d SANs -> shared (L7)", fqdn, len(leaf.DNSNames))
		return true
	}

	isExact := strings.EqualFold(leaf.Subject.CommonName, fqdn)
	for _, san := range leaf.DNSNames {
		if strings.EqualFold(san, fqdn) {
			isExact = true
			break
		}
	}

	if !isExact {
		log.Printf("[daemon] tls probe %s: fqdn not in cert -> shared (L7)", fqdn)
		return true
	}

	if strings.Contains(leaf.Subject.CommonName, "*") {
		log.Printf("[daemon] tls probe %s: wildcard CN -> shared (L7)", fqdn)
		return true
	}
	for _, san := range leaf.DNSNames {
		if strings.Contains(san, "*") {
			log.Printf("[daemon] tls probe %s: wildcard SAN -> shared (L7)", fqdn)
			return true
		}
	}

	log.Printf("[daemon] tls probe %s: dedicated cert -> L3", fqdn)
	return false
}

func runBin(iface, ip, op string) error {
	abs, err := filepath.Abs(xdpBin)
	if err != nil {
		return err
	}
	log.Printf("[ebpf] sudo %s %s %s %s", abs, iface, ip, op)
	cmd := exec.Command("sudo", abs, iface, ip, op)
	cmd.Dir = filepath.Dir(abs)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log.Printf("[ebpf] output: %s", strings.TrimSpace(string(out)))
	}
	if err != nil {
		log.Printf("[ebpf] error: %v", err)
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[ebpf] ok: %s %s %s", iface, ip, op)
	return nil
}

func runL7(val, op string) error {
	abs, err := filepath.Abs(l7Bin)
	if err != nil {
		return err
	}
	log.Printf("[sinkhole] %s %s %s", abs, op, val)
	cmd := exec.Command(abs, op, val)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log.Printf("[sinkhole] output: %s", strings.TrimSpace(string(out)))
	}
	if err != nil {
		log.Printf("[sinkhole] error: %v", err)
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[sinkhole] ok: %s %s", op, val)
	return nil
}

func syncIface(iface string, s *IFState) {
	log.Printf("[daemon] sync %s", iface)

	type fqdnResult struct {
		fqdn   string
		ip     string
		shared bool
	}

	fqdns := make([]string, 0, len(s.FQDNs))
	for f := range s.FQDNs {
		fqdns = append(fqdns, f)
	}
	ips := make(map[string]bool, len(s.IPs))
	for ip := range s.IPs {
		ips[ip] = true
	}

	allPeers := map[string]bool{}
	for _, st := range db {
		for f := range st.FQDNs {
			allPeers[f] = true
		}
	}

	mu.Unlock()
	results := make([]fqdnResult, 0, len(fqdns))
	for _, fqdn := range fqdns {
		ip := resolveIPv4(fqdn)
		if ip == "" {
			continue
		}
		shared := isSharedInfrastructure(fqdn, ip, allPeers)
		results = append(results, fqdnResult{fqdn, ip, shared})
	}
	mu.Lock()

	wantL3 := make(map[string]bool, len(ips))
	for ip := range ips {
		wantL3[ip] = true
	}
	wantL7 := map[string]bool{}

	for _, r := range results {
		if r.shared {
			log.Printf("[daemon] %s on %s -> L7", r.fqdn, r.ip)
			wantL7[r.fqdn] = true
		} else {
			log.Printf("[daemon] %s on %s -> L3", r.fqdn, r.ip)
			wantL3[r.ip] = true
		}
	}

	log.Printf("[daemon] sync %s wantL3=%v wantL7=%v", iface, keys(wantL3), keys(wantL7))

	for ip := range s.AppliedL3 {
		if !wantL3[ip] {
			log.Printf("[daemon] remove L3 %s on %s", ip, iface)
			runBin(iface, ip, "remove")
			delete(s.AppliedL3, ip)
		}
	}
	for ip := range wantL3 {
		if !s.AppliedL3[ip] {
			log.Printf("[daemon] add L3 %s on %s", ip, iface)
			if err := runBin(iface, ip, "add"); err == nil {
				s.AppliedL3[ip] = true
			}
		}
	}

	for f := range s.AppliedL7 {
		if !wantL7[f] {
			log.Printf("[daemon] remove L7 %s", f)
			runL7(f, "remove")
			delete(s.AppliedL7, f)
		}
	}
	for f := range wantL7 {
		if !s.AppliedL7[f] {
			log.Printf("[daemon] add L7 %s", f)
			if err := runL7(f, "add"); err == nil {
				s.AppliedL7[f] = true
			}
		}
	}
}

func syncAll() {
	mu.Lock()
	log.Printf("[daemon] periodic sync: %d interfaces", len(db))
	ifaces := make([]string, 0, len(db))
	for iface := range db {
		ifaces = append(ifaces, iface)
	}
	for _, iface := range ifaces {
		s := db[iface]
		if s != nil {
			syncIface(iface, s)
		}
	}
	mu.Unlock()
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
	log.Printf("[daemon] cmd=%s iface=%s val=%s", m.Cmd, m.Iface, m.Val)

	switch m.Cmd {
	case "add-iface":
		getOrCreate(m.Iface)
		log.Printf("[daemon] added iface %s", m.Iface)
		mu.Unlock()

	case "remove-iface":
		s := db[m.Iface]
		if s == nil {
			mu.Unlock()
			return "", nil
		}
		for ip := range s.AppliedL3 {
			runBin(m.Iface, ip, "remove")
		}
		for f := range s.AppliedL7 {
			runL7(f, "remove")
		}
		delete(db, m.Iface)
		log.Printf("[daemon] removed iface %s", m.Iface)
		mu.Unlock()

	case "add-ip":
		s := getOrCreate(m.Iface)
		s.IPs[m.Val] = true
		syncIface(m.Iface, s)
		mu.Unlock()

	case "remove-ip":
		s := db[m.Iface]
		if s == nil {
			mu.Unlock()
			return "", nil
		}
		delete(s.IPs, m.Val)
		syncIface(m.Iface, s)
		mu.Unlock()

	case "add-web":
		s := getOrCreate(m.Iface)
		s.FQDNs[m.Val] = true
		syncIface(m.Iface, s)
		mu.Unlock()

	case "remove-web":
		val := m.Val
		s := db[m.Iface]
		if s != nil {
			delete(s.FQDNs, val)
			syncIface(m.Iface, s)
		}
		mu.Unlock()
		runL7(val, "remove")

	case "add-web-file":
		lines, err := readLines(m.Val)
		if err != nil {
			mu.Unlock()
			return "", err
		}
		log.Printf("[daemon] add-web-file: %d entries from %s", len(lines), m.Val)
		s := getOrCreate(m.Iface)
		for _, l := range lines {
			s.FQDNs[l] = true
		}
		syncIface(m.Iface, s)
		mu.Unlock()

	case "remove-web-file":
		s := db[m.Iface]
		if s == nil {
			mu.Unlock()
			return "", nil
		}
		lines, err := readLines(m.Val)
		if err != nil {
			mu.Unlock()
			return "", err
		}
		log.Printf("[daemon] remove-web-file: %d entries from %s", len(lines), m.Val)
		for _, l := range lines {
			delete(s.FQDNs, l)
		}
		syncIface(m.Iface, s)
		mu.Unlock()

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
		mu.Unlock()
		return string(b), nil

	default:
		mu.Unlock()
		return "", fmt.Errorf("unknown cmd: %s", m.Cmd)
	}
	return "", nil
}

type server struct{ pb.UnimplementedAxonServer }

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