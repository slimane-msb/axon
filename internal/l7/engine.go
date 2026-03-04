// Package l7 implements the L7 inspection engine for shared-IP FQDN traffic.
package l7

import (
	"bytes"
	"context" // Added missing import
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/axon/internal/logging"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	NFQueueNum  = 1
	NFQueueSize = 1024
)

// Engine is the L7 inspection engine
type Engine struct {
	mu          sync.RWMutex
	sharedFQDNs map[string]map[string]struct{} // iface → set of FQDNs to block
	hub         *logging.Hub
	logger      *logging.Logger
	nf          *nfqueue.Nfqueue
	cancel      context.CancelFunc // Now correctly identified via import
}

// NewEngine creates the L7 inspection engine
func NewEngine(hub *logging.Hub, logger *logging.Logger) *Engine {
	return &Engine{
		sharedFQDNs: make(map[string]map[string]struct{}),
		hub:         hub,
		logger:      logger,
	}
}

// AddSharedFQDN registers an FQDN for L7 blocking on an interface
func (e *Engine) AddSharedFQDN(iface, fqdn string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sharedFQDNs[iface] == nil {
		e.sharedFQDNs[iface] = make(map[string]struct{})
	}
	e.sharedFQDNs[iface][strings.ToLower(fqdn)] = struct{}{}
}

// RemoveSharedFQDN removes an FQDN from L7 blocking
func (e *Engine) RemoveSharedFQDN(iface, fqdn string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.sharedFQDNs[iface]; ok {
		delete(s, strings.ToLower(fqdn))
	}
}

// GetSharedFQDNs returns current shared FQDNs for status reporting
func (e *Engine) GetSharedFQDNs(iface string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []string
	for fqdn := range e.sharedFQDNs[iface] {
		result = append(result, fqdn)
	}
	return result
}

// shouldBlock checks if an FQDN should be blocked (any interface match)
func (e *Engine) shouldBlock(fqdn string) (bool, string) {
	fqdn = strings.ToLower(fqdn)
	e.mu.RLock()
	defer e.mu.RUnlock()

	for iface, fqdns := range e.sharedFQDNs {
		if _, ok := fqdns[fqdn]; ok {
			return true, iface
		}
	}
	return false, ""
}

// Start begins NFQUEUE processing
func (e *Engine) Start() error {
	cfg := nfqueue.Config{
		NfQueue:      NFQueueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  NFQueueSize,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("open nfqueue: %w", err)
	}
	e.nf = nf

	fn := func(a nfqueue.Attribute) int {
		return e.handlePacket(a)
	}

	// Fix: Proper context management to prevent early panics
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	if err := nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		e.logger.Errorf("NFQUEUE error: %v", err)
		return 1
	}); err != nil {
		cancel() // Clean up context if registration fails
		return fmt.Errorf("register nfqueue handler: %w", err)
	}

	e.logger.Infof("L7 engine started on NFQUEUE %d", NFQueueNum)
	return nil // Added missing return
}

// Stop closes the NFQUEUE handle
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	if e.nf != nil {
		e.nf.Close()
	}
}

func (e *Engine) handlePacket(a nfqueue.Attribute) int {
	// THE FIX: Full guard against nil attributes from go-nfqueue during setup/teardown
	if a.PacketID == nil || a.Payload == nil {
		if a.PacketID != nil {
			_ = e.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		return 0
	}

	payload := *a.Payload
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

	// Try TLS SNI extraction first
	sni := extractTLSSNI(packet)
	if sni != "" {
		if block, iface := e.shouldBlock(sni); block {
			e.emitLog(packet, sni, iface, "blocked")
			return e.dropPacket(a)
		}
		return e.acceptPacket(a)
	}

	// Try HTTP Host header
	host := extractHTTPHost(packet)
	if host != "" {
		if block, iface := e.shouldBlock(host); block {
			e.emitLog(packet, host, iface, "blocked")
			return e.dropPacket(a)
		}
	}

	return e.acceptPacket(a)
}

func (e *Engine) acceptPacket(a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}
	_ = e.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
	return 0
}

func (e *Engine) dropPacket(a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}
	_ = e.nf.SetVerdict(*a.PacketID, nfqueue.NfDrop)
	return 0
}

func (e *Engine) emitLog(packet gopacket.Packet, fqdn, iface, action string) {
	log := logging.FirewallLog{
		Timestamp: time.Now().Format(time.RFC3339),
		Interface: iface,
		FQDN:      fqdn,
		RuleType:  "shared-l7",
		Action:    action,
		Layer:     "L7",
	}

	if ip, ok := packet.NetworkLayer().(*layers.IPv4); ok {
		log.SrcIP = ip.SrcIP.String()
		log.DstIP = ip.DstIP.String()
		log.Protocol = ip.Protocol.String()
	}

	if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
		log.SrcPort = uint32(tcp.SrcPort)
		log.DstPort = uint32(tcp.DstPort)
	}

	e.hub.Publish(log)
}

// ─────────────────────────────────────────────
// TLS SNI extraction
// ─────────────────────────────────────────────

func extractTLSSNI(packet gopacket.Packet) string {
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		return ""
	}

	payload := tcp.Payload
	if len(payload) < 5 {
		return ""
	}

	if payload[0] != 0x16 || payload[1] != 0x03 {
		return ""
	}

	data := payload[5:]
	if len(data) < 4 {
		return ""
	}

	if data[0] != 0x01 {
		return ""
	}

	return parseSNIFromClientHello(data[4:])
}

func parseSNIFromClientHello(hello []byte) string {
	if len(hello) < 38 {
		return ""
	}
	offset := 0
	offset += 2  // Version
	offset += 32 // Random
	if offset >= len(hello) {
		return ""
	}
	sessionIDLen := int(hello[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(hello) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2 + cipherLen
	if offset+1 > len(hello) {
		return ""
	}
	compLen := int(hello[offset])
	offset += 1 + compLen
	if offset+2 > len(hello) {
		return ""
	}
	offset += 2 // Extensions length
	for offset+4 <= len(hello) {
		extType := binary.BigEndian.Uint16(hello[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > len(hello) {
			break
		}
		if extType == 0 && extLen > 5 {
			extData := hello[offset : offset+extLen]
			if len(extData) > 5 && extData[2] == 0 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					return string(extData[5 : 5+nameLen])
				}
			}
		}
		offset += extLen
	}
	return ""
}

// ─────────────────────────────────────────────
// HTTP Host header extraction
// ─────────────────────────────────────────────

func extractHTTPHost(packet gopacket.Packet) string {
	app := packet.ApplicationLayer()
	if app == nil {
		return ""
	}
	payload := app.Payload()
	if len(payload) == 0 || !isHTTPRequest(payload) {
		return ""
	}
	lines := bytes.Split(payload, []byte("\r\n"))
	for _, line := range lines[1:] {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			host := strings.TrimSpace(string(line[5:]))
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return host
		}
	}
	return ""
}

func isHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT "}
	for _, m := range methods {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return false
}