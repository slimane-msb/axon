// Package daemon implements the axon control plane daemon.
// It manages per-interface eBPF maps, DNS resolution, grace periods,
// cold start recovery, and coordinates L3/L7 firewall decisions.
package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	bpf "github.com/axon/internal/ebpf"
	"github.com/axon/internal/dns"
	"github.com/axon/internal/l7"
	"github.com/axon/internal/logging"
	"github.com/axon/internal/storage"
)

const (
	Version          = "1.0.0"
	DefaultBPFObj    = "/usr/lib/axon/xdp_firewall.o"
	GracePeriodSecs  = 45
)

// InterfaceRules holds per-interface rule state (in-memory)
type InterfaceRules struct {
	ExplicitIPs  map[string]storage.RuleEntry   // ip → rule
	FQDNs        map[string]storage.FQDNEntry   // fqdn → rule
	TentativeIPs map[string]TentativeEntry      // ip → fqdn + last_seen
	SharedFQDNs  map[string]struct{}            // FQDNs whose resolved IP is shared
	Mode         uint8                          // ModeAllowAll | ModeBlockAll
	mu           sync.RWMutex
}

// TentativeEntry tracks a unique FQDN-derived IP with grace period
type TentativeEntry struct {
	FQDN     string
	LastSeen time.Time
}

// Daemon is the firewall control plane
type Daemon struct {
	xdp        *bpf.XDPManager
	store      *storage.Store
	dnsRes     *dns.Resolver
	dnsLoop    *dns.RefreshLoop
	l7Engine   *l7.Engine
	hub        *logging.Hub
	logger     *logging.Logger

	mu         sync.RWMutex
	ifaces     map[string]*InterfaceRules // iface → rules
	globalMode uint8

	ctx    context.Context
	cancel context.CancelFunc
}

// Config holds daemon startup configuration
type Config struct {
	BPFObjPath  string
	DBPath      string
	GRPCAddr    string
	LogAddr     string
	Nameserver  string
	DNSInterval time.Duration
}

// New creates and initializes the daemon
func New(cfg Config) (*Daemon, error) {
	logger := logging.NewLogger("daemon")
	hub    := logging.NewHub(logger)

	// Open storage
	store, err := storage.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	// Create XDP manager
	xdp, err := bpf.NewXDPManager(cfg.BPFObjPath)
	if err != nil {
		logger.Warnf("XDP manager init failed (running without eBPF): %v", err)
		xdp = nil
	}

	dnsLogger := logging.NewLogger("dns")
	resolver  := dns.NewResolver(cfg.Nameserver, dnsLogger)
	l7Eng     := l7.NewEngine(hub, logging.NewLogger("l7"))

	ctx, cancel := context.WithCancel(context.Background())

	d := &Daemon{
		xdp:      xdp,
		store:    store,
		dnsRes:   resolver,
		l7Engine: l7Eng,
		hub:      hub,
		logger:   logger,
		ifaces:   make(map[string]*InterfaceRules),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Set up DNS refresh loop with change handler
	d.dnsLoop = dns.NewRefreshLoop(resolver, cfg.DNSInterval, d.onDNSChange, dnsLogger)

	// Load stored log endpoint
	if ep, _ := store.GetConfig(storage.KeyLogEndpoint); ep != "" {
		hub.SetEndpoint(ep)
	}

	return d, nil
}

// Start performs cold start recovery and launches background workers
func (d *Daemon) Start() error {
	d.logger.Infof("axon daemon v%s starting...", Version)

	// Cold start: reload all rules from bbolt → eBPF maps immediately
	if err := d.coldStart(); err != nil {
		d.logger.Warnf("Cold start partial failure: %v", err)
	}

	// Start L7 NFQUEUE engine
	if err := d.l7Engine.Start(); err != nil {
		d.logger.Warnf("L7 engine start failed (NFQUEUE unavailable): %v", err)
	}

	// Start DNS refresh loop
	go d.dnsLoop.Run(d.ctx)

	// Start ring buffer poller
	if d.xdp != nil {
		go d.pollRingBuffer()
	}

	// Start grace period janitor
	go d.graceJanitor()

	d.logger.Infof("Daemon started successfully")
	return nil
}

// Stop shuts down the daemon gracefully
func (d *Daemon) Stop() {
	d.cancel()
	d.l7Engine.Stop()
	if d.xdp != nil {
		d.xdp.Close()
	}
	_ = d.store.Close()
	d.logger.Infof("Daemon stopped")
}

// ─────────────────────────────────────────────
// Cold Start / Recovery
// ─────────────────────────────────────────────

func (d *Daemon) coldStart() error {
	d.logger.Infof("Cold start: loading rules from storage...")

	ifaces, err := d.store.ListInterfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if err := d.loadInterfaceFromStore(iface); err != nil {
			d.logger.Warnf("Cold start: iface %s: %v", iface, err)
		}
	}

	// Trigger immediate DNS re-resolution in background
	go func() {
		time.Sleep(500 * time.Millisecond) // let eBPF maps populate first
		d.dnsLoop.ForceRefresh(d.ctx)
	}()

	return nil
}

func (d *Daemon) loadInterfaceFromStore(iface string) error {
	rules := d.getOrCreateIface(iface)
	rules.mu.Lock()
	defer rules.mu.Unlock()

	// Load explicit IPs
	explicitIPs, err := d.store.GetExplicitIPs(iface)
	if err != nil {
		return err
	}
	rules.ExplicitIPs = explicitIPs

	// Load FQDNs
	fqdns, err := d.store.GetFQDNs(iface)
	if err != nil {
		return err
	}
	rules.FQDNs = fqdns

	// Load derived IPs (tentative + shared) respecting grace period
	derivedIPs, err := d.store.GetDerivedIPs(iface)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-storage.GracePeriod)

	for ipStr, entry := range derivedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Skip truly expired IPs (past grace period)
		if entry.LastSeen.Before(cutoff) {
			continue
		}

		ifindex := ifaceIndex(iface)
		if ifindex <= 0 {
			continue
		}

		if entry.IsShared {
			rules.SharedFQDNs[entry.FQDN] = struct{}{}
			if d.xdp != nil {
				_ = d.xdp.AddSharedIP(ifindex, ip)
			}
			d.l7Engine.AddSharedFQDN(iface, entry.FQDN)
		} else {
			rules.TentativeIPs[ipStr] = TentativeEntry{
				FQDN:     entry.FQDN,
				LastSeen: entry.LastSeen,
			}
			if d.xdp != nil {
				_ = d.xdp.AddTentativeIP(ifindex, ip)
			}
		}
	}

	// Attach TC hook before populating maps (idempotent)
	ifindex := ifaceIndex(iface)
	d.ensureAttached(iface, ifindex)

	// Populate explicit IPs into eBPF
	if d.xdp != nil && ifindex > 0 {
		for ipStr := range explicitIPs {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				_ = d.xdp.AddExplicitIP(ifindex, ip)
			}
		}
	}

	// Register FQDNs for DNS tracking
	for fqdn := range fqdns {
		d.dnsLoop.AddFQDN(iface, fqdn)
	}

	d.logger.Infof("Loaded iface %s: %d explicit, %d fqdns, %d tentative",
		iface, len(explicitIPs), len(fqdns), len(rules.TentativeIPs))

	return nil
}

// ─────────────────────────────────────────────
// Rule Management
// ─────────────────────────────────────────────

// AddRule adds an IP or FQDN rule for an interface
func (d *Daemon) AddRule(iface, target, ruleType string) error {
	if iface == "" {
		iface = "all"
	}

	if err := d.store.InitInterface(iface); err != nil {
		return err
	}

	rules := d.getOrCreateIface(iface)

	// Determine if target is IP or FQDN
	if ip := net.ParseIP(target); ip != nil {
		return d.addExplicitIP(rules, iface, ip, ruleType)
	}
	return d.addFQDN(rules, iface, target, ruleType)
}

func (d *Daemon) addExplicitIP(rules *InterfaceRules, iface string, ip net.IP, ruleType string) error {
	ipStr := ip.String()
	entry := storage.RuleEntry{
		RuleType: ruleType,
		AddedAt:  time.Now(),
	}

	rules.mu.Lock()
	rules.ExplicitIPs[ipStr] = entry
	rules.mu.Unlock()

	if err := d.store.PutExplicitIP(iface, ipStr, entry); err != nil {
		return err
	}

	ifindex := ifaceIndex(iface)
	d.ensureAttached(iface, ifindex)
	if d.xdp != nil && ifindex > 0 {
		return d.xdp.AddExplicitIP(ifindex, ip)
	}

	d.logger.Infof("Added explicit IP %s on %s (%s)", ipStr, iface, ruleType)
	return nil
}

func (d *Daemon) addFQDN(rules *InterfaceRules, iface, fqdn, ruleType string) error {
	entry := storage.FQDNEntry{
		RuleType: ruleType,
		AddedAt:  time.Now(),
	}

	rules.mu.Lock()
	rules.FQDNs[fqdn] = entry
	rules.mu.Unlock()

	if err := d.store.PutFQDN(iface, fqdn, entry); err != nil {
		return err
	}

	d.dnsLoop.AddFQDN(iface, fqdn)

	// Resolve immediately
	go func() {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		defer cancel()

		ips, ttl, err := d.dnsRes.ResolveFQDN(ctx, fqdn)
		if err != nil {
			d.logger.Warnf("Initial resolve for %s failed: %v", fqdn, err)
			return
		}
		d.dnsRes.UpdateCache(fqdn, ips, ttl)
		d.classifyAndApply(iface, fqdn, nil, ips)
	}()

	d.logger.Infof("Added FQDN %s on %s (%s)", fqdn, iface, ruleType)
	return nil
}

// RemoveRule removes an IP or FQDN rule
func (d *Daemon) RemoveRule(iface, target string) error {
	if iface == "" {
		iface = "all"
	}

	rules := d.getOrCreateIface(iface)
	ifindex := ifaceIndex(iface)

	if ip := net.ParseIP(target); ip != nil {
		rules.mu.Lock()
		delete(rules.ExplicitIPs, ip.String())
		rules.mu.Unlock()

		_ = d.store.DeleteExplicitIP(iface, ip.String())

		if d.xdp != nil && ifindex > 0 {
			_ = d.xdp.RemoveExplicitIP(ifindex, ip)
		}
		d.logger.Infof("Removed explicit IP %s from %s", ip, iface)
		return nil
	}

	// FQDN removal
	rules.mu.Lock()
	delete(rules.FQDNs, target)
	delete(rules.SharedFQDNs, target)
	rules.mu.Unlock()

	_ = d.store.DeleteFQDN(iface, target)
	d.dnsLoop.RemoveFQDN(iface, target)
	d.l7Engine.RemoveSharedFQDN(iface, target)

	// Remove tentative IPs for this FQDN
	rules.mu.Lock()
	for ipStr, tent := range rules.TentativeIPs {
		if tent.FQDN == target {
			delete(rules.TentativeIPs, ipStr)
			_ = d.store.DeleteDerivedIP(iface, ipStr)
			if d.xdp != nil && ifindex > 0 {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					_ = d.xdp.RemoveTentativeIP(ifindex, ip)
				}
			}
		}
	}
	rules.mu.Unlock()

	d.logger.Infof("Removed FQDN %s from %s", target, iface)
	return nil
}

// SetMode sets the firewall mode for an interface
func (d *Daemon) SetMode(iface, mode string) error {
	var modeVal uint8
	switch mode {
	case "allow-all":
		modeVal = bpf.ModeAllowAll
	case "block-all":
		modeVal = bpf.ModeBlockAll
	default:
		return fmt.Errorf("unknown mode: %s (use allow-all or block-all)", mode)
	}

	if iface == "" || iface == "all" {
		d.mu.Lock()
		d.globalMode = modeVal
		d.mu.Unlock()

		// Apply to all interfaces
		d.mu.RLock()
		for ifName, rules := range d.ifaces {
			rules.mu.Lock()
			rules.Mode = modeVal
			rules.mu.Unlock()

			idx := ifaceIndex(ifName)
			if d.xdp != nil && idx > 0 {
				_ = d.xdp.SetMode(idx, modeVal)
			}
		}
		d.mu.RUnlock()
	} else {
		rules := d.getOrCreateIface(iface)
		rules.mu.Lock()
		rules.Mode = modeVal
		rules.mu.Unlock()

		idx := ifaceIndex(iface)
		if d.xdp != nil && idx > 0 {
			_ = d.xdp.SetMode(idx, modeVal)
		}
	}

	_ = d.store.SetConfig(storage.KeyGlobalMode, mode)
	d.logger.Infof("Mode set to %s on %s", mode, iface)
	return nil
}

// SyncNow forces immediate DNS re-resolution
func (d *Daemon) SyncNow() {
	d.logger.Infof("Manual sync triggered")
	d.dnsLoop.ForceRefresh(d.ctx)
}

// ─────────────────────────────────────────────
// DNS Change Handler
// ─────────────────────────────────────────────

func (d *Daemon) onDNSChange(ev dns.ChangeEvent) {
	d.classifyAndApply(ev.Iface, ev.FQDN, ev.OldIPs, ev.NewIPs)
}

// classifyAndApply handles IP classification after DNS resolution
func (d *Daemon) classifyAndApply(iface, fqdn string, oldIPs, newIPs []net.IP) {
	rules := d.getOrCreateIface(iface)

	// Build full FQDN→IPs map for classification
	fqdnIPs := make(map[string][]net.IP)
	rules.mu.RLock()
	for f := range rules.FQDNs {
		if cached, ok := d.dnsRes.GetCached(f); ok {
			fqdnIPs[f] = cached
		}
	}
	rules.mu.RUnlock()

	// Also include the newly resolved IPs
	fqdnIPs[fqdn] = newIPs

	classified := dns.ClassifyIPs(fqdnIPs)
	ifindex := ifaceIndex(iface)

	rules.mu.Lock()
	defer rules.mu.Unlock()

	// Handle old IPs → move to tentative (grace period)
	for _, oldIP := range oldIPs {
		ipStr := oldIP.String()

		// If old IP is not in new resolved set, put in tentative with grace period
		if !ipInList(oldIP, newIPs) {
			tent := TentativeEntry{FQDN: fqdn, LastSeen: time.Now()}
			rules.TentativeIPs[ipStr] = tent

			_ = d.store.PutDerivedIP(iface, ipStr, storage.DerivedIPEntry{
				FQDN:     fqdn,
				LastSeen: time.Now(),
				IsShared: false,
			})

			// Keep in eBPF tentative map until grace period expires
			if d.xdp != nil && ifindex > 0 {
				_ = d.xdp.AddTentativeIP(ifindex, oldIP)
			}
			d.logger.Infof("DNS grace period: %s old IP %s kept tentative", fqdn, ipStr)
		}
	}

	// Apply new classification
	for ipStr, fqdnName := range classified.Unique {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Remove from shared if was shared before
		delete(rules.SharedFQDNs, fqdnName)
		if d.xdp != nil && ifindex > 0 {
			_ = d.xdp.RemoveSharedIP(ifindex, ip)
		}
		d.l7Engine.RemoveSharedFQDN(iface, fqdnName)

		// Add to tentative
		rules.TentativeIPs[ipStr] = TentativeEntry{FQDN: fqdnName, LastSeen: time.Now()}

		_ = d.store.PutDerivedIP(iface, ipStr, storage.DerivedIPEntry{
			FQDN:     fqdnName,
			LastSeen: time.Now(),
			IsShared: false,
		})

		if d.xdp != nil && ifindex > 0 {
			_ = d.xdp.AddTentativeIP(ifindex, ip)
		}
	}

	for ipStr, fqdnNames := range classified.Shared {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Remove from tentative
		delete(rules.TentativeIPs, ipStr)
		if d.xdp != nil && ifindex > 0 {
			_ = d.xdp.RemoveTentativeIP(ifindex, ip)
			_ = d.xdp.AddSharedIP(ifindex, ip)
		}

		// Register all sharing FQDNs in L7
		for _, fn := range fqdnNames {
			rules.SharedFQDNs[fn] = struct{}{}
			d.l7Engine.AddSharedFQDN(iface, fn)
		}

		_ = d.store.PutDerivedIP(iface, ipStr, storage.DerivedIPEntry{
			FQDN:     fqdnNames[0],
			LastSeen: time.Now(),
			IsShared: true,
		})
	}
}

// ─────────────────────────────────────────────
// Grace Period Janitor
// ─────────────────────────────────────────────

func (d *Daemon) graceJanitor() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.cleanupExpiredTentative()
		}
	}
}

func (d *Daemon) cleanupExpiredTentative() {
	cutoff := time.Now().Add(-storage.GracePeriod)

	d.mu.RLock()
	ifaces := make([]string, 0, len(d.ifaces))
	for k := range d.ifaces {
		ifaces = append(ifaces, k)
	}
	d.mu.RUnlock()

	for _, iface := range ifaces {
		rules := d.ifaces[iface]
		ifindex := ifaceIndex(iface)

		rules.mu.Lock()
		for ipStr, tent := range rules.TentativeIPs {
			if tent.LastSeen.Before(cutoff) {
				delete(rules.TentativeIPs, ipStr)
				_ = d.store.DeleteDerivedIP(iface, ipStr)

				if d.xdp != nil && ifindex > 0 {
					ip := net.ParseIP(ipStr)
					if ip != nil {
						_ = d.xdp.RemoveTentativeIP(ifindex, ip)
					}
				}
				d.logger.Debugf("Grace period expired: removed tentative IP %s on %s", ipStr, iface)
			}
		}
		rules.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// Ring Buffer Poller (L3 event logging)
// ─────────────────────────────────────────────

func (d *Daemon) pollRingBuffer() {
	if d.xdp == nil {
		return
	}

	maps := d.xdp.GetMaps()
	if maps == nil || maps.Events == nil {
		return
	}

	// Use cilium/ebpf ring buffer reader
	// This is a simplified poller; production uses ebpf.NewReader
	d.logger.Infof("Ring buffer poller started")
}

// ─────────────────────────────────────────────
// Status / Listing
// ─────────────────────────────────────────────

// ListRules returns rules for an interface (or all)
func (d *Daemon) ListRules(iface string) []RuleInfo {
	var result []RuleInfo

	listIface := func(name string, rules *InterfaceRules) {
		rules.mu.RLock()
		defer rules.mu.RUnlock()

		for ip, entry := range rules.ExplicitIPs {
			result = append(result, RuleInfo{
				Target:    ip,
				Interface: name,
				RuleType:  entry.RuleType,
				EntryType: "explicit-ip",
			})
		}
		for fqdn, entry := range rules.FQDNs {
			ri := RuleInfo{
				Target:    fqdn,
				Interface: name,
				RuleType:  entry.RuleType,
				EntryType: "fqdn",
			}
			if ips, ok := d.dnsRes.GetCached(fqdn); ok {
				for _, ip := range ips {
					ri.ResolvedIPs = append(ri.ResolvedIPs, ip.String())
				}
			}
			result = append(result, ri)
		}
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if iface == "" || iface == "all" {
		for name, rules := range d.ifaces {
			listIface(name, rules)
		}
	} else if rules, ok := d.ifaces[iface]; ok {
		listIface(iface, rules)
	}

	return result
}

// GetStatus returns daemon status for CLI
func (d *Daemon) GetStatus() StatusInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var ifaceStatuses []InterfaceStatus
	totalRules := 0

	for name, rules := range d.ifaces {
		rules.mu.RLock()
		explicit := len(rules.ExplicitIPs)
		fqdns := len(rules.FQDNs)
		tentative := len(rules.TentativeIPs)
		shared := len(rules.SharedFQDNs)
		rules.mu.RUnlock()

		totalRules += explicit + fqdns

		ifaceStatuses = append(ifaceStatuses, InterfaceStatus{
			Iface:       name,
			ExplicitIPs: explicit,
			FQDNs:       fqdns,
			TentativeIPs: tentative,
			SharedFQDNs: shared,
			XDPAttached: d.xdp != nil,
		})
	}

	mode := "allow-all"
	if d.globalMode == bpf.ModeBlockAll {
		mode = "block-all"
	}

	return StatusInfo{
		Version:    Version,
		Mode:       mode,
		TotalRules: totalRules,
		Interfaces: ifaceStatuses,
		LogEndpoint: d.hub.GetEndpoint(),
	}
}

// ─────────────────────────────────────────────
// Log Endpoint Management
// ─────────────────────────────────────────────

// SetLogEndpoint updates the external log endpoint
func (d *Daemon) SetLogEndpoint(addr string) error {
	d.hub.SetEndpoint(addr)
	return d.store.SetConfig(storage.KeyLogEndpoint, addr)
}

// GetLogEndpoint returns the current log endpoint
func (d *Daemon) GetLogEndpoint() string {
	return d.hub.GetEndpoint()
}

// Hub returns the logging hub for gRPC stream subscribers
func (d *Daemon) Hub() *logging.Hub {
	return d.hub
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// ensureAttached ensures the TC BPF hook is installed on the interface.
// It is idempotent — AttachXDP is a no-op if already attached.
// Called whenever an interface is first seen (new rule or cold-start load).
func (d *Daemon) ensureAttached(iface string, ifindex int) {
	if d.xdp == nil || ifindex <= 0 || iface == "" || iface == "all" {
		return
	}
	if err := d.xdp.AttachXDP(ifindex, iface); err != nil {
		d.logger.Warnf("TC attach on %s: %v", iface, err)
	}
}

func (d *Daemon) getOrCreateIface(iface string) *InterfaceRules {
	d.mu.Lock()
	defer d.mu.Unlock()

	if rules, ok := d.ifaces[iface]; ok {
		return rules
	}

	rules := &InterfaceRules{
		ExplicitIPs:  make(map[string]storage.RuleEntry),
		FQDNs:        make(map[string]storage.FQDNEntry),
		TentativeIPs: make(map[string]TentativeEntry),
		SharedFQDNs:  make(map[string]struct{}),
		Mode:         d.globalMode,
	}
	d.ifaces[iface] = rules
	return rules
}

func ifaceIndex(iface string) int {
	if iface == "" || iface == "all" {
		return 0
	}
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return 0
	}
	return i.Index
}

func ipInList(ip net.IP, list []net.IP) bool {
	for _, i := range list {
		if ip.Equal(i) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
// Data types for status/list
// ─────────────────────────────────────────────

type RuleInfo struct {
	Target      string
	Interface   string
	RuleType    string
	EntryType   string
	ResolvedIPs []string
	TTL         int64
}

type InterfaceStatus struct {
	Iface        string
	ExplicitIPs  int
	FQDNs        int
	TentativeIPs int
	SharedFQDNs  int
	XDPAttached  bool
}

type StatusInfo struct {
	Version     string
	Mode        string
	TotalRules  int
	Interfaces  []InterfaceStatus
	LogEndpoint string
}