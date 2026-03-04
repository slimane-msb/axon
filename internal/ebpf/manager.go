// Package ebpf manages TC BPF program loading and eBPF map operations
// for the axon per-interface L3 firewall.
//
// Hook choice: TC ingress (clsact qdisc) instead of XDP because:
//   - Works on loopback (lo): XDP generic mode is silently ignored on lo in ≤5.15
//   - Works on WiFi (wlp8s0): WiFi drivers don't implement ndo_bpf (native XDP)
//   - Works everywhere: eth0, veth, bridge ports, virtual NICs
//   - Shared maps with the XDP section (still compiled in .o for wired-native use later)
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	PinPath      = "/sys/fs/bpf/axon"
	ModeAllowAll = uint8(0)
	ModeBlockAll = uint8(1)

	RuleTypeExplicit  = uint8(0)
	RuleTypeTentative = uint8(1)
	RuleTypeSharedL7  = uint8(2)
	RuleTypeModeDrop  = uint8(3)

	ActionPass     = uint8(0)
	ActionDrop     = uint8(1)
	ActionRedirect = uint8(2)
)

// IPKey is the map key: ifindex + IPv4 address
type IPKey struct {
	Ifindex uint32
	IP      uint32 // network byte order
}

// DropEvent mirrors the C struct drop_event
type DropEvent struct {
	Ifindex  uint32
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	RuleType uint8
	Action   uint8
	_        [3]uint8 // padding
}

// FirewallMaps holds references to all pinned eBPF maps
type FirewallMaps struct {
	BlockedIPMap *ebpf.Map
	TentativeMap *ebpf.Map
	SharedIPMap  *ebpf.Map
	ModeMap      *ebpf.Map
	Events       *ebpf.Map
	mu           sync.RWMutex
}

// tcAttachment tracks what we attached to an interface
type tcAttachment struct {
	prog    *ebpf.Program
	ifindex int
}

// XDPManager manages TC BPF programs per interface.
// (Named XDPManager for API compatibility; the hook is now TC ingress.)
type XDPManager struct {
	maps    *FirewallMaps
	tc      map[int]*tcAttachment // ifindex → TC attachment
	mu      sync.Mutex
	objPath string
}

// NewXDPManager creates a manager using the compiled BPF object
func NewXDPManager(bpfObjPath string) (*XDPManager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	if err := os.MkdirAll(PinPath, 0700); err != nil {
		return nil, fmt.Errorf("create pin path: %w", err)
	}

	m := &XDPManager{
		tc:      make(map[int]*tcAttachment),
		objPath: bpfObjPath,
	}

	maps, err := m.loadOrCreateMaps()
	if err != nil {
		return nil, fmt.Errorf("load maps: %w", err)
	}
	m.maps = maps
	return m, nil
}

func (m *XDPManager) loadOrCreateMaps() (*FirewallMaps, error) {
	spec, err := ebpf.LoadCollectionSpec(m.objPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: PinPath},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("new BPF collection: %w", err)
	}

	return &FirewallMaps{
		BlockedIPMap: coll.Maps["blocked_ip_map"],
		TentativeMap: coll.Maps["tentative_map"],
		SharedIPMap:  coll.Maps["shared_ip_map"],
		ModeMap:      coll.Maps["mode_map"],
		Events:       coll.Maps["events"],
	}, nil
}

// AttachXDP attaches the tc_firewall BPF program to an interface via TC ingress.
// Works on lo, wifi, ethernet, and virtual interfaces.
// (Method kept as AttachXDP for API compatibility with daemon.go)
func (m *XDPManager) AttachXDP(ifindex int, ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tc[ifindex]; exists {
		return nil // already attached
	}

	spec, err := ebpf.LoadCollectionSpec(m.objPath)
	if err != nil {
		return fmt.Errorf("load spec for %s: %w", ifname, err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: PinPath},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("collection for %s: %w", ifname, err)
	}

	prog := coll.Programs["tc_firewall"]
	if prog == nil {
		return fmt.Errorf("tc_firewall program not found in BPF object")
	}

	// Step 1: ensure clsact qdisc exists on the interface.
	// clsact is a no-op classless qdisc that provides the ingress/egress
	// hook points for BPF filters without affecting scheduling.
	// Must use netlink.Clsact{} — GenericQdisc with QdiscType "clsact" does
	// not serialize the netlink message correctly and is silently ignored.
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc on %s: %w", ifname, err)
	}

	// Step 2: attach the BPF program as a TC filter on ingress.
	// DirectAction=true means the program's return code IS the TC verdict
	// (TC_ACT_SHOT, TC_ACT_OK) — no classifier needed.
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "axon_tc_firewall",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add TC filter on %s: %w", ifname, err)
	}

	// Pin the program for persistence across daemon restarts
	pinFile := filepath.Join(PinPath, fmt.Sprintf("tc_%s", ifname))
	if err := prog.Pin(pinFile); err != nil {
		// Non-fatal: filter is attached; pinning is best-effort
		_ = err
	}

	m.tc[ifindex] = &tcAttachment{prog: prog, ifindex: ifindex}
	return nil
}

// DetachXDP removes the TC BPF filter and clsact qdisc from an interface
func (m *XDPManager) DetachXDP(ifindex int, ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	att, ok := m.tc[ifindex]
	if !ok {
		return nil
	}

	// Remove the BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
		},
	}
	_ = netlink.FilterDel(filter) // best-effort

	// Remove the clsact qdisc (takes all filters with it)
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	_ = netlink.QdiscDel(qdisc) // best-effort

	pinFile := filepath.Join(PinPath, fmt.Sprintf("tc_%s", ifname))
	_ = os.Remove(pinFile)

	_ = att.prog.Close()
	delete(m.tc, ifindex)
	return nil
}

// ─────────────────────────────────────────────
// Map Operations
// ─────────────────────────────────────────────

func ipToU32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return binary.BigEndian.Uint32(ip), nil
}

func (m *XDPManager) AddExplicitIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	val := uint8(1)
	return m.maps.BlockedIPMap.Put(key, val)
}

func (m *XDPManager) RemoveExplicitIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	return m.maps.BlockedIPMap.Delete(key)
}

func (m *XDPManager) AddTentativeIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	val := uint8(1)
	return m.maps.TentativeMap.Put(key, val)
}

func (m *XDPManager) RemoveTentativeIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	return m.maps.TentativeMap.Delete(key)
}

func (m *XDPManager) AddSharedIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	val := uint8(1)
	return m.maps.SharedIPMap.Put(key, val)
}

func (m *XDPManager) RemoveSharedIP(ifindex int, ip net.IP) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	ipU32, err := ipToU32(ip)
	if err != nil {
		return err
	}
	key := IPKey{Ifindex: uint32(ifindex), IP: ipU32}
	return m.maps.SharedIPMap.Delete(key)
}

func (m *XDPManager) SetMode(ifindex int, mode uint8) error {
	m.maps.mu.Lock()
	defer m.maps.mu.Unlock()
	key := uint32(ifindex)
	return m.maps.ModeMap.Put(key, mode)
}

func (m *XDPManager) GetMode(ifindex int) (uint8, error) {
	m.maps.mu.RLock()
	defer m.maps.mu.RUnlock()
	var val uint8
	if err := m.maps.ModeMap.Lookup(uint32(ifindex), &val); err != nil {
		return ModeAllowAll, nil
	}
	return val, nil
}

func (m *XDPManager) GetMaps() *FirewallMaps {
	return m.maps
}

func (m *XDPManager) CountEntries(ifindex int) (explicit, tentative, shared int) {
	m.maps.mu.RLock()
	defer m.maps.mu.RUnlock()

	iter := m.maps.BlockedIPMap.Iterate()
	var key IPKey
	var val uint8
	for iter.Next(&key, &val) {
		if key.Ifindex == uint32(ifindex) {
			explicit++
		}
	}
	iter = m.maps.TentativeMap.Iterate()
	for iter.Next(&key, &val) {
		if key.Ifindex == uint32(ifindex) {
			tentative++
		}
	}
	iter = m.maps.SharedIPMap.Iterate()
	for iter.Next(&key, &val) {
		if key.Ifindex == uint32(ifindex) {
			shared++
		}
	}
	return
}

func (m *XDPManager) Close() {
    m.mu.Lock()
    // We can't call DetachXDP directly because it tries to lock m.mu again
    // Copy the keys to avoid deadlocking or iterator invalidation
    indices := make([]int, 0, len(m.tc))
    for idx := range m.tc {
        indices = append(indices, idx)
    }
    m.mu.Unlock()

    for _, idx := range indices {
        // You might need a way to look up the ifname or change 
        // DetachXDP to not require it if it's just for the pin path
        _ = m.DetachXDP(idx, "") 
    }
}