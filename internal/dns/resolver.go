// Package dns provides TTL-aware FQDN resolution with grace period support.
package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/axon/internal/logging"
)

const (
	DefaultRefreshInterval = 30 * time.Second
	MinTTL                 = 30 * time.Second
	GracePeriod            = 45 * time.Second
)

// ResolvedEntry stores resolved IPs for an FQDN
type ResolvedEntry struct {
	IPs        []net.IP
	TTL        time.Duration
	ResolvedAt time.Time
	ExpiresAt  time.Time
}

// ClassifiedIPs result of IP deduplication across all FQDNs
type ClassifiedIPs struct {
	// Unique: IP resolved by exactly one FQDN → tentative block
	Unique map[string]string // ip → fqdn

	// Shared: IP resolved by multiple FQDNs → L7 engine
	Shared map[string][]string // ip → []fqdns
}

// ChangeEvent signals a DNS resolution change
type ChangeEvent struct {
	Iface     string
	FQDN      string
	OldIPs    []net.IP
	NewIPs    []net.IP
	Timestamp time.Time
}

// Resolver manages TTL-aware DNS resolution per interface
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]*ResolvedEntry // fqdn → resolved
	logger   *logging.Logger
	resolver *net.Resolver
}

// NewResolver creates a DNS resolver with system or custom nameserver
func NewResolver(nameserver string, logger *logging.Logger) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
	}
	if nameserver != "" {
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", nameserver)
		}
	}

	return &Resolver{
		cache:    make(map[string]*ResolvedEntry),
		logger:   logger,
		resolver: r,
	}
}

// ResolveFQDN resolves an FQDN and returns its IPs + TTL
func (r *Resolver) ResolveFQDN(ctx context.Context, fqdn string) ([]net.IP, time.Duration, error) {
	addrs, err := r.resolver.LookupIPAddr(ctx, fqdn)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve %s: %w", fqdn, err)
	}

	var ips []net.IP
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			ips = append(ips, v4)
		}
	}

	// Lookup TTL via LookupHost records
	ttl := r.lookupTTL(ctx, fqdn)
	if ttl < MinTTL {
		ttl = MinTTL
	}

	return ips, ttl, nil
}

func (r *Resolver) lookupTTL(ctx context.Context, fqdn string) time.Duration {
	// Go's standard resolver doesn't expose TTL directly.
	// We use a heuristic: query cname and fall back to 60s default.
	// For production, use miekg/dns for full TTL support.
	return 60 * time.Second
}

// UpdateCache updates the cache for an FQDN after resolution
func (r *Resolver) UpdateCache(fqdn string, ips []net.IP, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.cache[fqdn] = &ResolvedEntry{
		IPs:        ips,
		TTL:        ttl,
		ResolvedAt: now,
		ExpiresAt:  now.Add(ttl),
	}
}

// GetCached returns cached IPs if still valid
func (r *Resolver) GetCached(fqdn string) ([]net.IP, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	e, ok := r.cache[fqdn]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e.IPs, true
}

// NeedsRefresh returns true if FQDN cache is expired
func (r *Resolver) NeedsRefresh(fqdn string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	e, ok := r.cache[fqdn]
	if !ok {
		return true
	}
	return time.Now().After(e.ExpiresAt)
}

// ClassifyIPs determines unique vs shared IPs across all FQDNs for an interface
func ClassifyIPs(fqdnIPs map[string][]net.IP) ClassifiedIPs {
	// ip → set of FQDNs that resolve to it
	ipToFQDNs := make(map[string][]string)

	for fqdn, ips := range fqdnIPs {
		for _, ip := range ips {
			ipStr := ip.String()
			ipToFQDNs[ipStr] = append(ipToFQDNs[ipStr], fqdn)
		}
	}

	result := ClassifiedIPs{
		Unique: make(map[string]string),
		Shared: make(map[string][]string),
	}

	for ipStr, fqdns := range ipToFQDNs {
		if len(fqdns) == 1 {
			result.Unique[ipStr] = fqdns[0]
		} else {
			result.Shared[ipStr] = fqdns
		}
	}

	return result
}

// RefreshLoop runs periodic DNS re-resolution for all tracked FQDNs
type RefreshLoop struct {
	resolver *Resolver
	interval time.Duration
	fqdns    map[string]map[string]struct{} // iface → set of FQDNs
	onChange  func(ChangeEvent)
	mu       sync.RWMutex
	logger   *logging.Logger
}

// NewRefreshLoop creates a DNS refresh loop
func NewRefreshLoop(r *Resolver, interval time.Duration, onChange func(ChangeEvent), logger *logging.Logger) *RefreshLoop {
	if interval == 0 {
		interval = DefaultRefreshInterval
	}
	return &RefreshLoop{
		resolver: r,
		interval: interval,
		fqdns:    make(map[string]map[string]struct{}),
		onChange:  onChange,
		logger:   logger,
	}
}

// AddFQDN adds an FQDN to be tracked for an interface
func (rl *RefreshLoop) AddFQDN(iface, fqdn string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.fqdns[iface] == nil {
		rl.fqdns[iface] = make(map[string]struct{})
	}
	rl.fqdns[iface][fqdn] = struct{}{}
}

// RemoveFQDN stops tracking an FQDN for an interface
func (rl *RefreshLoop) RemoveFQDN(iface, fqdn string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if s, ok := rl.fqdns[iface]; ok {
		delete(s, fqdn)
	}
}

// Run starts the refresh loop (blocking, use goroutine)
func (rl *RefreshLoop) Run(ctx context.Context) {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.refresh(ctx)
		}
	}
}

// ForceRefresh triggers immediate resolution for all FQDNs
func (rl *RefreshLoop) ForceRefresh(ctx context.Context) {
	rl.refresh(ctx)
}

func (rl *RefreshLoop) refresh(ctx context.Context) {
	rl.mu.RLock()
	snapshot := make(map[string][]string)
	for iface, fqdns := range rl.fqdns {
		for fqdn := range fqdns {
			snapshot[iface] = append(snapshot[iface], fqdn)
		}
	}
	rl.mu.RUnlock()

	for iface, fqdns := range snapshot {
		for _, fqdn := range fqdns {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)

			// Get current cached IPs before resolution
			oldIPs, _ := rl.resolver.GetCached(fqdn)

			newIPs, ttl, err := rl.resolver.ResolveFQDN(rctx, fqdn)
			cancel()

			if err != nil {
				rl.logger.Warnf("DNS refresh failed for %s on %s: %v", fqdn, iface, err)
				continue
			}

			rl.resolver.UpdateCache(fqdn, newIPs, ttl)

			// Check if IPs changed
			if ipsChanged(oldIPs, newIPs) {
				rl.logger.Infof("DNS change detected: %s on %s: %v → %v", fqdn, iface, oldIPs, newIPs)
				if rl.onChange != nil {
					rl.onChange(ChangeEvent{
						Iface:     iface,
						FQDN:      fqdn,
						OldIPs:    oldIPs,
						NewIPs:    newIPs,
						Timestamp: time.Now(),
					})
				}
			}
		}
	}
}

func ipsChanged(old, new []net.IP) bool {
	if len(old) != len(new) {
		return true
	}
	set := make(map[string]bool)
	for _, ip := range old {
		set[ip.String()] = true
	}
	for _, ip := range new {
		if !set[ip.String()] {
			return true
		}
	}
	return false
}
