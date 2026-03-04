// Package storage provides bbolt-backed persistent storage for firewall rules.
// Buckets per interface: ExplicitIPs, FQDNs, DerivedIPs
package storage

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	DBPath           = "/var/lib/axon/db.bolt"
	GracePeriod      = 45 * time.Second
	BucketConfig     = "config"
	KeyLogEndpoint   = "log_endpoint"
	KeyGlobalMode    = "global_mode"
)

// DerivedIPEntry stores metadata for FQDN-resolved IPs
type DerivedIPEntry struct {
	FQDN     string    `json:"fqdn"`
	LastSeen time.Time `json:"last_seen"`
	TTL      int64     `json:"ttl_seconds"`
	IsShared bool      `json:"is_shared"`
}

// FQDNEntry stores metadata for tracked FQDNs
type FQDNEntry struct {
	RuleType   string    `json:"rule_type"` // "block" | "allow"
	AddedAt    time.Time `json:"added_at"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// RuleEntry stores an explicit IP rule
type RuleEntry struct {
	RuleType string    `json:"rule_type"` // "block" | "allow"
	AddedAt  time.Time `json:"added_at"`
}

// Store wraps bbolt for firewall persistence
type Store struct {
	db *bolt.DB
}

// Open opens or creates the bbolt database
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close closes the database
func (s *Store) Close() error {
	return s.db.Close()
}

// ─────────────────────────────────────────────
// Bucket helpers
// ─────────────────────────────────────────────

func explicitBucket(iface string) []byte {
	return []byte(fmt.Sprintf("iface.%s.explicit", iface))
}

func fqdnBucket(iface string) []byte {
	return []byte(fmt.Sprintf("iface.%s.fqdns", iface))
}

func derivedBucket(iface string) []byte {
	return []byte(fmt.Sprintf("iface.%s.derived", iface))
}

// InitInterface ensures buckets exist for an interface
func (s *Store) InitInterface(iface string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			explicitBucket(iface),
			fqdnBucket(iface),
			derivedBucket(iface),
			[]byte(BucketConfig),
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// ─────────────────────────────────────────────
// Explicit IPs
// ─────────────────────────────────────────────

func (s *Store) PutExplicitIP(iface, ip string, entry RuleEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(explicitBucket(iface))
		if b == nil {
			return fmt.Errorf("bucket not found for iface %s", iface)
		}
		return b.Put([]byte(ip), data)
	})
}

func (s *Store) DeleteExplicitIP(iface, ip string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(explicitBucket(iface))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(ip))
	})
}

func (s *Store) GetExplicitIPs(iface string) (map[string]RuleEntry, error) {
	result := make(map[string]RuleEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(explicitBucket(iface))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var entry RuleEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			result[string(k)] = entry
			return nil
		})
	})
	return result, err
}

// ─────────────────────────────────────────────
// FQDNs
// ─────────────────────────────────────────────

func (s *Store) PutFQDN(iface, fqdn string, entry FQDNEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(fqdnBucket(iface))
		if b == nil {
			return fmt.Errorf("bucket not found for iface %s", iface)
		}
		return b.Put([]byte(fqdn), data)
	})
}

func (s *Store) DeleteFQDN(iface, fqdn string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(fqdnBucket(iface))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(fqdn))
	})
}

func (s *Store) GetFQDNs(iface string) (map[string]FQDNEntry, error) {
	result := make(map[string]FQDNEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(fqdnBucket(iface))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var entry FQDNEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			result[string(k)] = entry
			return nil
		})
	})
	return result, err
}

// ─────────────────────────────────────────────
// Derived IPs (FQDN-resolved)
// ─────────────────────────────────────────────

func (s *Store) PutDerivedIP(iface, ip string, entry DerivedIPEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(derivedBucket(iface))
		if b == nil {
			return fmt.Errorf("bucket not found for iface %s", iface)
		}
		return b.Put([]byte(ip), data)
	})
}

func (s *Store) DeleteDerivedIP(iface, ip string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(derivedBucket(iface))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(ip))
	})
}

func (s *Store) GetDerivedIPs(iface string) (map[string]DerivedIPEntry, error) {
	result := make(map[string]DerivedIPEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(derivedBucket(iface))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var entry DerivedIPEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			result[string(k)] = entry
			return nil
		})
	})
	return result, err
}

// GetExpiredTentativeIPs returns derived IPs past the grace period
func (s *Store) GetExpiredTentativeIPs(iface string) ([]string, error) {
	var expired []string
	cutoff := time.Now().Add(-GracePeriod)

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(derivedBucket(iface))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var entry DerivedIPEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			if entry.LastSeen.Before(cutoff) {
				expired = append(expired, string(k))
			}
			return nil
		})
	})
	return expired, err
}

// UpdateDerivedIPLastSeen refreshes the last_seen timestamp
func (s *Store) UpdateDerivedIPLastSeen(iface, ip string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(derivedBucket(iface))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		var entry DerivedIPEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return err
		}
		entry.LastSeen = time.Now()
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), data)
	})
}

// ─────────────────────────────────────────────
// Config (global)
// ─────────────────────────────────────────────

func (s *Store) SetConfig(key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(BucketConfig))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), []byte(value))
	})
}

func (s *Store) GetConfig(key string) (string, error) {
	var val string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketConfig))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(key))
		if v != nil {
			val = string(v)
		}
		return nil
	})
	return val, err
}

// ListInterfaces returns all interface names that have bucket data
func (s *Store) ListInterfaces() ([]string, error) {
	seen := make(map[string]bool)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			n := string(name)
			// Parse "iface.<name>.explicit" pattern
			var iface string
			if _, err := fmt.Sscanf(n, "iface.%s", &iface); err == nil {
				// Extract just interface name from "eth0.explicit"
				for i, c := range iface {
					if c == '.' {
						seen[iface[:i]] = true
						break
					}
				}
			}
			return nil
		})
	})
	result := make([]string, 0, len(seen))
	for k := range seen {
		result = append(result, k)
	}
	return result, err
}
