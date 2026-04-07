// Package dnssec — Trust Anchor Auto-Update (RFC 5011)
//
// This module implements RFC 5011 "Trust Anchor Management for DNS Security".
// When a trust anchor (DS or DNSKEY) is added at a child zone, the resolver
// can automatically add it to its trust anchor store after a "hold-down" period.
//
// Key concepts:
// - When we see a new DNSKEY at a zone where we have a trust anchor via its parent,
//   we add it to a "pending" list
// - The key must be seen continuously for a minimum period (30 days default)
// - If the key disappears during this period, it's discarded
// - After successful hold-down, the key becomes a trust anchor
//
// This enables automatic key rollovers without manual intervention.
package dnssec

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 5011 trust anchor states
const (
	// TrustAnchorStateUnseen - key has not been observed
	TrustAnchorStateUnseen TrustAnchorState = iota
	// TrustAnchorStatePending - key observed, in hold-down period
	TrustAnchorStatePending
	// TrustAnchorStateTrusted - key passed hold-down, added as trust anchor
	TrustAnchorStateTrusted
	// TrustAnchorStateRemoved - key was removed during pending
	TrustAnchorStateRemoved
)

type TrustAnchorState int

func (s TrustAnchorState) String() string {
	switch s {
	case TrustAnchorStateUnseen:
		return "Unseen"
	case TrustAnchorStatePending:
		return "Pending"
	case TrustAnchorStateTrusted:
		return "Trusted"
	case TrustAnchorStateRemoved:
		return "Removed"
	default:
		return "Unknown"
	}
}

// PendingTrustAnchor tracks a key that has been observed but not yet trusted.
// Per RFC 5011, the key must be seen continuously for the hold-down period
// before it can be added to the trust anchor set.
type PendingTrustAnchor struct {
	Zone       string
	DNSKEY     *protocol.RDataDNSKEY
	KeyTag     uint16
	Algorithm  uint8
	Digest     []byte // DS digest for verification

	// State machine
	State TrustAnchorState

	// Timing (RFC 5011)
	FirstSeen     time.Time // When we first observed this key
	LastSeen      time.Time // Last time we saw this key
	MinimumTrust  time.Time // earliest time this key could become trusted (FirstSeen + HoldDown)
	LastSuccessful time.Time // Last time we successfully validated with this key

	// Trust Anchor ID for the DS record that introduced this key
	TrustAnchorID string // Format: "zone:keytag:algo:digest"
}

// RFC5011Config configures RFC 5011 automatic trust anchor updates.
type RFC5011Config struct {
	// Enabled enables RFC 5011 trust anchor auto-update.
	Enabled bool

	// HoldDownDuration is how long a new key must be continuously observed
	// before being added as a trust anchor. RFC 5011 recommends >= 30 days.
	// Default: 30 days.
	HoldDownDuration time.Duration

	// AddHoldDownDuration is how long a key must remain after removal
	// before being deleted. RFC 5011 recommends >= 30 days.
	// Default: 30 days.
	AddHoldDownDuration time.Duration

	// TrustAnchorStore is the store to update when keys become trusted.
	TrustAnchorStore *TrustAnchorStore

	// CheckInterval determines how often to check for key changes.
	// Default: 1 hour.
	CheckInterval time.Duration

	// Maximum number of pending keys per zone.
	MaxPendingKeys int

	// Key tag of the introducing trust anchor (the DS record's key tag).
	IntroducingKeyTag uint16
}

// DefaultRFC5011Config returns sensible defaults for RFC 5011.
func DefaultRFC5011Config() RFC5011Config {
	return RFC5011Config{
		Enabled:            false, // Must be explicitly enabled
		HoldDownDuration:   30 * 24 * time.Hour, // 30 days per RFC 5011
		AddHoldDownDuration: 30 * 24 * time.Hour, // 30 days per RFC 5011
		CheckInterval:      1 * time.Hour,
		MaxPendingKeys:     10,
	}
}

// RFC5011Manager manages automatic trust anchor updates per RFC 5011.
type RFC5011Manager struct {
	config RFC5011Config
	logger func(string, ...any)

	mu       sync.Mutex
	pending  map[string]*PendingTrustAnchor // key: "zone:keytag:algo"
	trusts   map[string]*PendingTrustAnchor // key: "zone:keytag:algo", keys that passed hold-down
	removed  map[string]*PendingTrustAnchor // key: "zone:keytag:algo", keys pending deletion

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRFC5011Manager creates a new RFC 5011 trust anchor manager.
func NewRFC5011Manager(config RFC5011Config, logger func(string, ...any)) *RFC5011Manager {
	if logger == nil {
		logger = func(string, ...any) {}
	}
	if config.TrustAnchorStore == nil {
		config.TrustAnchorStore = NewTrustAnchorStore()
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = 1 * time.Hour
	}
	if config.HoldDownDuration == 0 {
		config.HoldDownDuration = 30 * 24 * time.Hour
	}
	if config.AddHoldDownDuration == 0 {
		config.AddHoldDownDuration = 30 * 24 * time.Hour
	}
	if config.MaxPendingKeys == 0 {
		config.MaxPendingKeys = 10
	}

	m := &RFC5011Manager{
		config:  config,
		logger:  logger,
		pending: make(map[string]*PendingTrustAnchor),
		trusts:  make(map[string]*PendingTrustAnchor),
		removed: make(map[string]*PendingTrustAnchor),
	}

	return m
}

// pendingKey creates a unique key for pending tracking.
func pendingKey(zone string, keyTag uint16, algo uint8) string {
	return fmt.Sprintf("%s:%d:%d", zone, keyTag, algo)
}

// Start begins the RFC 5011 manager background processing.
func (m *RFC5011Manager) Start() {
	if !m.config.Enabled {
		m.logger("dnssec rfc5011: disabled")
		return
	}

	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.wg.Add(1)
	go m.run()
	m.logger("dnssec rfc5011: started (hold-down=%v)", m.config.HoldDownDuration)
}

// Stop shuts down the RFC 5011 manager.
func (m *RFC5011Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.logger("dnssec rfc5011: stopped")
}

// run is the main processing loop.
func (m *RFC5011Manager) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			m.logger("dnssec rfc5011: manager stopped")
			return
		case <-ticker.C:
			m.processUpdates()
		}
	}
}

// processUpdates evaluates all pending keys and performs state transitions.
func (m *RFC5011Manager) processUpdates() {
	now := time.Now()

	// Process pending keys - check if they've passed hold-down
	for key, pta := range m.pendingKeys() {
		switch pta.State {
		case TrustAnchorStatePending:
			if now.After(pta.MinimumTrust) {
				// Hold-down period passed - add as trust anchor
				if err := m.promoteToTrustAnchor(pta); err != nil {
					m.logger("dnssec rfc5011: failed to promote key %s: %v", key, err)
				} else {
					m.logger("dnssec rfc5011: key %s passed hold-down, promoted to trust anchor", key)
				}
			}

		case TrustAnchorStateRemoved:
			// Check if remove hold-down has passed
			removeDeadline := pta.LastSeen.Add(m.config.AddHoldDownDuration)
			if now.After(removeDeadline) {
				m.logger("dnssec rfc5011: key %s remove hold-down passed, finalizing removal", key)
				delete(m.removed, key)
			}
		}
	}

	// Update last-seen times for keys we're actively tracking
	// This happens when ProcessDNSKEYResponse is called
}

// pendingKeys returns a snapshot of pending keys.
func (m *RFC5011Manager) pendingKeys() map[string]*PendingTrustAnchor {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]*PendingTrustAnchor, len(m.pending))
	for k, v := range m.pending {
		result[k] = v
	}
	return result
}

// ProcessDNSKEYResponse processes a DNSKEY response from a zone where we have
// a trust anchor (via DS record). This is called during DNSSEC validation
// when we receive a DNSKEY set from a delegated zone.
//
// RFC 5011 Section 2.1: when we receive a DNSKEY set, we compare it against
// our pending and trusted keys, updating our tracking accordingly.
func (m *RFC5011Manager) ProcessDNSKEYResponse(zone string, dnskeys []*protocol.RDataDNSKEY) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Time{}

	// Build set of key tags in this response
	seenTags := make(map[uint16]bool)
	for _, dk := range dnskeys {
		kt := protocol.CalculateKeyTag(dk.Flags, dk.Algorithm, dk.PublicKey)
		seenTags[kt] = true
	}

	// Check pending keys - mark as removed if not in response
	for key, pta := range m.pending {
		if pta.Zone != zone {
			continue
		}

		if seenTags[pta.KeyTag] {
			// Key is present - update LastSeen
			pta.LastSeen = now
			m.logger("dnssec rfc5011: key %s still present at %s", key, zone)
		} else {
			// Key is missing - mark as removed
			if pta.State == TrustAnchorStatePending {
				pta.State = TrustAnchorStateRemoved
				pta.LastSeen = now
				delete(m.pending, key)
				m.removed[key] = pta
				m.logger("dnssec rfc5011: key %s removed from %s, entering remove hold-down", key, zone)
			}
		}
	}

	// Check trusted keys - they should also be present
	for key, pta := range m.trusts {
		if pta.Zone != zone {
			continue
		}

		if seenTags[pta.KeyTag] {
			pta.LastSeen = now
		} else {
			// Trusted key is missing - this is concerning but handled differently
			m.logger("dnssec rfc5011: WARNING: trusted key %s missing from %s", key, zone)
		}
	}

	// RFC 5011 Section 2.4: Check for new keys not in our pending/trusted/removed sets
	// These are potential new keys that need to be tracked
	for _, dk := range dnskeys {
		kt := protocol.CalculateKeyTag(dk.Flags, dk.Algorithm, dk.PublicKey)
		key := pendingKey(zone, kt, dk.Algorithm)

		// Skip if we already know about this key
		if _, exists := m.pending[key]; exists {
			continue
		}
		if _, exists := m.trusts[key]; exists {
			continue
		}
		if _, exists := m.removed[key]; exists {
			continue
		}

		// This is a new key - check if it's a SEP (KSK)
		if dk.Flags&protocol.DNSKEYFlagSEP == 0 {
			// Not a KSK - skip. Only track KSKs for trust anchor updates.
			continue
		}

		// Add to pending
		if len(m.pending) >= m.config.MaxPendingKeys {
			m.logger("dnssec rfc5011: too many pending keys for %s, skipping new key", zone)
			continue
		}

		pta := &PendingTrustAnchor{
			Zone:           zone,
			DNSKEY:         dk,
			KeyTag:         kt,
			Algorithm:      dk.Algorithm,
			State:          TrustAnchorStatePending,
			FirstSeen:      now,
			LastSeen:       now,
			MinimumTrust:   now.Add(m.config.HoldDownDuration),
			LastSuccessful: now,
			TrustAnchorID:  key,
		}

		m.pending[key] = pta
		m.logger("dnssec rfc5011: new KSK observed at %s, keytag=%d algo=%d, entering hold-down until %v",
			zone, kt, dk.Algorithm, pta.MinimumTrust.Format(time.RFC3339))
	}
}

// promoteToTrustAnchor moves a pending key to the trusted set and adds it
// as an actual trust anchor.
func (m *RFC5011Manager) promoteToTrustAnchor(pta *PendingTrustAnchor) error {
	// Create the trust anchor from the pending key
	anchor := &TrustAnchor{
		Zone:       pta.Zone,
		KeyTag:     pta.KeyTag,
		Algorithm:  pta.Algorithm,
		DigestType: 2, // SHA-256 by default
		Digest:     pta.Digest,
		PublicKey:  pta.DNSKEY.PublicKey,
		ValidFrom:  time.Now(),
	}

	// Add to the trust anchor store
	m.config.TrustAnchorStore.AddAnchor(anchor)

	// Move from pending to trusted
	delete(m.pending, pta.TrustAnchorID)
	pta.State = TrustAnchorStateTrusted
	m.trusts[pta.TrustAnchorID] = pta

	return nil
}

// GetTrustAnchorsForZone returns all trusted anchors for a zone.
func (m *RFC5011Manager) GetTrustAnchorsForZone(zone string) []*TrustAnchor {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*TrustAnchor
	for _, pta := range m.trusts {
		if pta.Zone == zone {
			result = append(result, &TrustAnchor{
				Zone:       pta.Zone,
				KeyTag:     pta.KeyTag,
				Algorithm:  pta.Algorithm,
				PublicKey:  pta.DNSKEY.PublicKey,
				Digest:     pta.Digest,
				ValidFrom:  pta.FirstSeen,
			})
		}
	}
	return result
}

// GetPendingKeys returns all pending keys (for debugging/admin).
func (m *RFC5011Manager) GetPendingKeys() []*PendingTrustAnchor {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*PendingTrustAnchor, 0, len(m.pending))
	for _, pta := range m.pending {
		result = append(result, pta)
	}
	return result
}

// GetRemovedKeys returns all keys in remove hold-down (for debugging/admin).
func (m *RFC5011Manager) GetRemovedKeys() []*PendingTrustAnchor {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*PendingTrustAnchor, 0, len(m.removed))
	for _, pta := range m.removed {
		result = append(result, pta)
	}
	return result
}

// Stats returns current RFC 5011 statistics.
type RFC5011Stats struct {
	PendingKeys int
	TrustedKeys int
	RemovedKeys int
}

func (m *RFC5011Manager) Stats() RFC5011Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	return RFC5011Stats{
		PendingKeys: len(m.pending),
		TrustedKeys: len(m.trusts),
		RemovedKeys: len(m.removed),
	}
}
