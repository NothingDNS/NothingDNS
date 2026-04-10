package dnssec

import (
	"context"
	"sync"
	"time"
)

// KeyState represents the lifecycle state of a DNSSEC signing key per RFC 7583.
type KeyState int

const (
	// KeyStateCreated means the key exists but is not published in the zone.
	KeyStateCreated KeyState = iota
	// KeyStatePublished means the DNSKEY is in the zone but not yet used for signing.
	KeyStatePublished
	// KeyStateActive means the key is used for signing.
	KeyStateActive
	// KeyStateRetired means the key is no longer used for signing but the DNSKEY
	// remains in the zone so existing signatures can be validated.
	KeyStateRetired
	// KeyStateDead means the key has been removed from the zone.
	KeyStateDead
)

func (s KeyState) String() string {
	switch s {
	case KeyStateCreated:
		return "Created"
	case KeyStatePublished:
		return "Published"
	case KeyStateActive:
		return "Active"
	case KeyStateRetired:
		return "Retired"
	case KeyStateDead:
		return "Dead"
	default:
		return "Unknown"
	}
}

// KeyTiming holds the RFC 7583 timing metadata for a signing key.
// All fields are optional; zero value means "not scheduled".
type KeyTiming struct {
	// Created is when the key was generated.
	Created time.Time
	// Publish is when the DNSKEY should appear in the zone.
	Publish time.Time
	// Active is when the key should start being used for signing.
	Active time.Time
	// Retire is when the key should stop being used for signing.
	// The DNSKEY remains published until Remove.
	Retire time.Time
	// Remove is when the DNSKEY should be removed from the zone.
	Remove time.Time
}

// RolloverConfig configures automatic key rollover behavior per RFC 7583.
type RolloverConfig struct {
	// Enabled enables automatic key rollover.
	Enabled bool

	// ZSKLifetime is how long a ZSK remains active before rollover.
	// Typical: 30-90 days. 0 disables ZSK rollover.
	ZSKLifetime time.Duration

	// KSKLifetime is how long a KSK remains active before rollover.
	// Typical: 1-2 years. 0 disables KSK rollover.
	KSKLifetime time.Duration

	// PublishSafety is how long a new key is published before becoming active.
	// This ensures resolvers have cached the new DNSKEY before signing starts.
	// Typical: 1 hour to 1 day.
	PublishSafety time.Duration

	// RetireSafety is how long a retired key stays published after its
	// replacement becomes active, ensuring old signatures can be validated.
	// Typical: signature validity period + clock skew.
	RetireSafety time.Duration

	// Algorithm is the DNSSEC algorithm to use for generated keys.
	// Default: 13 (ECDSAP256SHA256).
	Algorithm uint8

	// CheckInterval is how often the scheduler checks for rollover actions.
	// Default: 1 hour.
	CheckInterval time.Duration
}

// DefaultRolloverConfig returns sensible rollover defaults.
func DefaultRolloverConfig() RolloverConfig {
	return RolloverConfig{
		Enabled:       false,
		ZSKLifetime:   90 * 24 * time.Hour,  // 90 days
		KSKLifetime:   365 * 24 * time.Hour, // ~1 year
		PublishSafety: 24 * time.Hour,       // 1 day
		RetireSafety:  30 * 24 * time.Hour,  // 30 days (matches SignatureValidity)
		Algorithm:     13,                   // ECDSAP256SHA256
		CheckInterval: 1 * time.Hour,
	}
}

// RolloverScheduler manages automatic key rollover per RFC 7583.
type RolloverScheduler struct {
	signer *Signer
	config RolloverConfig
	logger func(string, ...interface{})

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRolloverScheduler creates a new rollover scheduler.
// The logger function is optional; if nil, logging is skipped.
func NewRolloverScheduler(signer *Signer, config RolloverConfig, logger func(string, ...interface{})) *RolloverScheduler {
	if logger == nil {
		logger = func(string, ...interface{}) {}
	}
	return &RolloverScheduler{
		signer: signer,
		config: config,
		logger: logger,
	}
}

// Start begins the rollover scheduler loop.
func (rs *RolloverScheduler) Start() {
	if !rs.config.Enabled {
		return
	}

	rs.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	rs.cancel = cancel
	rs.mu.Unlock()

	rs.wg.Add(1)
	go rs.run(ctx)
	rs.logger("dnssec rollover: scheduler started (zsk=%s, ksk=%s)", rs.config.ZSKLifetime, rs.config.KSKLifetime)
}

// Stop shuts down the rollover scheduler.
func (rs *RolloverScheduler) Stop() {
	rs.mu.Lock()
	cancel := rs.cancel
	rs.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	rs.wg.Wait()
}

// run is the main scheduling loop.
func (rs *RolloverScheduler) run(ctx context.Context) {
	defer rs.wg.Done()

	// Do initial check
	rs.check()

	interval := rs.config.CheckInterval
	if interval < time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			rs.logger("dnssec rollover: scheduler stopped")
			return
		case <-ticker.C:
			rs.check()
		}
	}
}

// check evaluates all keys and performs state transitions as needed.
func (rs *RolloverScheduler) check() {
	now := time.Now()

	keys := rs.signer.GetKeys()
	for _, key := range keys {
		if key.Timing == nil {
			continue
		}
		rs.transitionKey(key, now)
	}

	// Check if we need to generate new keys
	rs.maybeRolloverZSK(now)
	rs.maybeRolloverKSK(now)
}

// transitionKey moves a key through its lifecycle based on timing.
func (rs *RolloverScheduler) transitionKey(key *SigningKey, now time.Time) {
	timing := key.Timing

	switch key.State {
	case KeyStateCreated:
		if !timing.Publish.IsZero() && !now.Before(timing.Publish) {
			rs.signer.SetKeyState(key.KeyTag, KeyStatePublished)
			rs.logger("dnssec rollover: key %d transitioned Created -> Published", key.KeyTag)
		}

	case KeyStatePublished:
		if !timing.Active.IsZero() && !now.Before(timing.Active) {
			rs.signer.SetKeyState(key.KeyTag, KeyStateActive)
			rs.logger("dnssec rollover: key %d transitioned Published -> Active", key.KeyTag)
		}

	case KeyStateActive:
		if !timing.Retire.IsZero() && !now.Before(timing.Retire) {
			rs.signer.SetKeyState(key.KeyTag, KeyStateRetired)
			rs.logger("dnssec rollover: key %d transitioned Active -> Retired", key.KeyTag)
		}

	case KeyStateRetired:
		if !timing.Remove.IsZero() && !now.Before(timing.Remove) {
			rs.signer.SetKeyState(key.KeyTag, KeyStateDead)
			rs.signer.RemoveKey(key.KeyTag)
			rs.logger("dnssec rollover: key %d transitioned Retired -> Dead (removed)", key.KeyTag)
		}
	}
}

// maybeRolloverZSK checks if a new ZSK needs to be generated because
// the current active ZSK is approaching its retirement time.
func (rs *RolloverScheduler) maybeRolloverZSK(now time.Time) {
	if rs.config.ZSKLifetime == 0 {
		return
	}

	zsks := rs.signer.GetActiveZSKs()
	needsRollover := len(zsks) == 0

	for _, zsk := range zsks {
		if zsk.Timing != nil && !zsk.Timing.Retire.IsZero() {
			timeUntilRetire := zsk.Timing.Retire.Sub(now)
			if timeUntilRetire <= rs.config.PublishSafety {
				needsRollover = true
				break
			}
		}
	}

	if needsRollover {
		rs.generateRolloverZSK(now)
	}
}

// maybeRolloverKSK checks if a new KSK needs to be generated.
func (rs *RolloverScheduler) maybeRolloverKSK(now time.Time) {
	if rs.config.KSKLifetime == 0 {
		return
	}

	ksks := rs.signer.GetActiveKSKs()
	needsRollover := len(ksks) == 0

	for _, ksk := range ksks {
		if ksk.Timing != nil && !ksk.Timing.Retire.IsZero() {
			timeUntilRetire := ksk.Timing.Retire.Sub(now)
			if timeUntilRetire <= rs.config.PublishSafety {
				needsRollover = true
				break
			}
		}
	}

	if needsRollover {
		rs.generateRolloverKSK(now)
	}
}

// generateRolloverZSK creates a new ZSK with proper timing and schedules
// the old active ZSK for retirement.
func (rs *RolloverScheduler) generateRolloverZSK(now time.Time) {
	algo := rs.config.Algorithm
	if algo == 0 {
		algo = 13 // ECDSAP256SHA256
	}

	key, err := rs.signer.GenerateKeyPair(algo, false)
	if err != nil {
		rs.logger("dnssec rollover: failed to generate ZSK: %v", err)
		return
	}

	publishTime := now
	activeTime := now.Add(rs.config.PublishSafety)
	retireTime := activeTime.Add(rs.config.ZSKLifetime)
	removeTime := retireTime.Add(rs.config.RetireSafety)

	rs.signer.SetKeyState(key.KeyTag, KeyStatePublished)
	rs.signer.SetKeyTiming(key.KeyTag, &KeyTiming{
		Created: now,
		Publish: publishTime,
		Active:  activeTime,
		Retire:  retireTime,
		Remove:  removeTime,
	})

	rs.logger("dnssec rollover: new ZSK %d generated (active=%s, retire=%s)",
		key.KeyTag, activeTime.Format(time.DateOnly), retireTime.Format(time.DateOnly))

	// Schedule retirement of current active ZSKs
	zsks := rs.signer.GetActiveZSKs()
	for _, zsk := range zsks {
		if zsk.KeyTag != key.KeyTag && zsk.Timing != nil && zsk.Timing.Retire.IsZero() {
			updatedTiming := *zsk.Timing // copy
			updatedTiming.Retire = activeTime
			updatedTiming.Remove = activeTime.Add(rs.config.RetireSafety)
			rs.signer.SetKeyTiming(zsk.KeyTag, &updatedTiming)
			rs.logger("dnssec rollover: ZSK %d scheduled for retirement at %s",
				zsk.KeyTag, activeTime.Format(time.DateOnly))
		}
	}
}

// generateRolloverKSK creates a new KSK with proper timing.
func (rs *RolloverScheduler) generateRolloverKSK(now time.Time) {
	algo := rs.config.Algorithm
	if algo == 0 {
		algo = 13
	}

	key, err := rs.signer.GenerateKeyPair(algo, true)
	if err != nil {
		rs.logger("dnssec rollover: failed to generate KSK: %v", err)
		return
	}

	publishTime := now
	activeTime := now.Add(rs.config.PublishSafety)
	retireTime := activeTime.Add(rs.config.KSKLifetime)
	removeTime := retireTime.Add(rs.config.RetireSafety)

	rs.signer.SetKeyState(key.KeyTag, KeyStatePublished)
	rs.signer.SetKeyTiming(key.KeyTag, &KeyTiming{
		Created: now,
		Publish: publishTime,
		Active:  activeTime,
		Retire:  retireTime,
		Remove:  removeTime,
	})

	rs.logger("dnssec rollover: new KSK %d generated (active=%s, retire=%s)",
		key.KeyTag, activeTime.Format(time.DateOnly), retireTime.Format(time.DateOnly))

	// Schedule retirement of current active KSKs
	ksks := rs.signer.GetActiveKSKs()
	for _, ksk := range ksks {
		if ksk.KeyTag != key.KeyTag && ksk.Timing != nil && ksk.Timing.Retire.IsZero() {
			updatedTiming := *ksk.Timing // copy
			updatedTiming.Retire = activeTime
			updatedTiming.Remove = activeTime.Add(rs.config.RetireSafety)
			rs.signer.SetKeyTiming(ksk.KeyTag, &updatedTiming)
			rs.logger("dnssec rollover: KSK %d scheduled for retirement at %s",
				ksk.KeyTag, activeTime.Format(time.DateOnly))
		}
	}
}
