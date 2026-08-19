package dnssec

import (
	"testing"
	"time"
)

func TestKeyStateString(t *testing.T) {
	tests := []struct {
		state KeyState
		want  string
	}{
		{KeyStateCreated, "Created"},
		{KeyStatePublished, "Published"},
		{KeyStateActive, "Active"},
		{KeyStateRetired, "Retired"},
		{KeyStateDead, "Dead"},
		{KeyState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("KeyState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestDefaultRolloverConfig(t *testing.T) {
	cfg := DefaultRolloverConfig()
	if cfg.Enabled {
		t.Error("default rollover should be disabled")
	}
	if cfg.ZSKLifetime != 90*24*time.Hour {
		t.Errorf("ZSKLifetime = %v, want 90 days", cfg.ZSKLifetime)
	}
	if cfg.KSKLifetime != 365*24*time.Hour {
		t.Errorf("KSKLifetime = %v, want ~1 year", cfg.KSKLifetime)
	}
	if cfg.Algorithm != 13 {
		t.Errorf("Algorithm = %d, want 13", cfg.Algorithm)
	}
}

func TestSigningKeyStateTransitions(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())

	// Generate a ZSK
	key, err := signer.GenerateKeyPair(13, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Without timing, key should be considered active (backward compatible)
	active := signer.GetActiveZSKs()
	if len(active) != 1 || active[0].KeyTag != key.KeyTag {
		t.Errorf("GetActiveZSKs() = %d keys, want 1 active ZSK", len(active))
	}

	// Set timing with state transitions
	now := time.Now()
	signer.SetKeyTiming(key.KeyTag, &KeyTiming{
		Created: now.Add(-2 * time.Hour),
		Publish: now.Add(-1 * time.Hour),
		Active:  now.Add(1 * time.Hour), // Not yet active
		Retire:  now.Add(90 * 24 * time.Hour),
		Remove:  now.Add(120 * 24 * time.Hour),
	})
	signer.SetKeyState(key.KeyTag, KeyStatePublished)

	// Key is Published, not Active — should not appear in GetActiveZSKs
	active = signer.GetActiveZSKs()
	if len(active) != 0 {
		t.Errorf("GetActiveZSKs() = %d keys after setting state to Published, want 0", len(active))
	}

	// Transition to Active
	signer.SetKeyState(key.KeyTag, KeyStateActive)
	active = signer.GetActiveZSKs()
	if len(active) != 1 {
		t.Errorf("GetActiveZSKs() = %d keys after setting state to Active, want 1", len(active))
	}

	// Transition to Retired
	signer.SetKeyState(key.KeyTag, KeyStateRetired)
	active = signer.GetActiveZSKs()
	if len(active) != 0 {
		t.Errorf("GetActiveZSKs() = %d keys after setting state to Retired, want 0", len(active))
	}

	// Verify key still exists in signer
	allKeys := signer.GetKeys()
	found := false
	for _, k := range allKeys {
		if k.KeyTag == key.KeyTag {
			found = true
			break
		}
	}
	if !found {
		t.Error("retired key should still exist in signer")
	}

	// Transition to Dead — key gets removed
	signer.SetKeyState(key.KeyTag, KeyStateDead)
	signer.RemoveKey(key.KeyTag)
	allKeys = signer.GetKeys()
	for _, k := range allKeys {
		if k.KeyTag == key.KeyTag {
			t.Error("dead key should have been removed from signer")
		}
	}
}

func TestRolloverSchedulerStartStop(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())

	// Generate initial keys
	_, err := signer.GenerateKeyPair(13, true) // KSK
	if err != nil {
		t.Fatalf("GenerateKeyPair KSK: %v", err)
	}
	_, err = signer.GenerateKeyPair(13, false) // ZSK
	if err != nil {
		t.Fatalf("GenerateKeyPair ZSK: %v", err)
	}

	logCalled := false
	cfg := RolloverConfig{
		Enabled:       true,
		ZSKLifetime:   90 * 24 * time.Hour,
		KSKLifetime:   365 * 24 * time.Hour,
		PublishSafety: 24 * time.Hour,
		RetireSafety:  30 * 24 * time.Hour,
		Algorithm:     13,
		CheckInterval: 1 * time.Hour,
	}

	scheduler := NewRolloverScheduler(signer, cfg, func(msg string, args ...interface{}) {
		logCalled = true
	})

	scheduler.Start()
	time.Sleep(100 * time.Millisecond) // Let initial check run
	scheduler.Stop()

	// The initial check should have triggered logging
	if !logCalled {
		t.Error("expected scheduler to perform initial check and log")
	}
}

func TestRolloverSchedulerDisabled(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())

	cfg := RolloverConfig{Enabled: false}
	scheduler := NewRolloverScheduler(signer, cfg, nil)
	scheduler.Start() // Should be no-op
	scheduler.Stop()  // Should be no-op
	// If we reach here without panic, the test passes
}

func TestGetActiveKSKsWithoutTiming(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())

	ksk, err := signer.GenerateKeyPair(13, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// No timing set — key should be active by default
	active := signer.GetActiveKSKs()
	if len(active) != 1 {
		t.Fatalf("GetActiveKSKs() = %d, want 1", len(active))
	}
	if active[0].KeyTag != ksk.KeyTag {
		t.Errorf("active KSK keytag = %d, want %d", active[0].KeyTag, ksk.KeyTag)
	}
}

func TestKeyTimingFields(t *testing.T) {
	now := time.Now()
	timing := &KeyTiming{
		Created: now,
		Publish: now.Add(time.Hour),
		Active:  now.Add(2 * time.Hour),
		Retire:  now.Add(90 * 24 * time.Hour),
		Remove:  now.Add(120 * 24 * time.Hour),
	}

	if timing.Publish.Before(timing.Created) {
		t.Error("Publish should be after Created")
	}
	if timing.Active.Before(timing.Publish) {
		t.Error("Active should be after Publish")
	}
	if timing.Retire.Before(timing.Active) {
		t.Error("Retire should be after Active")
	}
	if timing.Remove.Before(timing.Retire) {
		t.Error("Remove should be after Retire")
	}
}

// TestRolloverNoDuplicateKeys verifies that while a replacement ZSK/KSK is
// already published and waiting to activate, the scheduler does NOT mint
// another key on every check tick.
//
// Regression: maybeRolloverZSK/KSK only looked at ACTIVE keys, so once a
// rollover was triggered (active key within PublishSafety of Retire), every
// subsequent check() call generated ANOTHER replacement — an unbounded pile
// of Published-but-inactive keys accumulating over the PublishSafety window.
func TestRolloverNoDuplicateKeys(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())

	// Seed an active ZSK and KSK with timing that triggers rollover soon:
	// Retire is inside PublishSafety from now.
	now := time.Now()
	zsk, err := signer.GenerateKeyPair(13, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair ZSK: %v", err)
	}
	signer.SetKeyTiming(zsk.KeyTag, &KeyTiming{
		Created: now.Add(-30 * 24 * time.Hour),
		Publish: now.Add(-29 * 24 * time.Hour),
		Active:  now.Add(-28 * 24 * time.Hour),
		Retire:  now.Add(12 * time.Hour), // inside PublishSafety (24h)
		Remove:  now.Add(30 * 24 * time.Hour),
	})
	signer.SetKeyState(zsk.KeyTag, KeyStateActive)

	ksk, err := signer.GenerateKeyPair(13, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair KSK: %v", err)
	}
	signer.SetKeyTiming(ksk.KeyTag, &KeyTiming{
		Created: now.Add(-400 * 24 * time.Hour),
		Publish: now.Add(-399 * 24 * time.Hour),
		Active:  now.Add(-398 * 24 * time.Hour),
		Retire:  now.Add(12 * time.Hour), // inside PublishSafety (24h)
		Remove:  now.Add(30 * 24 * time.Hour),
	})
	signer.SetKeyState(ksk.KeyTag, KeyStateActive)

	cfg := RolloverConfig{
		Enabled:       true,
		ZSKLifetime:   90 * 24 * time.Hour,
		KSKLifetime:   365 * 24 * time.Hour,
		PublishSafety: 24 * time.Hour,
		RetireSafety:  30 * 24 * time.Hour,
		Algorithm:     13,
		CheckInterval: 1 * time.Hour,
	}
	scheduler := NewRolloverScheduler(signer, cfg, nil)

	// Run check() several times: each run triggers maybeRolloverZSK/KSK.
	for i := 0; i < 5; i++ {
		scheduler.check()
	}

	// Exactly one replacement per key type should have been generated.
	zskCount, kskCount := 0, 0
	for _, k := range signer.GetKeys() {
		if k.IsZSK {
			zskCount++
		}
		if k.IsKSK {
			kskCount++
		}
	}
	if zskCount != 2 {
		t.Errorf("expected 2 ZSKs (original + one replacement), got %d", zskCount)
	}
	if kskCount != 2 {
		t.Errorf("expected 2 KSKs (original + one replacement), got %d", kskCount)
	}
}
