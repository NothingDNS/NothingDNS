package dnssec

import (
	"testing"
	"time"
)

// An active key must not retire before its replacement becomes active: with no
// active ZSK the zone's online answers go out unsigned and validators fail
// them. The scheduler starts a rollover on the first check inside the publish
// window, so the old key's Retire can fall anywhere in (now, now+PublishSafety]
// — before the new key's Active time unless the old Retire is moved out.
func TestRolloverZSKHasNoSigningGap(t *testing.T) {
	cfg := RolloverConfig{
		Enabled:       true,
		ZSKLifetime:   30 * 24 * time.Hour,
		PublishSafety: 24 * time.Hour,
		RetireSafety:  24 * time.Hour,
		Algorithm:     13,
	}

	setup := func(retireIn time.Duration) (*Signer, *SigningKey, time.Time) {
		signer := NewSigner("example.com.", DefaultSignerConfig())
		now := time.Now()
		old, err := signer.generateKeyPairWithState(13, false, KeyStateActive, &KeyTiming{
			Created: now.Add(-29 * 24 * time.Hour),
			Publish: now.Add(-29 * 24 * time.Hour),
			Active:  now.Add(-29 * 24 * time.Hour),
			Retire:  now.Add(retireIn),
			Remove:  now.Add(retireIn + cfg.RetireSafety),
		})
		if err != nil {
			t.Fatal(err)
		}
		return signer, old, now
	}

	t.Run("retire inside the publish window", func(t *testing.T) {
		signer, old, _ := setup(23*time.Hour + 30*time.Minute)
		NewRolloverScheduler(signer, cfg, nil).check()

		var newActive time.Time
		for _, k := range signer.GetKeys() {
			if k.KeyTag != old.KeyTag && k.IsZSK {
				newActive = k.Timing.Active
			}
		}
		if newActive.IsZero() {
			t.Fatal("no replacement ZSK was generated")
		}
		oldRetire := signer.keys[old.KeyTag].Timing.Retire
		if oldRetire.Before(newActive) {
			t.Fatalf("FAIL: old ZSK retires at %s, %s before the replacement is active at %s: no active ZSK in between",
				oldRetire.Format(time.RFC3339), newActive.Sub(oldRetire).Round(time.Second), newActive.Format(time.RFC3339))
		}
	})

	// Control: a key far from retirement starts no rollover.
	t.Run("retire outside the publish window", func(t *testing.T) {
		signer, _, _ := setup(10 * 24 * time.Hour)
		NewRolloverScheduler(signer, cfg, nil).check()
		if n := len(signer.GetKeys()); n != 1 {
			t.Fatalf("control: %d keys, want 1", n)
		}
	})
}
