package transfer

import (
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// SOA timer bounds for secondary zones (F412). A master's SOA controls how
// often this server contacts it, so absurd values are clamped (as BIND's
// min/max-refresh-time and min/max-retry-time do): a zero REFRESH must not
// become a transfer loop, and a huge one must not silently stop refreshing.
const (
	slaveMinRefresh = 30 * time.Second
	slaveMaxRefresh = 28 * 24 * time.Hour
	slaveMinRetry   = 30 * time.Second
	slaveMaxRetry   = 14 * 24 * time.Hour
)

func realAfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// SetClock replaces the time source of the SOA refresh/retry/expire timers
// (tests inject a fake clock). now reports the current time; afterFunc must
// arrange for f to run once, asynchronously, after d and return a function
// that cancels it (reporting whether it stopped the timer before it fired).
// Nil arguments restore the real clock. Call it before AddSlaveZone.
func (sm *SlaveManager) SetClock(now func() time.Time, afterFunc func(d time.Duration, f func()) (stop func() bool)) {
	if now == nil {
		now = time.Now
	}
	if afterFunc == nil {
		afterFunc = realAfterFunc
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.now, sm.afterFunc = now, afterFunc
	for _, sz := range sm.slaveZones {
		sz.mu.Lock()
		sz.now = now
		sz.mu.Unlock()
	}
}

// Expired reports whether the zone's SOA EXPIRE interval has elapsed since
// its last successful refresh (RFC 1035 §4.3.5). An expired zone must no
// longer be served; it becomes servable again after the next successful
// refresh. A zone the manager never refreshed has no expiry.
func (sz *SlaveZone) Expired() bool {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	if sz.expireAt.IsZero() {
		return false
	}
	now := sz.now
	if now == nil {
		now = time.Now
	}
	return !now().Before(sz.expireAt)
}

// ExpiresAt returns when the zone expires unless a refresh succeeds first
// (zero when no expiry is known).
func (sz *SlaveZone) ExpiresAt() time.Time {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	return sz.expireAt
}

// IsServable reports whether the zone may be answered from: it holds
// transferred data (an SOA) and has not expired.
func (sz *SlaveZone) IsServable() bool {
	z := sz.GetZone()
	if z == nil {
		return false
	}
	z.RLock()
	hasSOA := z.SOA != nil
	z.RUnlock()
	return hasSOA && !sz.Expired()
}

// soaTimers holds a zone's clamped SOA REFRESH, RETRY and EXPIRE intervals.
type soaTimers struct {
	refresh, retry, expire time.Duration
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// zoneSOATimers reads the timer fields of z's SOA; ok is false without one.
func zoneSOATimers(z *zone.Zone) (soaTimers, bool) {
	if z == nil {
		return soaTimers{}, false
	}
	z.RLock()
	defer z.RUnlock()
	if z.SOA == nil {
		return soaTimers{}, false
	}
	t := soaTimers{
		refresh: clampDuration(time.Duration(z.SOA.Refresh)*time.Second, slaveMinRefresh, slaveMaxRefresh),
		retry:   clampDuration(time.Duration(z.SOA.Retry)*time.Second, slaveMinRetry, slaveMaxRetry),
		expire:  time.Duration(z.SOA.Expire) * time.Second,
	}
	// EXPIRE shorter than one refresh cycle would expire a healthy zone
	// between checks (RFC 1912 §2.2: expire well above refresh + retry).
	if floor := t.refresh + t.retry; t.expire < floor {
		t.expire = floor
	}
	return t, true
}

// completeTransfer ends one transfer run of the zone's owner. If a refresh was
// requested meanwhile it keeps ownership and returns true (run again).
// Otherwise it releases ownership and, in the same critical section, arms the
// zone's next timer so no concurrent run can interleave: after success the
// EXPIRE window restarts and REFRESH is armed; after a failure one RETRY wait
// is armed unless one is already pending (single retry chain, F204).
func (sm *SlaveManager) completeTransfer(zoneName string, sz *SlaveZone, err error) bool {
	timers, haveSOA := zoneSOATimers(sz.GetZone())

	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sz.mu.Lock()
	defer sz.mu.Unlock()

	if sz.refreshPending {
		sz.refreshPending = false
		return true
	}
	sz.transferring = false
	if sm.slaveZones[zoneName] != sz {
		return false
	}
	sz.now = sm.now

	// The bookkeeping below also runs while stopping; only arming a timer
	// is skipped once Stop has begun (it cancels every timer).
	if err == nil {
		sz.retries = 0
		if haveSOA {
			sz.expireAt = sm.now().Add(timers.expire)
			if !sm.stopped {
				sm.armTimerLocked(zoneName, sz, timers.refresh, false)
			}
		}
		return false
	}

	if sz.retryScheduled {
		return false
	}
	sz.retries++
	if sm.stopped {
		return false
	}
	if max := sz.Config.MaxRetries; max > 0 && sz.retries > max {
		if !haveSOA {
			sz.cancelTimerLocked()
			util.Warnf("slave: giving up on %s after %d consecutive transfer failures (MaxRetries=%d)",
				zoneName, sz.retries-1, max)
			return false
		}
		util.Warnf("slave: %s: %d consecutive transfer failures (MaxRetries=%d); next attempt at the SOA refresh interval",
			zoneName, sz.retries-1, max)
		sz.retries = 0
		sm.armTimerLocked(zoneName, sz, timers.refresh, false)
		return false
	}
	interval := sz.Config.RetryInterval
	if haveSOA {
		interval = timers.retry
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	sm.armTimerLocked(zoneName, sz, interval, true)
	return false
}

// armTimerLocked replaces the zone's pending timer with one firing after d.
// The caller holds sm.mu (read) and sz.mu.
func (sm *SlaveManager) armTimerLocked(zoneName string, sz *SlaveZone, d time.Duration, retry bool) {
	sz.cancelTimerLocked()
	gen := sz.timerGen
	sz.retryScheduled = retry
	sz.stopTimer = sm.afterFunc(d, func() { sm.timerFired(zoneName, sz, gen) })
}

// cancelTimerLocked stops the zone's pending timer and invalidates a callback
// that already fired. The caller holds sz.mu.
func (sz *SlaveZone) cancelTimerLocked() {
	if sz.stopTimer != nil {
		sz.stopTimer()
		sz.stopTimer = nil
	}
	sz.timerGen++
	sz.retryScheduled = false
}

// timerFired runs a zone's REFRESH or RETRY: it starts a transfer (IXFR with
// the held serial, which answers a lone SOA when the zone is current), or
// folds into the one already in flight. Holding sm.mu across the stopped
// check and startZoneTransfer's wg.Add keeps it ordered before Stop's Wait.
func (sm *SlaveManager) timerFired(zoneName string, sz *SlaveZone, gen uint64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.stopped || sm.slaveZones[zoneName] != sz {
		return
	}
	sz.mu.Lock()
	if sz.timerGen != gen {
		sz.mu.Unlock()
		return
	}
	sz.stopTimer = nil
	sz.retryScheduled = false
	sz.mu.Unlock()
	sm.startZoneTransfer(zoneName, sz)
}
