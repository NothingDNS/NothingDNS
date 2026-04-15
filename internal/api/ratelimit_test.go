package api

import (
	"testing"
	"time"
)

func newTestLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		ipAttempts:   make(map[string]*loginAttempt),
		userAttempts: make(map[string]*loginAttempt),
	}
}

// --- checkRateLimit tests ---

func TestCheckRateLimit_NoEntry(t *testing.T) {
	l := newTestLimiter()
	limited, delay := l.checkRateLimit("1.2.3.4")
	if limited {
		t.Error("new IP should not be rate limited")
	}
	if delay != 0 {
		t.Errorf("expected 0 delay, got %v", delay)
	}
}

func TestCheckRateLimit_AfterFewAttempts(t *testing.T) {
	l := newTestLimiter()
	// Record a few attempts but not enough to trigger lockout
	l.recordFailedAttempt("1.2.3.4", "user")
	l.recordFailedAttempt("1.2.3.4", "user")
	l.recordFailedAttempt("1.2.3.4", "user")

	// Should be limited due to progressive delay
	limited, _ := l.checkRateLimit("1.2.3.4")
	if !limited {
		t.Error("expected progressive delay to be active")
	}
}

func TestCheckRateLimit_AfterLockoutExpires(t *testing.T) {
	l := newTestLimiter()
	// Manually set a locked IP with expired lockout
	l.mu.Lock()
	l.ipAttempts["1.2.3.4"] = &loginAttempt{
		count:       10,
		lastTry:     time.Now().Add(-10 * time.Minute),
		lockedUntil: time.Now().Add(-5 * time.Minute), // expired
	}
	l.mu.Unlock()

	limited, delay := l.checkRateLimit("1.2.3.4")
	if limited {
		t.Error("expired lockout should not rate limit")
	}
	if delay != 0 {
		t.Errorf("expected 0 delay, got %v", delay)
	}
}

// --- checkUserRateLimit tests ---

func TestCheckUserRateLimit_NoEntry(t *testing.T) {
	l := newTestLimiter()
	limited, delay := l.checkUserRateLimit("admin")
	if limited {
		t.Error("new user should not be rate limited")
	}
	if delay != 0 {
		t.Errorf("expected 0 delay, got %v", delay)
	}
}

func TestCheckUserRateLimit_LockedOut(t *testing.T) {
	l := newTestLimiter()
	l.mu.Lock()
	l.userAttempts["admin"] = &loginAttempt{
		count:       loginMaxAttempts,
		lastTry:     time.Now(),
		lockedUntil: time.Now().Add(loginLockoutPeriod),
	}
	l.mu.Unlock()

	limited, delay := l.checkUserRateLimit("admin")
	if !limited {
		t.Error("locked user should be rate limited")
	}
	if delay <= 0 {
		t.Errorf("expected positive delay, got %v", delay)
	}
}

func TestCheckUserRateLimit_ExpiredLockout(t *testing.T) {
	l := newTestLimiter()
	l.mu.Lock()
	l.userAttempts["admin"] = &loginAttempt{
		count:       loginMaxAttempts,
		lastTry:     time.Now().Add(-10 * time.Minute),
		lockedUntil: time.Now().Add(-5 * time.Minute),
	}
	l.mu.Unlock()

	limited, _ := l.checkUserRateLimit("admin")
	if limited {
		t.Error("expired user lockout should not rate limit")
	}
}

// --- recordFailedAttempt tests ---

func TestRecordFailedAttempt_NewIP(t *testing.T) {
	l := newTestLimiter()
	l.recordFailedAttempt("1.2.3.4", "user")

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ipAttempts) != 1 {
		t.Errorf("expected 1 IP entry, got %d", len(l.ipAttempts))
	}
	if l.ipAttempts["1.2.3.4"].count != 1 {
		t.Errorf("expected count 1, got %d", l.ipAttempts["1.2.3.4"].count)
	}
	if len(l.userAttempts) != 1 {
		t.Errorf("expected 1 user entry, got %d", len(l.userAttempts))
	}
}

func TestRecordFailedAttempt_Increments(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < 3; i++ {
		l.recordFailedAttempt("1.2.3.4", "user")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ipAttempts["1.2.3.4"].count != 3 {
		t.Errorf("expected count 3, got %d", l.ipAttempts["1.2.3.4"].count)
	}
}

func TestRecordFailedAttempt_TriggersLockout(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < loginMaxAttempts; i++ {
		l.recordFailedAttempt("1.2.3.4", "user")
	}

	l.mu.Lock()
	ipEntry := l.ipAttempts["1.2.3.4"]
	userEntry := l.userAttempts["user"]
	l.mu.Unlock()

	if ipEntry.lockedUntil.IsZero() {
		t.Error("expected IP to be locked after max attempts")
	}
	if userEntry.lockedUntil.IsZero() {
		t.Error("expected user to be locked after max attempts")
	}
	if time.Until(ipEntry.lockedUntil) < loginLockoutPeriod-time.Second {
		t.Error("IP lockout period too short")
	}
}

func TestRecordFailedAttempt_ResetsAfterExpiredLockout(t *testing.T) {
	l := newTestLimiter()
	// Set an expired lockout
	l.mu.Lock()
	l.ipAttempts["1.2.3.4"] = &loginAttempt{
		count:       loginMaxAttempts,
		lastTry:     time.Now().Add(-10 * time.Minute),
		lockedUntil: time.Now().Add(-5 * time.Minute), // expired
	}
	l.mu.Unlock()

	// New attempt should reset count
	l.recordFailedAttempt("1.2.3.4", "user")

	l.mu.Lock()
	defer l.mu.Unlock()
	// count gets reset to 0 then incremented to 1
	if l.ipAttempts["1.2.3.4"].count != 1 {
		t.Errorf("expected count 1 after expired lockout reset, got %d", l.ipAttempts["1.2.3.4"].count)
	}
}

func TestRecordFailedAttempt_MultipleIPs(t *testing.T) {
	l := newTestLimiter()
	l.recordFailedAttempt("1.2.3.4", "admin")
	l.recordFailedAttempt("5.6.7.8", "admin")

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ipAttempts) != 2 {
		t.Errorf("expected 2 IP entries, got %d", len(l.ipAttempts))
	}
	// Both IPs tracked for same user
	if l.userAttempts["admin"].count != 2 {
		t.Errorf("expected user count 2, got %d", l.userAttempts["admin"].count)
	}
}

// --- recordSuccess tests ---

func TestRecordSuccess_ClearsEntries(t *testing.T) {
	l := newTestLimiter()
	l.recordFailedAttempt("1.2.3.4", "admin")
	l.recordFailedAttempt("1.2.3.4", "admin")

	l.recordSuccess("1.2.3.4", "admin")

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.ipAttempts["1.2.3.4"]; exists {
		t.Error("IP entry should be removed after success")
	}
	if _, exists := l.userAttempts["admin"]; exists {
		t.Error("user entry should be removed after success")
	}
}

func TestRecordSuccess_NoEntry(t *testing.T) {
	l := newTestLimiter()
	// Should not panic
	l.recordSuccess("1.2.3.4", "admin")
}

// --- cleanup tests ---

func TestCleanup_RemovesStale(t *testing.T) {
	l := newTestLimiter()
	l.mu.Lock()
	// Expired IP entry
	l.ipAttempts["1.2.3.4"] = &loginAttempt{
		count:       1,
		lastTry:     time.Now().Add(-2 * time.Minute),
		lockedUntil: time.Time{},
	}
	// Active IP entry (still in delay window)
	l.ipAttempts["5.6.7.8"] = &loginAttempt{
		count:       1,
		lastTry:     time.Now(),
		lockedUntil: time.Time{},
	}
	// Expired user lockout
	l.userAttempts["admin"] = &loginAttempt{
		count:       5,
		lastTry:     time.Now().Add(-10 * time.Minute),
		lockedUntil: time.Now().Add(-5 * time.Minute),
	}
	// Active user lockout
	l.userAttempts["root"] = &loginAttempt{
		count:       5,
		lastTry:     time.Now(),
		lockedUntil: time.Now().Add(5 * time.Minute),
	}
	l.mu.Unlock()

	l.cleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.ipAttempts["1.2.3.4"]; exists {
		t.Error("stale IP entry should be cleaned up")
	}
	if _, exists := l.ipAttempts["5.6.7.8"]; !exists {
		t.Error("active IP entry should NOT be cleaned up")
	}
	if _, exists := l.userAttempts["admin"]; exists {
		t.Error("expired user lockout should be cleaned up")
	}
	if _, exists := l.userAttempts["root"]; !exists {
		t.Error("active user lockout should NOT be cleaned up")
	}
}

func TestCleanup_EmptyMaps(t *testing.T) {
	l := newTestLimiter()
	// Should not panic
	l.cleanup()
}

// --- Integration: full login flow ---

func TestLoginRateLimiter_FullFlow(t *testing.T) {
	l := newTestLimiter()
	ip := "192.168.1.100"
	username := "admin"

	// Successful login first
	limited, _ := l.checkRateLimit(ip)
	if limited {
		t.Fatal("first attempt should not be rate limited")
	}
	l.recordSuccess(ip, username)

	// Simulate max failed attempts (bypass checkRateLimit to avoid progressive delay)
	for i := 0; i < loginMaxAttempts; i++ {
		l.recordFailedAttempt(ip, username)
	}

	// Should now be locked
	limited, delay := l.checkRateLimit(ip)
	if !limited {
		t.Error("should be locked after max attempts")
	}
	if delay <= 0 {
		t.Error("should have remaining lockout time")
	}

	// User should also be locked
	userLimited, _ := l.checkUserRateLimit(username)
	if !userLimited {
		t.Error("user should be locked after max attempts")
	}
}
