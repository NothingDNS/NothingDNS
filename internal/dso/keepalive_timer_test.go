package dso

import (
	"testing"
	"time"
)

// RFC 8490 §6.3: "a DSO Keepalive message resets only the keepalive timer, not
// the inactivity timeout timer. The reason for this is that periodic DSO
// Keepalive messages are sent for the sole purpose of keeping a DSO Session
// alive when that DSO Session has current or recent non-maintenance activity...
// If DSO keepalive traffic itself were to reset the inactivity timer, then that
// would create a circular livelock where keepalive traffic would be sent
// indefinitely to keep a DSO Session alive."
//
// RFC 8490 §6.4.1: when the inactivity period passes with no operation active,
// "the server MUST consider the client delinquent and MUST forcibly abort the
// DSO Session".
//
// A client that does nothing but send Keepalives must therefore still be
// reaped. If a Keepalive refreshes the session's activity time, an idle session
// is held open for as long as the client keeps pinging — exhausting the
// session table (MaxSessions) with connections that carry no work.
func TestKeepaliveDoesNotResetTheInactivityTimer(t *testing.T) {
	const inactivity = 200 * time.Millisecond

	newIdleSession := func(t *testing.T) (*Manager, *Session) {
		t.Helper()
		cfg := DefaultConfig()
		cfg.AllowPlainTCP = true
		cfg.InactivityTimeout = inactivity
		m := NewManager(cfg, nil)
		sess := freshSession()
		// Last real activity was far longer ago than the inactivity timeout.
		sess.LastActivity = time.Now().Add(-time.Minute)
		m.sessions[sess.ID] = sess
		return m, sess
	}

	t.Run("control: a non-keepalive DSO message does count as activity", func(t *testing.T) {
		m, sess := newIdleSession(t)
		// Maximum Payload is a recognised, non-keepalive primary TLV.
		if _, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVMaximumPayload, []byte{0x10, 0x00}))); err != nil {
			t.Fatalf("HandleDSORequest: %v", err)
		}
		m.cleanupExpiredSessions()
		if m.SessionCount() != 1 {
			t.Fatalf("a session that just carried a real message was reaped (count=%d)", m.SessionCount())
		}
	})

	t.Run("control: an idle session with no traffic at all is reaped", func(t *testing.T) {
		m, _ := newIdleSession(t)
		m.cleanupExpiredSessions()
		if m.SessionCount() != 0 {
			t.Fatalf("an idle session survived the sweep (count=%d)", m.SessionCount())
		}
	})

	t.Run("a Keepalive does not rescue an idle session", func(t *testing.T) {
		m, sess := newIdleSession(t)
		resp, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVKeepalive, keepaliveBody(15000, 15000))))
		if err != nil || resp == nil {
			t.Fatalf("Keepalive must still be answered: err=%v resp=%v", err, resp)
		}
		m.cleanupExpiredSessions()
		if m.SessionCount() != 0 {
			t.Fatalf("FAIL: an idle session survived the sweep because the client sent a Keepalive (count=%d); a Keepalive must reset only the keepalive timer (RFC 8490 §6.3)", m.SessionCount())
		}
	})

	t.Run("a Keepalive still updates the negotiated timeouts", func(t *testing.T) {
		m, sess := newIdleSession(t)
		if _, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVKeepalive, keepaliveBody(15000, 45000)))); err != nil {
			t.Fatal(err)
		}
		if sess.KeepaliveTime != 45*time.Second || !sess.keepalivesEnabled {
			t.Fatalf("KeepaliveTime=%v enabled=%v, the Keepalive's interval must still be applied", sess.KeepaliveTime, sess.keepalivesEnabled)
		}
	})
}
