package dso

import (
	"bytes"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default Enabled should be false")
	}
	if cfg.InactivityTimeout != DefaultInactivityTimeout {
		t.Errorf("Default InactivityTimeout = %v, want %v", cfg.InactivityTimeout, DefaultInactivityTimeout)
	}
	if cfg.MaxPayloadSize != DefaultMaxPayloadSize {
		t.Errorf("Default MaxPayloadSize = %d, want %d", cfg.MaxPayloadSize, DefaultMaxPayloadSize)
	}
	if cfg.MaxSessions != 1000 {
		t.Errorf("Default MaxSessions = %d, want 1000", cfg.MaxSessions)
	}
}

func TestNewManager(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()

	m := NewManager(cfg, logger)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.inactivityTimeout != DefaultInactivityTimeout {
		t.Errorf("inactivityTimeout = %v, want %v", m.inactivityTimeout, DefaultInactivityTimeout)
	}
}

func TestManager_StartStop(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()

	m := NewManager(cfg, logger)

	m.Start()

	// Check that cleanup loop started
	time.Sleep(100 * time.Millisecond)

	m.Stop()
}

func TestNewKeepaliveTLV(t *testing.T) {
	primary := 5 * time.Second
	secondary := 2 * time.Second

	tlv := NewKeepaliveTLV(primary, secondary)

	if tlv.Type != DSOTLVKeepalive {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVKeepalive)
	}
	if len(tlv.Value) != 8 {
		t.Errorf("Value length = %d, want 8", len(tlv.Value))
	}
}

func TestParseKeepaliveTLV(t *testing.T) {
	primary := 5 * time.Second
	secondary := 2 * time.Second

	tlv := NewKeepaliveTLV(primary, secondary)
	parsedPrimary, parsedSecondary, err := ParseKeepaliveTLV(tlv)
	if err != nil {
		t.Fatalf("ParseKeepaliveTLV failed: %v", err)
	}

	// Allow some tolerance due to millisecond conversion
	if parsedPrimary < 4*time.Second || parsedPrimary > 6*time.Second {
		t.Errorf("Primary timeout = %v, want ~5s", parsedPrimary)
	}
	if parsedSecondary < 1*time.Second || parsedSecondary > 3*time.Second {
		t.Errorf("Secondary timeout = %v, want ~2s", parsedSecondary)
	}
}

func TestParseKeepaliveTLV_InvalidType(t *testing.T) {
	tlv := &TLV{Type: DSOTLVPadding, Value: make([]byte, 8)}
	_, _, err := ParseKeepaliveTLV(tlv)
	if err == nil {
		t.Error("Expected error for invalid TLV type")
	}
}

func TestNewSessionIDTLV(t *testing.T) {
	sessionID := uint64(12345)
	tlv := NewSessionIDTLV(sessionID)

	if tlv.Type != DSOTLVSessionID {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVSessionID)
	}
	if len(tlv.Value) != 8 {
		t.Errorf("Value length = %d, want 8", len(tlv.Value))
	}
}

func TestParseSessionIDTLV(t *testing.T) {
	sessionID := uint64(12345)
	tlv := NewSessionIDTLV(sessionID)

	parsedID, err := ParseSessionIDTLV(tlv)
	if err != nil {
		t.Fatalf("ParseSessionIDTLV failed: %v", err)
	}
	if parsedID != sessionID {
		t.Errorf("Session ID = %d, want %d", parsedID, sessionID)
	}
}

func TestNewRetryDelayTLV(t *testing.T) {
	delay := 5 * time.Second
	tlv := NewRetryDelayTLV(delay)

	if tlv.Type != DSOTLVRetryDelay {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVRetryDelay)
	}
	if len(tlv.Value) != 4 {
		t.Errorf("Value length = %d, want 4", len(tlv.Value))
	}
}

func TestNewMaximumPayloadTLV(t *testing.T) {
	maxPayload := uint16(4096)
	tlv := NewMaximumPayloadTLV(maxPayload)

	if tlv.Type != DSOTLVMaximumPayload {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVMaximumPayload)
	}
	if len(tlv.Value) != 2 {
		t.Errorf("Value length = %d, want 2", len(tlv.Value))
	}
}

func TestNewPaddingTLV(t *testing.T) {
	length := uint16(32)
	tlv := NewPaddingTLV(length)

	if tlv.Type != DSOTLVPadding {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVPadding)
	}
	if len(tlv.Value) != 32 {
		t.Errorf("Value length = %d, want 32", len(tlv.Value))
	}
}

func TestTLV_PackUnpack(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVKeepalive,
		Value: []byte{0, 0, 0, 50, 0, 0, 0, 25},
	}

	buf := make([]byte, 100)
	size, err := tlv.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	if size != 4+8 {
		t.Errorf("Pack size = %d, want 12", size)
	}

	// Unpack
	unpacked, consumed, err := UnpackTLV(buf, 0)
	if err != nil {
		t.Fatalf("UnpackTLV failed: %v", err)
	}
	if consumed != size {
		t.Errorf("Consumed = %d, want %d", consumed, size)
	}
	if unpacked.Type != tlv.Type {
		t.Errorf("Type = %d, want %d", unpacked.Type, tlv.Type)
	}
	if !bytes.Equal(unpacked.Value, tlv.Value) {
		t.Errorf("Value mismatch")
	}
}

func TestUnpackTLV_BufferTooSmall(t *testing.T) {
	buf := make([]byte, 2)
	_, _, err := UnpackTLV(buf, 0)
	if err == nil {
		t.Error("Expected error for buffer too small")
	}
}

func TestSession_IsExpired(t *testing.T) {
	s := &Session{
		ID:           1,
		LastActivity: time.Now().Add(-30 * time.Second),
	}

	if !s.IsExpired(15 * time.Second) {
		t.Error("Session should be expired after 30s with 15s timeout")
	}

	if s.IsExpired(60 * time.Second) {
		t.Error("Session should not be expired with 60s timeout")
	}
}

func TestSession_UpdateActivity(t *testing.T) {
	s := &Session{
		ID:           1,
		LastActivity: time.Now().Add(-30 * time.Second),
	}

	oldActivity := s.LastActivity
	s.UpdateActivity()

	if !s.LastActivity.After(oldActivity) {
		t.Error("LastActivity should be updated")
	}
}

func TestSession_IsClosed(t *testing.T) {
	s := &Session{
		ID:     1,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	if s.IsClosed() {
		t.Error("Session should not be closed initially")
	}

	s.Close()

	if !s.IsClosed() {
		t.Error("Session should be closed after Close()")
	}
}

func TestManager_SessionCount(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	if m.SessionCount() != 0 {
		t.Errorf("Initial count = %d, want 0", m.SessionCount())
	}
}

func TestManager_RemoveSession(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	// Create a mock session
	s := &Session{
		ID:     1,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	m.sessions[1] = s

	m.RemoveSession(1)

	if m.SessionCount() != 0 {
		t.Errorf("Count after remove = %d, want 0", m.SessionCount())
	}
}

func TestIsDSOMessage(t *testing.T) {
	// Standard query (opcode 0)
	standardQuery := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{Opcode: 0}},
	}
	if IsDSOMessage(standardQuery) {
		t.Error("Standard query should not be DSO")
	}

	// DSO message (opcode 6)
	dsoMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{Opcode: 6}},
	}
	if !IsDSOMessage(dsoMsg) {
		t.Error("DSO message should be detected")
	}
}

func TestCreateDSOMessage(t *testing.T) {
	tlvs := []*TLV{
		NewKeepaliveTLV(5*time.Second, 2*time.Second),
	}

	msg, err := CreateDSOMessage(tlvs)
	if err != nil {
		t.Fatalf("CreateDSOMessage failed: %v", err)
	}

	// Check opcode
	if msg.Header.Flags.Opcode != 6 {
		t.Errorf("Opcode = %d, want 6", msg.Header.Flags.Opcode)
	}

	// Check QR = 0 (query)
	if msg.Header.Flags.QR != false {
		t.Error("QR should be 0 for query")
	}

	// Check ARCount
	if msg.Header.ARCount != uint16(len(tlvs)) {
		t.Errorf("ARCount = %d, want %d", msg.Header.ARCount, len(tlvs))
	}
}

func TestTLV_Size(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVKeepalive,
		Value: make([]byte, 8),
	}

	if tlv.Size() != 12 {
		t.Errorf("Size() = %d, want 12", tlv.Size())
	}
}

func TestManager_cleanupExpiredSessions(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.InactivityTimeout = 100 * time.Millisecond
	m := NewManager(cfg, logger)

	// Create expired session
	s1 := &Session{
		ID:            1,
		LastActivity:  time.Now().Add(-200 * time.Millisecond),
		KeepaliveTime: 50 * time.Millisecond,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	// Create active session
	s2 := &Session{
		ID:            2,
		LastActivity:  time.Now(),
		KeepaliveTime: 50 * time.Millisecond,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	m.sessions[1] = s1
	m.sessions[2] = s2

	m.cleanupExpiredSessions()

	if m.SessionCount() != 1 {
		t.Errorf("Count after cleanup = %d, want 1", m.SessionCount())
	}

	_, ok := m.sessions[2]
	if !ok {
		t.Error("Active session should remain")
	}
}
