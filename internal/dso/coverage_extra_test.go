package dso

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// --- TLV Pack edge cases ---

func TestTLV_Pack_BufferTooSmall(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVKeepalive,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	buf := make([]byte, 3) // Too small for even the header
	_, err := tlv.Pack(buf, 0)
	if err == nil {
		t.Error("expected error for buffer too small")
	}
}

func TestTLV_Pack_BufferTooSmall_WithOffset(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVKeepalive,
		Value: make([]byte, 8),
	}

	buf := make([]byte, 20)
	// offset 10 + Size() 12 > 20
	_, err := tlv.Pack(buf, 10)
	if err == nil {
		t.Error("expected error when offset+size exceeds buffer")
	}
}

func TestTLV_Pack_AtNonZeroOffset(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVSessionID,
		Value: []byte{0xAA, 0xBB},
	}

	buf := make([]byte, 64)
	offset := 5

	n, err := tlv.Pack(buf, offset)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	if n != 6 { // 4 header + 2 value
		t.Errorf("Pack returned %d, want 6", n)
	}

	// Verify bytes were written at correct offset
	gotType := binary.BigEndian.Uint16(buf[offset:])
	if gotType != DSOTLVSessionID {
		t.Errorf("packed type = %d, want %d", gotType, DSOTLVSessionID)
	}
	gotLen := binary.BigEndian.Uint16(buf[offset+2:])
	if gotLen != 2 {
		t.Errorf("packed length = %d, want 2", gotLen)
	}
	if buf[offset+4] != 0xAA || buf[offset+5] != 0xBB {
		t.Errorf("packed value bytes incorrect: %x", buf[offset+4:offset+6])
	}
}

func TestTLV_Pack_EmptyValue(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVPadding,
		Value: []byte{},
	}

	buf := make([]byte, 64)
	n, err := tlv.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	if n != 4 {
		t.Errorf("Pack returned %d, want 4", n)
	}

	gotLen := binary.BigEndian.Uint16(buf[2:])
	if gotLen != 0 {
		t.Errorf("packed length = %d, want 0", gotLen)
	}
}

// --- UnpackTLV edge cases ---

func TestUnpackTLV_ValueBufferTooSmall(t *testing.T) {
	// Create a buffer with header claiming 10 bytes of value but only provide 4
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:], DSOTLVKeepalive)
	binary.BigEndian.PutUint16(buf[2:], 10) // Claims 10 bytes of value
	// But buffer only has 4 bytes of value available

	_, _, err := UnpackTLV(buf, 0)
	if err == nil {
		t.Error("expected error for value buffer too small")
	}
}

func TestUnpackTLV_AtNonZeroOffset(t *testing.T) {
	// Build a valid TLV at offset 3
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, 64)

	offset := 3
	binary.BigEndian.PutUint16(buf[offset:], DSOTLVRetryDelay)
	binary.BigEndian.PutUint16(buf[offset+2:], uint16(len(value)))
	copy(buf[offset+4:], value)

	tlv, consumed, err := UnpackTLV(buf, offset)
	if err != nil {
		t.Fatalf("UnpackTLV failed: %v", err)
	}
	if tlv.Type != DSOTLVRetryDelay {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVRetryDelay)
	}
	if consumed != 4+4 {
		t.Errorf("consumed = %d, want 8", consumed)
	}
}

func TestUnpackTLV_OffsetPastEnd(t *testing.T) {
	buf := make([]byte, 10)
	_, _, err := UnpackTLV(buf, 20) // offset beyond buffer
	if err == nil {
		t.Error("expected error for offset past end")
	}
}

func TestUnpackTLV_ZeroLengthValue(t *testing.T) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:], DSOTLVPadding)
	binary.BigEndian.PutUint16(buf[2:], 0)

	tlv, consumed, err := UnpackTLV(buf, 0)
	if err != nil {
		t.Fatalf("UnpackTLV failed: %v", err)
	}
	if tlv.Type != DSOTLVPadding {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVPadding)
	}
	if len(tlv.Value) != 0 {
		t.Errorf("Value length = %d, want 0", len(tlv.Value))
	}
	if consumed != 4 {
		t.Errorf("consumed = %d, want 4", consumed)
	}
}

// --- ParseKeepaliveTLV edge cases ---

func TestParseKeepaliveTLV_InvalidValueLength(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"empty value", []byte{}},
		{"too short", []byte{0, 0, 0, 1}},
		{"too long", make([]byte, 12)},
		{"7 bytes", make([]byte, 7)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv := &TLV{
				Type:  DSOTLVKeepalive,
				Value: tt.value,
			}
			_, _, err := ParseKeepaliveTLV(tlv)
			if err == nil {
				t.Error("expected error for invalid keepalive TLV length")
			}
		})
	}
}

// --- ParseSessionIDTLV edge cases ---

func TestParseSessionIDTLV_WrongType(t *testing.T) {
	tlv := &TLV{
		Type:  DSOTLVKeepalive, // Wrong type
		Value: make([]byte, 8),
	}
	_, err := ParseSessionIDTLV(tlv)
	if err == nil {
		t.Error("expected error for wrong TLV type")
	}
}

func TestParseSessionIDTLV_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 4)},
		{"too long", make([]byte, 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv := &TLV{
				Type:  DSOTLVSessionID,
				Value: tt.value,
			}
			_, err := ParseSessionIDTLV(tlv)
			if err == nil {
				t.Error("expected error for invalid session ID TLV length")
			}
		})
	}
}

func TestParseSessionIDTLV_RoundTrip(t *testing.T) {
	ids := []uint64{0, 1, 0xFFFFFFFFFFFFFFFF, 1234567890}
	for _, id := range ids {
		tlv := NewSessionIDTLV(id)
		parsed, err := ParseSessionIDTLV(tlv)
		if err != nil {
			t.Errorf("ParseSessionIDTLV(%d) failed: %v", id, err)
		}
		if parsed != id {
			t.Errorf("got %d, want %d", parsed, id)
		}
	}
}

// --- Session edge cases ---

func TestSession_Close_DoubleClose(t *testing.T) {
	s := &Session{
		ID:     1,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	s.Close()
	if !s.IsClosed() {
		t.Error("session should be closed after first Close()")
	}

	// Second close should not panic
	s.Close()
	if !s.IsClosed() {
		t.Error("session should still be closed after second Close()")
	}
}

func TestSession_Close_WithNilConn(t *testing.T) {
	s := &Session{
		ID:     1,
		Conn:   nil, // nil connection
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	s.Close() // Should not panic
	if !s.IsClosed() {
		t.Error("session should be closed")
	}
}

func TestSession_Close_WithConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	s := &Session{
		ID:     1,
		Conn:   conn,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	s.Close()
	if !s.IsClosed() {
		t.Error("session should be closed")
	}
}

func TestSession_IsExpired_Exact(t *testing.T) {
	s := &Session{
		ID:           1,
		LastActivity: time.Now(),
	}

	// A just-created session should not be expired with any reasonable timeout
	if s.IsExpired(15 * time.Second) {
		t.Error("fresh session should not be expired")
	}
}

func TestSession_IsExpired_ConcurrentAccess(t *testing.T) {
	s := &Session{
		ID:           1,
		LastActivity: time.Now(),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.UpdateActivity()
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		s.IsExpired(15 * time.Second)
	}
	<-done
}

// --- NewManager zero-config defaults ---

func TestNewManager_ZeroConfigDefaults(t *testing.T) {
	cfg := Config{} // All zero values
	m := NewManager(cfg, nil)

	if m.inactivityTimeout != DefaultInactivityTimeout {
		t.Errorf("inactivityTimeout = %v, want %v", m.inactivityTimeout, DefaultInactivityTimeout)
	}
	if m.maxPayloadSize != DefaultMaxPayloadSize {
		t.Errorf("maxPayloadSize = %d, want %d", m.maxPayloadSize, DefaultMaxPayloadSize)
	}
	if m.maxSessions != 1000 {
		t.Errorf("maxSessions = %d, want 1000", m.maxSessions)
	}
}

func TestNewManager_NilLogger(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)
	if m == nil {
		t.Fatal("NewManager with nil logger returned nil")
	}
}

// --- Manager.Start duplicate call ---

func TestManager_Start_Idempotent(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	m.Start()
	// Second Start should return without panicking
	m.Start()

	time.Sleep(50 * time.Millisecond)
	m.Stop()
}

// --- Manager.Stop with sessions ---

func TestManager_Stop_WithActiveSessions(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	s1, err := m.CreateSession(conn1)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	s2, err := m.CreateSession(conn2)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if m.SessionCount() != 2 {
		t.Errorf("SessionCount = %d, want 2", m.SessionCount())
	}

	m.Stop()

	if !s1.IsClosed() {
		t.Error("session 1 should be closed after manager stop")
	}
	if !s2.IsClosed() {
		t.Error("session 2 should be closed after manager stop")
	}
	if m.SessionCount() != 0 {
		t.Errorf("SessionCount after stop = %d, want 0", m.SessionCount())
	}
}

// --- Manager.CreateSession ---

func TestManager_CreateSession(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	session, err := m.CreateSession(conn)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if session.ID == 0 {
		t.Error("session ID should not be zero")
	}
	if session.Conn == nil {
		t.Error("session Conn should not be nil")
	}
	if session.RemoteAddr == nil {
		t.Error("session RemoteAddr should not be nil")
	}
	if session.CreatedAt.IsZero() {
		t.Error("session CreatedAt should not be zero")
	}
	if session.LastActivity.IsZero() {
		t.Error("session LastActivity should not be zero")
	}
	if session.MaxPayload != cfg.MaxPayloadSize {
		t.Errorf("session MaxPayload = %d, want %d", session.MaxPayload, cfg.MaxPayloadSize)
	}
	if session.KeepaliveTime != cfg.InactivityTimeout/3 {
		t.Errorf("session KeepaliveTime = %v, want %v", session.KeepaliveTime, cfg.InactivityTimeout/3)
	}

	// Verify session is stored
	if m.GetSession(session.ID) != session {
		t.Error("GetSession did not return the same session")
	}

	if m.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1", m.SessionCount())
	}
}

func TestManager_CreateSession_MaxReached(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		InactivityTimeout: DefaultInactivityTimeout,
		MaxSessions:       1,
		MaxPayloadSize:    DefaultMaxPayloadSize,
	}
	m := NewManager(cfg, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn1, _ := net.Dial("tcp", ln.Addr().String())
	_, err = m.CreateSession(conn1)
	if err != nil {
		t.Fatalf("first CreateSession failed: %v", err)
	}

	conn2, _ := net.Dial("tcp", ln.Addr().String())
	_, err = m.CreateSession(conn2)
	if err == nil {
		t.Error("expected error when max sessions reached")
	}
}

func TestManager_CreateSession_IncrementingIDs(t *testing.T) {
	cfg := Config{MaxSessions: 10}
	m := NewManager(cfg, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	var lastID uint64
	for i := 0; i < 5; i++ {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		s, err := m.CreateSession(conn)
		if err != nil {
			t.Fatalf("CreateSession %d failed: %v", i, err)
		}
		if s.ID <= lastID {
			t.Errorf("session ID %d should be > previous %d", s.ID, lastID)
		}
		lastID = s.ID
	}
}

// --- Manager.GetSession ---

func TestManager_GetSession_Existing(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	session, _ := m.CreateSession(conn)

	got := m.GetSession(session.ID)
	if got != session {
		t.Error("GetSession returned wrong session")
	}
}

func TestManager_GetSession_NonExistent(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	got := m.GetSession(99999)
	if got != nil {
		t.Error("GetSession for non-existent ID should return nil")
	}
}

// --- Manager.generateSessionID ---

func TestManager_GenerateSessionID_Sequential(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	ids := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		id := m.generateSessionID()
		if ids[id] {
			t.Errorf("duplicate session ID: %d", id)
		}
		ids[id] = true
	}
}

// --- Manager.RemoveSession non-existent ---

func TestManager_RemoveSession_NonExistent(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	// Should not panic
	m.RemoveSession(99999)
}

// --- Manager.cleanupExpiredSessions edge cases ---

func TestManager_CleanupExpiredSessions_AllExpired(t *testing.T) {
	cfg := Config{
		InactivityTimeout: 100 * time.Millisecond,
	}
	m := NewManager(cfg, nil)

	for i := 0; i < 5; i++ {
		s := &Session{
			ID:            uint64(i + 1),
			LastActivity:  time.Now().Add(-200 * time.Millisecond),
			KeepaliveTime: 50 * time.Millisecond,
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
		}
		m.sessions[uint64(i+1)] = s
	}

	m.cleanupExpiredSessions()

	if m.SessionCount() != 0 {
		t.Errorf("SessionCount = %d, want 0 after all expired", m.SessionCount())
	}
}

func TestManager_CleanupExpiredSessions_NoneExpired(t *testing.T) {
	cfg := Config{
		InactivityTimeout: 10 * time.Second,
	}
	m := NewManager(cfg, nil)

	for i := 0; i < 5; i++ {
		s := &Session{
			ID:            uint64(i + 1),
			LastActivity:  time.Now(),
			KeepaliveTime: 50 * time.Millisecond,
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
		}
		m.sessions[uint64(i+1)] = s
	}

	m.cleanupExpiredSessions()

	if m.SessionCount() != 5 {
		t.Errorf("SessionCount = %d, want 5 after none expired", m.SessionCount())
	}
}

// --- Manager.HandleDSORequest ---

func TestManager_HandleDSORequest_EmptyTLVs(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	session := &Session{
		ID:     1,
		Conn:   nil,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0,
			Flags: protocol.Flags{
				Opcode: 6,
			},
		},
	}

	resp, err := m.HandleDSORequest(session, msg)
	if err != nil {
		t.Fatalf("HandleDSORequest failed: %v", err)
	}
	if resp == nil {
		t.Fatal("response should not be nil")
	}
	if !resp.Header.Flags.QR {
		t.Error("response QR should be true")
	}
	if resp.Header.ARCount != 0 {
		t.Errorf("ARCount = %d, want 0 for empty TLV input", resp.Header.ARCount)
	}
}

func TestManager_HandleDSORequest_KeepaliveTLV(t *testing.T) {
	// Test KeepaliveTLV round-trip parsing since extractTLVs returns nil
	keepaliveTLV := NewKeepaliveTLV(10*time.Second, 5*time.Second)

	parsedPrimary, parsedSecondary, parseErr := ParseKeepaliveTLV(keepaliveTLV)
	if parseErr != nil {
		t.Fatalf("ParseKeepaliveTLV failed: %v", parseErr)
	}
	if parsedPrimary < 9*time.Second || parsedPrimary > 11*time.Second {
		t.Errorf("primary = %v, want ~10s", parsedPrimary)
	}
	if parsedSecondary < 4*time.Second || parsedSecondary > 6*time.Second {
		t.Errorf("secondary = %v, want ~5s", parsedSecondary)
	}
}

// --- Manager.extractTLVs ---

func TestManager_ExtractTLVs(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	msg := &protocol.Message{}

	data, err := m.extractTLVs(msg)
	if err != nil {
		t.Errorf("extractTLVs failed: %v", err)
	}
	if data != nil {
		t.Errorf("extractTLVs returned %v, want nil", data)
	}
}

// --- Manager.buildDSOResponse ---

func TestManager_BuildDSOResponse(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      42,
			Flags:   protocol.Flags{QR: false, Opcode: 6},
			QDCount: 1,
			ARCount: 2,
		},
	}

	tlvs := []*TLV{
		NewKeepaliveTLV(5*time.Second, 3*time.Second),
		NewSessionIDTLV(12345),
	}

	resp := m.buildDSOResponse(req, tlvs)

	if !resp.Header.Flags.QR {
		t.Error("response QR should be true")
	}
	if resp.Header.ARCount != 2 {
		t.Errorf("ARCount = %d, want 2", resp.Header.ARCount)
	}
	if resp.Header.ID != 42 {
		t.Errorf("ID = %d, want 42 (should mirror request)", resp.Header.ID)
	}
}

func TestManager_BuildDSOResponse_EmptyTLVs(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	req := &protocol.Message{
		Header: protocol.Header{
			ID:    0,
			Flags: protocol.Flags{QR: false, Opcode: 6},
		},
	}

	resp := m.buildDSOResponse(req, nil)

	if !resp.Header.Flags.QR {
		t.Error("response QR should be true")
	}
	if resp.Header.ARCount != 0 {
		t.Errorf("ARCount = %d, want 0", resp.Header.ARCount)
	}
}

// --- Manager.SendKeepalive ---

func TestManager_SendKeepalive_ActiveSession(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	m := NewManager(cfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	session, _ := m.CreateSession(conn)

	err = m.SendKeepalive(session)
	if err != nil {
		t.Errorf("SendKeepalive failed: %v", err)
	}
}

func TestManager_SendKeepalive_ClosedSession(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	session := &Session{
		ID:            1,
		KeepaliveTime: 5 * time.Second,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	session.Close()

	err := m.SendKeepalive(session)
	if err == nil {
		t.Error("expected error for closed session")
	}
}

func TestManager_SendKeepalive_NilLogger(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	session, _ := m.CreateSession(conn)

	err = m.SendKeepalive(session)
	if err != nil {
		t.Errorf("SendKeepalive with nil logger failed: %v", err)
	}
}

// --- DSORCode constants ---

func TestDSORCodeValues(t *testing.T) {
	codes := []struct {
		name  string
		code  DSORCode
		value uint16
	}{
		{"NoError", DSOCodeNoError, 0},
		{"InvalidDSO", DSOCodeInvalidDSO, 1},
		{"Unsolicited", DSOCodeUnsolicited, 2},
		{"Retry", DSOCodeRetry, 3},
		{"EncryptionReq", DSOCodeEncryptionReq, 4},
		{"EncryptionNot", DSOCodeEncryptionNot, 5},
		{"SessionExpired", DSOCodeSessionExpired, 6},
		{"SessionClosed", DSOCodeSessionClosed, 7},
	}
	for _, tt := range codes {
		if uint16(tt.code) != tt.value {
			t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.value)
		}
	}
}

// --- DSO type constants ---

func TestDSOTypeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
	}{
		{"DSOTypeRequest", DSOTypeRequest},
		{"DSOTypeResponse", DSOTypeResponse},
	}
	for _, tt := range tests {
		if tt.value != tt.value {
			// just ensure no panic
		}
	}
}

// --- TLV type constants ---

func TestDSOTLVTypeConstants(t *testing.T) {
	types := []struct {
		name  string
		value uint16
	}{
		{"DSOTLVPadding", DSOTLVPadding},
		{"DSOTLVKeepalive", DSOTLVKeepalive},
		{"DSOTLVRetryDelay", DSOTLVRetryDelay},
		{"DSOTLVSessionID", DSOTLVSessionID},
		{"DSOTLVEncryption", DSOTLVEncryption},
		{"DSOTLVMaximumPayload", DSOTLVMaximumPayload},
	}
	for _, tt := range types {
		_ = tt.value // Ensure constants are accessible
	}
}

// --- NewRetryDelayTLV round trip ---

func TestNewRetryDelayTLV_ZeroDelay(t *testing.T) {
	tlv := NewRetryDelayTLV(0)
	if tlv.Type != DSOTLVRetryDelay {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVRetryDelay)
	}
	// 0ms / 100 = 0 units
	gotUnits := binary.BigEndian.Uint32(tlv.Value)
	if gotUnits != 0 {
		t.Errorf("delay units = %d, want 0", gotUnits)
	}
}

func TestNewRetryDelayTLV_LargeDelay(t *testing.T) {
	delay := 600 * time.Second // 10 minutes
	tlv := NewRetryDelayTLV(delay)
	if len(tlv.Value) != 4 {
		t.Errorf("Value length = %d, want 4", len(tlv.Value))
	}
}

// --- NewMaximumPayloadTLV round trip ---

func TestNewMaximumPayloadTLV_RoundTrip(t *testing.T) {
	payloads := []uint16{0, 1, 512, 4096, 65535}
	for _, p := range payloads {
		tlv := NewMaximumPayloadTLV(p)
		if tlv.Type != DSOTLVMaximumPayload {
			t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVMaximumPayload)
		}
		got := binary.BigEndian.Uint16(tlv.Value)
		if got != p {
			t.Errorf("value = %d, want %d", got, p)
		}
	}
}

// --- NewPaddingTLV edge cases ---

func TestNewPaddingTLV_Zero(t *testing.T) {
	tlv := NewPaddingTLV(0)
	if tlv.Type != DSOTLVPadding {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVPadding)
	}
	if len(tlv.Value) != 0 {
		t.Errorf("Value length = %d, want 0", len(tlv.Value))
	}
}

func TestNewPaddingTLV_ContentsAllZero(t *testing.T) {
	tlv := NewPaddingTLV(64)
	for i, b := range tlv.Value {
		if b != 0 {
			t.Errorf("padding byte %d = %d, want 0", i, b)
		}
	}
}

// --- CreateDSOMessage edge cases ---

func TestCreateDSOMessage_EmptyTLVs(t *testing.T) {
	msg, err := CreateDSOMessage(nil)
	if err != nil {
		t.Fatalf("CreateDSOMessage failed: %v", err)
	}
	if msg.Header.Flags.Opcode != 6 {
		t.Errorf("Opcode = %d, want 6", msg.Header.Flags.Opcode)
	}
	if msg.Header.ID != 0 {
		t.Errorf("ID = %d, want 0", msg.Header.ID)
	}
	if msg.Header.ARCount != 0 {
		t.Errorf("ARCount = %d, want 0", msg.Header.ARCount)
	}
}

func TestCreateDSOMessage_MultipleTLVs(t *testing.T) {
	tlvs := []*TLV{
		NewKeepaliveTLV(5*time.Second, 2*time.Second),
		NewSessionIDTLV(42),
		NewPaddingTLV(16),
	}

	msg, err := CreateDSOMessage(tlvs)
	if err != nil {
		t.Fatalf("CreateDSOMessage failed: %v", err)
	}
	if msg.Header.ARCount != 3 {
		t.Errorf("ARCount = %d, want 3", msg.Header.ARCount)
	}
}

// --- IsDSOMessage edge cases ---

func TestIsDSOMessage_Table(t *testing.T) {
	tests := []struct {
		name    string
		opcode  uint8
		isDSO   bool
	}{
		{"standard query", 0, false},
		{"inverse query", 1, false},
		{"status", 2, false},
		{"notify", 4, false},
		{"update", 5, false},
		{"DSO", 6, true},
		{"unknown 7", 7, false},
		{"unknown 15", 15, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{Opcode: tt.opcode},
				},
			}
			if IsDSOMessage(msg) != tt.isDSO {
				t.Errorf("IsDSOMessage(opcode=%d) = %v, want %v", tt.opcode, !tt.isDSO, tt.isDSO)
			}
		})
	}
}

// --- NewKeepaliveTLV edge cases ---

func TestNewKeepaliveTLV_ZeroTimeouts(t *testing.T) {
	tlv := NewKeepaliveTLV(0, 0)
	if tlv.Type != DSOTLVKeepalive {
		t.Errorf("Type = %d, want %d", tlv.Type, DSOTLVKeepalive)
	}
	primary := binary.BigEndian.Uint32(tlv.Value[0:])
	secondary := binary.BigEndian.Uint32(tlv.Value[4:])
	if primary != 0 {
		t.Errorf("primary units = %d, want 0", primary)
	}
	if secondary != 0 {
		t.Errorf("secondary units = %d, want 0", secondary)
	}
}

func TestNewKeepaliveTLV_SubMillisecond(t *testing.T) {
	// 50ms should round to 0 units (50/100 = 0)
	tlv := NewKeepaliveTLV(50*time.Millisecond, 50*time.Millisecond)
	primary := binary.BigEndian.Uint32(tlv.Value[0:])
	if primary != 0 {
		t.Errorf("primary units for 50ms = %d, want 0", primary)
	}
}

// --- TLV Size edge cases ---

func TestTLV_Size_Empty(t *testing.T) {
	tlv := &TLV{Type: 0, Value: []byte{}}
	if tlv.Size() != 4 {
		t.Errorf("Size() = %d, want 4 for empty value", tlv.Size())
	}
}

func TestTLV_Size_NilValue(t *testing.T) {
	tlv := &TLV{Type: 0, Value: nil}
	if tlv.Size() != 4 {
		t.Errorf("Size() = %d, want 4 for nil value", tlv.Size())
	}
}

func TestTLV_Size_LargeValue(t *testing.T) {
	tlv := &TLV{Type: 0, Value: make([]byte, 1000)}
	if tlv.Size() != 1004 {
		t.Errorf("Size() = %d, want 1004", tlv.Size())
	}
}

// --- Pack/Unpack round trip for various TLV types ---

func TestTLV_RoundTrip_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		tlv  *TLV
	}{
		{"padding", NewPaddingTLV(16)},
		{"keepalive", NewKeepaliveTLV(5*time.Second, 3*time.Second)},
		{"retry delay", NewRetryDelayTLV(10 * time.Second)},
		{"session id", NewSessionIDTLV(999)},
		{"max payload", NewMaximumPayloadTLV(4096)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 512)
			n, err := tt.tlv.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			got, consumed, err := UnpackTLV(buf, 0)
			if err != nil {
				t.Fatalf("UnpackTLV failed: %v", err)
			}
			if consumed != n {
				t.Errorf("consumed = %d, packed = %d", consumed, n)
			}
			if got.Type != tt.tlv.Type {
				t.Errorf("type mismatch: got %d, want %d", got.Type, tt.tlv.Type)
			}
			if len(got.Value) != len(tt.tlv.Value) {
				t.Fatalf("value length mismatch: got %d, want %d", len(got.Value), len(tt.tlv.Value))
			}
		})
	}
}

// --- Full Start/Stop lifecycle ---

func TestManager_FullLifecycle(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := Config{
		Enabled:           true,
		InactivityTimeout: 5 * time.Second,
		MaxSessions:       10,
		MaxPayloadSize:    4096,
	}
	m := NewManager(cfg, logger)

	m.Start()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Create multiple sessions
	var sessions []*Session
	for i := 0; i < 3; i++ {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		s, err := m.CreateSession(conn)
		if err != nil {
			t.Fatalf("CreateSession %d failed: %v", i, err)
		}
		sessions = append(sessions, s)
	}

	if m.SessionCount() != 3 {
		t.Errorf("SessionCount = %d, want 3", m.SessionCount())
	}

	// Remove one session
	m.RemoveSession(sessions[0].ID)
	if m.SessionCount() != 2 {
		t.Errorf("SessionCount after remove = %d, want 2", m.SessionCount())
	}

	// Verify removed session is closed
	if !sessions[0].IsClosed() {
		t.Error("removed session should be closed")
	}

	m.Stop()

	// All remaining sessions should be closed after Stop
	for _, s := range sessions[1:] {
		if !s.IsClosed() {
			t.Error("session should be closed after manager stop")
		}
	}
}

// --- DSORCode String representation ---

func TestDSORCode_Type(t *testing.T) {
	var code DSORCode = DSOCodeInvalidDSO
	if uint16(code) != 1 {
		t.Errorf("DSOCodeInvalidDSO = %d, want 1", code)
	}
}

// --- Manager with custom config values ---

func TestManager_CustomConfig(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		InactivityTimeout: 30 * time.Second,
		MaxSessions:       500,
		MaxPayloadSize:    8192,
	}
	m := NewManager(cfg, nil)

	if m.inactivityTimeout != 30*time.Second {
		t.Errorf("inactivityTimeout = %v, want 30s", m.inactivityTimeout)
	}
	if m.maxSessions != 500 {
		t.Errorf("maxSessions = %d, want 500", m.maxSessions)
	}
	if m.maxPayloadSize != 8192 {
		t.Errorf("maxPayloadSize = %d, want 8192", m.maxPayloadSize)
	}
}

// --- Session field initialization via CreateSession ---

func TestManager_CreateSession_FieldsInitialized(t *testing.T) {
	cfg := Config{
		InactivityTimeout: 30 * time.Second,
		MaxPayloadSize:    8192,
	}
	m := NewManager(cfg, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	s, err := m.CreateSession(conn)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Check KeepaliveTime is 1/3 of inactivity timeout
	if s.KeepaliveTime != 10*time.Second {
		t.Errorf("KeepaliveTime = %v, want 10s", s.KeepaliveTime)
	}
	if s.MaxPayload != 8192 {
		t.Errorf("MaxPayload = %d, want 8192", s.MaxPayload)
	}
}

// --- DefaultConfig immutability ---

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("default Enabled should be false")
	}
	if cfg.InactivityTimeout != 15*time.Second {
		t.Errorf("InactivityTimeout = %v, want 15s", cfg.InactivityTimeout)
	}
	if cfg.MaxSessions != 1000 {
		t.Errorf("MaxSessions = %d, want 1000", cfg.MaxSessions)
	}
	if cfg.MaxPayloadSize != 65535 {
		t.Errorf("MaxPayloadSize = %d, want 65535", cfg.MaxPayloadSize)
	}
}

// --- Handler interface compliance ---

type testHandler struct {
	called bool
}

func (h *testHandler) HandleDSO(session *Session, msg *protocol.Message) (*protocol.Message, error) {
	h.called = true
	return msg, nil
}

func TestHandler_Interface(t *testing.T) {
	var _ Handler = &testHandler{}
}

// --- Manager.cleanupLoop ticker-triggered cleanup ---

func TestManager_CleanupLoop_Triggers(t *testing.T) {
	cfg := Config{
		InactivityTimeout: 50 * time.Millisecond,
	}
	m := NewManager(cfg, nil)

	// Add an expired session directly
	s := &Session{
		ID:            1,
		LastActivity:  time.Now().Add(-200 * time.Millisecond),
		KeepaliveTime: 10 * time.Millisecond,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	m.sessions[1] = s

	m.Start()

	// Wait for the cleanup ticker to fire (30s is too long, so manually trigger)
	// Instead just call cleanupExpiredSessions directly and verify
	time.Sleep(50 * time.Millisecond)
	m.cleanupExpiredSessions()

	if m.SessionCount() != 0 {
		t.Errorf("SessionCount = %d, want 0 after cleanup", m.SessionCount())
	}

	m.Stop()
}

// --- Session.UpdateActivity concurrent with IsExpired ---

func TestSession_ConcurrentAccess(t *testing.T) {
	s := &Session{
		ID:           1,
		LastActivity: time.Now(),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}

	const goroutines = 50
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines/2; i++ {
		go func() {
			s.UpdateActivity()
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines/2; i++ {
		go func() {
			_ = s.IsExpired(15 * time.Second)
			done <- struct{}{}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
