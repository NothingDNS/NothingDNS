package quic

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// testTLSConfig returns a minimal TLS config for testing.
// We only need the struct to exist; the DoQ server stores it but
// these unit tests never perform a real TLS handshake.
func testTLSConfig() *tls.Config {
	return &tls.Config{
		NextProtos: []string{"doq"},
	}
}

// =================== Constructor Tests ===================

func TestNewDoQServer(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if srv == nil {
		t.Fatal("NewDoQServer returned nil")
	}
	if srv.addr != "127.0.0.1:0" {
		t.Errorf("addr = %q, want %q", srv.addr, "127.0.0.1:0")
	}
	if srv.handler == nil {
		t.Error("handler should not be nil")
	}
	if srv.tlsConfig == nil {
		t.Error("tlsConfig should not be nil")
	}
	if srv.config == nil {
		t.Error("config should not be nil (default should be applied)")
	}
	if srv.conns == nil {
		t.Error("conns map should be initialized")
	}
	if srv.connSem == nil {
		t.Error("connSem should be initialized")
	}
	if cap(srv.connSem) != DoQMaxConnections {
		t.Errorf("connSem capacity = %d, want %d", cap(srv.connSem), DoQMaxConnections)
	}
	if srv.ctx == nil {
		t.Error("ctx should not be nil")
	}
	if srv.cancel == nil {
		t.Error("cancel should not be nil")
	}
}

func TestNewDoQServerWithConfig(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	cfg := &Config{
		TransportParams: DefaultTransportParams(),
		MaxStreams:      50,
		MaxStreamData:   131072,
		MaxData:         524288,
	}

	srv := NewDoQServerWithConfig("127.0.0.1:8853", handler, testTLSConfig(), cfg)

	if srv == nil {
		t.Fatal("NewDoQServerWithConfig returned nil")
	}
	if srv.config != cfg {
		t.Error("custom config was not applied")
	}
	if srv.config.MaxStreams != 50 {
		t.Errorf("MaxStreams = %d, want 50", srv.config.MaxStreams)
	}
}

func TestNewDoQServerWithNilConfig(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServerWithConfig("127.0.0.1:0", handler, testTLSConfig(), nil)

	if srv == nil {
		t.Fatal("NewDoQServerWithConfig returned nil with nil config")
	}
	if srv.config == nil {
		t.Fatal("nil config should be replaced with defaults")
	}
	if srv.config.MaxStreams != DefaultInitialMaxStreamsBidi {
		t.Errorf("MaxStreams = %d, want %d (default)", srv.config.MaxStreams, DefaultInitialMaxStreamsBidi)
	}
}

// =================== Listen / Stop Tests ===================

func TestDoQServerListenAndStop(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after Listen")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("Addr() is %T, want *net.UDPAddr", addr)
	}
	if udpAddr.Port == 0 {
		t.Error("expected a non-zero port after binding to :0")
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestDoQServerListenWithConn(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	srv.ListenWithConn(conn)

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after ListenWithConn")
	}
}

func TestDoQServerStopIdempotent(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// First stop should succeed.
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Second stop should not panic. The underlying conn is already closed,
	// so an error is acceptable but a panic is not.
	_ = srv.Stop()
}

func TestDoQServerStopWithoutListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Stop without Listen — conn is nil, should return nil.
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop without Listen: %v", err)
	}
}

func TestDoQServerListenInvalidAddr(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("not-valid-address-!!!", handler, testTLSConfig())

	if err := srv.Listen(); err == nil {
		t.Error("expected error for invalid address")
		srv.Stop()
	}
}

func TestDoQServerAddrBeforeListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if addr := srv.Addr(); addr != nil {
		t.Errorf("Addr() before Listen should be nil, got %v", addr)
	}
}

// =================== Metrics / Stats Tests ===================

func TestDoQServerStatsInitial(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	stats := srv.Stats()

	if stats.ConnectionsAccepted != 0 {
		t.Errorf("ConnectionsAccepted = %d, want 0", stats.ConnectionsAccepted)
	}
	if stats.ConnectionsClosed != 0 {
		t.Errorf("ConnectionsClosed = %d, want 0", stats.ConnectionsClosed)
	}
	if stats.QueriesReceived != 0 {
		t.Errorf("QueriesReceived = %d, want 0", stats.QueriesReceived)
	}
	if stats.QueriesResponded != 0 {
		t.Errorf("QueriesResponded = %d, want 0", stats.QueriesResponded)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	if stats.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", stats.ActiveConnections)
	}
}

func TestDoQServerStatsCounters(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Manually bump atomic counters and verify Stats reflects them.
	atomic.AddUint64(&srv.connectionsAccepted, 10)
	atomic.AddUint64(&srv.connectionsClosed, 3)
	atomic.AddUint64(&srv.queriesReceived, 42)
	atomic.AddUint64(&srv.queriesResponded, 41)
	atomic.AddUint64(&srv.errors, 5)

	stats := srv.Stats()

	if stats.ConnectionsAccepted != 10 {
		t.Errorf("ConnectionsAccepted = %d, want 10", stats.ConnectionsAccepted)
	}
	if stats.ConnectionsClosed != 3 {
		t.Errorf("ConnectionsClosed = %d, want 3", stats.ConnectionsClosed)
	}
	if stats.QueriesReceived != 42 {
		t.Errorf("QueriesReceived = %d, want 42", stats.QueriesReceived)
	}
	if stats.QueriesResponded != 41 {
		t.Errorf("QueriesResponded = %d, want 41", stats.QueriesResponded)
	}
	if stats.Errors != 5 {
		t.Errorf("Errors = %d, want 5", stats.Errors)
	}
}

func TestDoQServerStatsActiveConnections(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Inject synthetic connections into the map.
	cid1 := ConnectionID{0x01, 0x02, 0x03, 0x04}
	cid2 := ConnectionID{0x05, 0x06, 0x07, 0x08}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	srv.connsMu.Lock()
	srv.conns[toKey(cid1)] = &doqConn{scID: cid1, ctx: ctx1, cancel: cancel1}
	srv.conns[toKey(cid2)] = &doqConn{scID: cid2, ctx: ctx2, cancel: cancel2}
	srv.connsMu.Unlock()

	stats := srv.Stats()
	if stats.ActiveConnections != 2 {
		t.Errorf("ActiveConnections = %d, want 2", stats.ActiveConnections)
	}

	// Remove one.
	srv.connsMu.Lock()
	delete(srv.conns, toKey(cid1))
	srv.connsMu.Unlock()

	stats = srv.Stats()
	if stats.ActiveConnections != 1 {
		t.Errorf("ActiveConnections after removal = %d, want 1", stats.ActiveConnections)
	}
}

// =================== Connection Tracking Tests ===================

func TestDoQServerConnectionTracking(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	cid := ConnectionID{0xaa, 0xbb, 0xcc, 0xdd}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dc := &doqConn{
		scID:     cid,
		ctx:      ctx,
		cancel:   cancel,
		streamCh: make(chan uint64, 64),
	}

	// Add
	srv.connsMu.Lock()
	srv.conns[toKey(cid)] = dc
	srv.connsMu.Unlock()

	srv.connsMu.RLock()
	_, exists := srv.conns[toKey(cid)]
	srv.connsMu.RUnlock()
	if !exists {
		t.Error("connection should exist after adding")
	}

	// Remove via removeConn
	srv.removeConn(dc)

	srv.connsMu.RLock()
	_, exists = srv.conns[toKey(cid)]
	srv.connsMu.RUnlock()
	if exists {
		t.Error("connection should not exist after removeConn")
	}
}

func TestCidKeyRoundTrip(t *testing.T) {
	cid := ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	key := toKey(cid)

	// Same bytes should produce the same key.
	cid2 := ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	key2 := toKey(cid2)
	if key != key2 {
		t.Errorf("identical CIDs should map to the same key")
	}

	// Different bytes should produce different keys.
	cid3 := ConnectionID{0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	key3 := toKey(cid3)
	if key == key3 {
		t.Errorf("different CIDs should map to different keys")
	}
}

// =================== Idle Reaper Tests ===================

func TestDoQServerReapIdleConnections(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// We need to set up the semaphore to absorb the tokens released by closeConnection.
	// Fill sem tokens for each connection we inject.
	srv.connSem <- struct{}{}
	srv.connSem <- struct{}{}

	// Create two connections: one alive, one cancelled.
	cidAlive := ConnectionID{0x01, 0x02, 0x03, 0x04}
	ctxAlive, cancelAlive := context.WithCancel(srv.ctx)
	defer cancelAlive()

	cidDead := ConnectionID{0x05, 0x06, 0x07, 0x08}
	ctxDead, cancelDead := context.WithCancel(srv.ctx)

	// Cancel the dead one immediately.
	cancelDead()

	// Build minimal ServerConnections so closeConnection can call sc.Close().
	scAlive := NewServerConnection(testTLSConfig(), cidAlive, &net.UDPAddr{}, &net.UDPAddr{}, nil)
	scDead := NewServerConnection(testTLSConfig(), cidDead, &net.UDPAddr{}, &net.UDPAddr{}, nil)

	dcAlive := &doqConn{
		sc:       scAlive,
		scID:     cidAlive,
		ctx:      ctxAlive,
		cancel:   cancelAlive,
		streamCh: make(chan uint64, 64),
	}
	dcDead := &doqConn{
		sc:       scDead,
		scID:     cidDead,
		ctx:      ctxDead,
		cancel:   cancelDead,
		streamCh: make(chan uint64, 64),
	}

	srv.connsMu.Lock()
	srv.conns[toKey(cidAlive)] = dcAlive
	srv.conns[toKey(cidDead)] = dcDead
	srv.connsMu.Unlock()

	// Run the reaper.
	srv.reapIdleConnections()

	srv.connsMu.RLock()
	_, aliveExists := srv.conns[toKey(cidAlive)]
	_, deadExists := srv.conns[toKey(cidDead)]
	srv.connsMu.RUnlock()

	if !aliveExists {
		t.Error("alive connection should not be reaped")
	}
	if deadExists {
		t.Error("dead connection should be reaped")
	}

	// Verify the connectionsClosed counter incremented.
	closed := atomic.LoadUint64(&srv.connectionsClosed)
	if closed != 1 {
		t.Errorf("connectionsClosed = %d, want 1", closed)
	}
}

func TestDoQServerReapNoConnections(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Should not panic when there are no connections.
	srv.reapIdleConnections()

	stats := srv.Stats()
	if stats.ConnectionsClosed != 0 {
		t.Errorf("ConnectionsClosed = %d, want 0", stats.ConnectionsClosed)
	}
}

// =================== Handler Adapter Tests ===================

func TestDoQHandlerFunc(t *testing.T) {
	var called bool
	var receivedQuery []byte
	var receivedStream *Stream

	fn := DoQHandlerFunc(func(s *Stream, q []byte) {
		called = true
		receivedStream = s
		receivedQuery = q
	})

	stream := &Stream{id: 42}
	query := []byte{0x01, 0x02, 0x03}
	fn.ServeDoQ(stream, query)

	if !called {
		t.Error("handler function was not called")
	}
	if receivedStream != stream {
		t.Error("handler received wrong stream")
	}
	if len(receivedQuery) != 3 || receivedQuery[0] != 0x01 {
		t.Errorf("handler received wrong query: %v", receivedQuery)
	}
}

// =================== Packet Handling Tests ===================

func TestDoQServerHandlePacketEmpty(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Empty packet should be silently dropped (no panic, no error counter bump).
	srv.handlePacket(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	srv.handlePacket([]byte{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	stats := srv.Stats()
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0 for empty packets", stats.Errors)
	}
}

func TestDoQServerHandlePacketInvalidLongHeader(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// A packet with the long header bit set but too short to parse.
	data := []byte{0xC0, 0xFF}
	srv.handlePacket(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	stats := srv.Stats()
	if stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1 for invalid long header", stats.Errors)
	}
}

func TestDoQServerHandlePacketWrongVersion(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Build a long header with a non-V1 version.
	hdr := &LongHeader{
		Type:       PacketTypeInitial,
		Version:    0x00000002, // Not Version1
		DestConnID: ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		SrcConnID:  ConnectionID{},
	}
	pkt, err := BuildLongHeader(hdr, 0, 1)
	if err != nil {
		t.Fatalf("BuildLongHeader: %v", err)
	}

	srv.handlePacket(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	// Wrong version is silently ignored (not counted as an error).
	stats := srv.Stats()
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0 for wrong version", stats.Errors)
	}
}

func TestDoQServerHandleShortHeaderNoConnection(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Short header packet with no matching connection should be silently dropped.
	data := []byte{
		0x40,                   // Short header
		0x01, 0x02, 0x03, 0x04, // DCID (4 bytes)
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // Payload
	}
	srv.handlePacket(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	stats := srv.Stats()
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0 for unmatched short header", stats.Errors)
	}
}

func TestDoQServerRouteToConnectionMissing(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Routing to a non-existent connection should not panic.
	cid := ConnectionID{0xde, 0xad, 0xbe, 0xef}
	srv.routeToConnection(cid)
}

func TestDoQServerRouteToConnectionExists(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	cid := ConnectionID{0xde, 0xad, 0xbe, 0xef}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv.connsMu.Lock()
	srv.conns[toKey(cid)] = &doqConn{scID: cid, ctx: ctx, cancel: cancel}
	srv.connsMu.Unlock()

	// Should not panic; this is a routing path only.
	srv.routeToConnection(cid)
}

// =================== Connection Semaphore Tests ===================

func TestDoQServerConnectionSemaphoreCapacity(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if cap(srv.connSem) != DoQMaxConnections {
		t.Errorf("connSem capacity = %d, want %d", cap(srv.connSem), DoQMaxConnections)
	}

	// Verify we can acquire and release a semaphore token.
	select {
	case srv.connSem <- struct{}{}:
		// acquired
	default:
		t.Fatal("failed to acquire connection semaphore token")
	}

	select {
	case <-srv.connSem:
		// released
	default:
		t.Fatal("failed to release connection semaphore token")
	}
}

// =================== Serve Without Listen Tests ===================

func TestDoQServerServeWithoutListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	// Serve without a prior Listen should return an error immediately.
	err := srv.Serve()
	if err == nil {
		t.Error("expected error from Serve() without Listen()")
	}
}

// =================== Serve Lifecycle Tests ===================

func TestDoQServerServeAndStop(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve()
	}()

	// Give the goroutines a moment to start.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Stop")
	}
}

// =================== DoQServerStats Struct Tests ===================

func TestDoQServerStatsZeroValue(t *testing.T) {
	var stats DoQServerStats

	if stats.ConnectionsAccepted != 0 ||
		stats.ConnectionsClosed != 0 ||
		stats.QueriesReceived != 0 ||
		stats.QueriesResponded != 0 ||
		stats.Errors != 0 ||
		stats.ActiveConnections != 0 {
		t.Error("zero-value DoQServerStats should have all zeros")
	}
}

// =================== DoQ Constants Tests ===================

func TestDoQConstants(t *testing.T) {
	if DefaultDoQPort != 853 {
		t.Errorf("DefaultDoQPort = %d, want 853", DefaultDoQPort)
	}
	if DoQMaxMessageSize != 65535 {
		t.Errorf("DoQMaxMessageSize = %d, want 65535", DoQMaxMessageSize)
	}
	if DoQStreamIdleTimeout != 30*time.Second {
		t.Errorf("DoQStreamIdleTimeout = %v, want 30s", DoQStreamIdleTimeout)
	}
	if DoQConnectionIdleTimeout != 60*time.Second {
		t.Errorf("DoQConnectionIdleTimeout = %v, want 60s", DoQConnectionIdleTimeout)
	}
	if DoQMaxConnections != 500 {
		t.Errorf("DoQMaxConnections = %d, want 500", DoQMaxConnections)
	}
	if DoQMaxStreamsPerConnection != 100 {
		t.Errorf("DoQMaxStreamsPerConnection = %d, want 100", DoQMaxStreamsPerConnection)
	}
}

// =================== sendCryptoPacket Tests ===================

func TestDoQServerSendCryptoPacketNilConn(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	cid := ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := NewServerConnection(testTLSConfig(), cid, &net.UDPAddr{}, &net.UDPAddr{}, nil)
	dc := &doqConn{sc: sc, scID: cid, ctx: ctx, cancel: cancel}

	// srv.conn is nil; sendCryptoPacket should return without panic.
	srv.sendCryptoPacket(dc, tls.QUICEncryptionLevelInitial, []byte{0x01, 0x02})
}

func TestDoQServerSendCryptoPacketCancelledCtx(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Stop()

	cid := ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	sc := NewServerConnection(testTLSConfig(), cid, &net.UDPAddr{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, nil)
	dc := &doqConn{sc: sc, scID: cid, ctx: ctx, cancel: cancel}

	// Should return early due to cancelled context, no panic.
	srv.sendCryptoPacket(dc, tls.QUICEncryptionLevelHandshake, []byte{0x01})
}

func TestDoQServerSendCryptoPacketUnsupportedLevel(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Stop()

	cid := ConnectionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := NewServerConnection(testTLSConfig(), cid, &net.UDPAddr{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, nil)
	dc := &doqConn{sc: sc, scID: cid, ctx: ctx, cancel: cancel}

	// Application level (tls.QUICEncryptionLevelApplication) hits the default
	// case in the switch, so nothing is sent. Should not panic.
	srv.sendCryptoPacket(dc, tls.QUICEncryptionLevelApplication, []byte{0x01})
}

// =================== handleInitialPacket Connection Limit Test ===================

func TestDoQServerInitialPacketConnectionLimit(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Stop()

	// Exhaust the connection semaphore.
	for i := 0; i < DoQMaxConnections; i++ {
		srv.connSem <- struct{}{}
	}

	// Build a valid Initial packet.
	cid := ConnectionID{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	hdr := &LongHeader{
		Type:       PacketTypeInitial,
		Version:    Version1,
		DestConnID: cid,
		SrcConnID:  ConnectionID{},
		Payload:    []byte{0x00},
	}

	// handleInitialPacket should fail to acquire the semaphore and bump errors.
	srv.handleInitialPacket(hdr, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	stats := srv.Stats()
	if stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1 when connection limit is reached", stats.Errors)
	}
	if stats.ConnectionsAccepted != 0 {
		t.Errorf("ConnectionsAccepted = %d, want 0", stats.ConnectionsAccepted)
	}

	// Drain the semaphore to clean up.
	for i := 0; i < DoQMaxConnections; i++ {
		<-srv.connSem
	}
}

// =================== newDoQConnection Test ===================

func TestDoQServerNewDoQConnection(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, testTLSConfig())

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Stop()

	cid := ConnectionID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5353}

	dc, err := srv.newDoQConnection(cid, remoteAddr, "10.0.0.1")
	if err != nil {
		t.Fatalf("newDoQConnection: %v", err)
	}
	if dc == nil {
		t.Fatal("newDoQConnection returned nil")
	}
	if dc.sc == nil {
		t.Error("ServerConnection should not be nil")
	}
	if !dc.scID.Equal(cid) {
		t.Errorf("scID = %v, want %v", dc.scID, cid)
	}
	if dc.ctx == nil {
		t.Error("ctx should not be nil")
	}
	if dc.cancel == nil {
		t.Error("cancel should not be nil")
	}
	if dc.streamCh == nil {
		t.Error("streamCh should not be nil")
	}

	// Verify it was added to the conns map.
	srv.connsMu.RLock()
	_, exists := srv.conns[toKey(cid)]
	srv.connsMu.RUnlock()
	if !exists {
		t.Error("connection should be in the conns map")
	}

	// Verify connectionsAccepted was incremented.
	accepted := atomic.LoadUint64(&srv.connectionsAccepted)
	if accepted != 1 {
		t.Errorf("connectionsAccepted = %d, want 1", accepted)
	}
}
