package raft

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

const (
	msgTypeVoteRequest      uint8 = 1
	msgTypeVoteResponse     uint8 = 2
	msgTypeAppendRequest    uint8 = 3
	msgTypeAppendResponse   uint8 = 4
	msgTypeSnapshot         uint8 = 5
	msgTypeSnapshotResponse uint8 = 6
)

// Transport is the network transport interface for Raft RPC.
// All methods accept a context; implementations should respect it for
// cancellation and timeouts. A nil context is treated as context.Background.
type Transport interface {
	// SendRequestVote sends a RequestVote RPC to a peer.
	SendRequestVote(ctx context.Context, peerID NodeID, req VoteRequest) (*VoteResponse, error)
	// SendAppendEntries sends an AppendEntries RPC to a peer.
	SendAppendEntries(ctx context.Context, peerID NodeID, req AppendRequest) (*AppendResponse, error)
	// SendSnapshot sends a snapshot to a peer and returns the follower's
	// acknowledgement. The leader must only advance matchIndex when the
	// response reports Success — a fire-and-forget install would let the
	// leader count an uninstalled snapshot toward quorum.
	SendSnapshot(ctx context.Context, peerID NodeID, req SnapshotRequest) (*SnapshotResponse, error)
}

// RPCHandler handles incoming RPCs.
type RPCHandler interface {
	// HandleVoteRequest handles a RequestVote RPC.
	HandleVoteRequest(req VoteRequest) VoteResponse
	// HandleAppendRequest handles an AppendEntries RPC.
	HandleAppendRequest(req AppendRequest) AppendResponse
	// HandleSnapshotRequest handles a Snapshot RPC and reports whether the
	// snapshot was actually installed.
	HandleSnapshotRequest(req SnapshotRequest) SnapshotResponse
}

// RPCServer is the RPC server that handles incoming connections.
type RPCServer struct {
	listener  net.Listener
	handler   RPCHandler
	conns     map[NodeID]net.Conn
	mu        sync.RWMutex
	stopCh    chan struct{}
	stopOnce  sync.Once // guards Stop() against second-call panic
	wg        sync.WaitGroup
	tlsConfig *tls.Config // nil means plain TCP (dev-only; AEAD must be set in production)
	aead      cipher.AEAD // AEAD for encrypted framing; nil is plaintext
}

// NewRPCServer creates a new RPC server with optional TLS and AEAD encryption.
// tlsConfig is for the TCP listener. aead is for message-level encryption (nil = plaintext).
// In production, either TLS or AEAD (or both) must be configured.
func NewRPCServer(addr string, handler RPCHandler, tlsConfig *tls.Config, aead cipher.AEAD) (*RPCServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	return &RPCServer{
		listener:  listener,
		handler:   handler,
		conns:     make(map[NodeID]net.Conn),
		stopCh:    make(chan struct{}),
		tlsConfig: tlsConfig,
		aead:      aead,
	}, nil
}

// Start starts the RPC server.
func (s *RPCServer) Start() {
	s.wg.Add(1)
	go s.acceptLoop()
}

// Stop stops the RPC server. Idempotent.
func (s *RPCServer) Stop() {
	closed := false
	s.stopOnce.Do(func() {
		close(s.stopCh)
		closed = true
	})
	if !closed {
		return
	}
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		util.Warnf("raft rpc: failed to close listener: %v", err)
	}

	s.mu.Lock()
	for _, conn := range s.conns {
		if err := closeRaftConn(conn); err != nil {
			util.Warnf("raft rpc: failed to close tracked connection: %v", err)
		}
	}
	s.mu.Unlock()

	s.wg.Wait()
}

// acceptLoop accepts incoming connections.
func (s *RPCServer) acceptLoop() {
	defer s.wg.Done()
	// Defense-in-depth (V14): a panic in the accept path must not crash the
	// whole process. The DNS data path already recovers; cluster goroutines did
	// not.
	defer func() {
		if r := recover(); r != nil {
			util.Errorf("raft rpc: panic in acceptLoop: %v", r)
		}
	}()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := setListenerDeadline(s.listener, time.Now().Add(100*time.Millisecond)); err != nil {
			util.Warnf("raft rpc: failed to set listener deadline: %v", err)
			return
		}

		conn, err := s.listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}

		// Store connection keyed by remote address until we learn the NodeID
		// from the first message (VULN-049: was using "" which is incorrect)
		addr := conn.RemoteAddr().String()
		s.mu.Lock()
		s.conns[NodeID(addr)] = conn
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConn(conn, NodeID(addr))
	}
}

type listenerWithDeadline interface {
	SetDeadline(time.Time) error
}

func setListenerDeadline(listener net.Listener, deadline time.Time) error {
	if listener == nil {
		return nil
	}
	if deadlineListener, ok := listener.(listenerWithDeadline); ok {
		return deadlineListener.SetDeadline(deadline)
	}
	return nil
}

// handleConn handles a single connection.
func (s *RPCServer) handleConn(conn net.Conn, nodeID NodeID) {
	// Recover from any panic decoding attacker-controlled bytes so a single
	// malformed/malicious connection tears down only itself, not the process
	// (V14). Registered first so it runs after the cleanup defers below.
	defer func() {
		if r := recover(); r != nil {
			util.Errorf("raft rpc: panic handling connection from %s: %v", nodeID, r)
		}
	}()
	defer s.wg.Done()
	defer func() {
		if err := closeRaftConn(conn); err != nil {
			util.Warnf("raft rpc: failed to close connection: %v", err)
		}
	}()
	defer func() {
		s.mu.Lock()
		delete(s.conns, nodeID)
		s.mu.Unlock()
	}()

	fw := newFrameWriter(conn, s.aead)
	fr := newFrameReader(conn, s.aead)

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}

		// Read the frame's type + raw payload, THEN decode into the struct the
		// type calls for. The previous code decoded every frame into a whole
		// voteReqBuf, which decodeNative doesn't handle — so the server errored
		// on the first frame and dropped the connection. (Masked because no
		// test exercised the real TCP path.)
		msgType, payload, err := fr.readFrameBytes()
		if err != nil {
			return
		}

		switch msgType {
		case msgTypeVoteRequest:
			var req VoteRequest
			if err := decodeNative(&req, payload); err != nil {
				return
			}
			resp := s.handler.HandleVoteRequest(req)
			if err := fw.writeFramed(msgTypeVoteResponse, resp); err != nil {
				return
			}
		case msgTypeAppendRequest:
			var req AppendRequest
			if err := decodeNative(&req, payload); err != nil {
				return
			}
			resp := s.handler.HandleAppendRequest(req)
			if err := fw.writeFramed(msgTypeAppendResponse, resp); err != nil {
				return
			}
		case msgTypeSnapshot:
			var req SnapshotRequest
			if err := decodeNative(&req, payload); err != nil {
				return
			}
			resp := s.handler.HandleSnapshotRequest(req)
			if err := fw.writeFramed(msgTypeSnapshotResponse, resp); err != nil {
				return
			}
		}
	}
}

// writeMessage writes a message with type prefix.
func (s *RPCServer) writeMessage(w io.Writer, msgType uint8, msg any) error {
	fw := newFrameWriter(w, s.aead)
	return fw.writeFramed(msgType, msg)
}

// readMessage reads a message.
func (s *RPCServer) readMessage(r io.Reader, msg any) error {
	fr := newFrameReader(r, s.aead)
	_, err := fr.readFramed(msg)
	return err
}

// writeRPCMessage is the low-level frame writer used by TCPTransport. It uses
// the AEAD when available (shared secret derived from the cluster key). The
// matching read side is frameReader.readFramed, called directly by the
// transport's exchange().
func writeRPCMessage(w io.Writer, msgType uint8, msg any, aead cipher.AEAD) error {
	fw := newFrameWriter(w, aead)
	return fw.writeFramed(msgType, msg)
}

// TCPTransport is a TCP-based Raft transport.
type TCPTransport struct {
	dialTimeout time.Duration
	conns       map[NodeID]net.Conn
	peerAddrs   map[NodeID]string
	peerLocks   map[NodeID]*sync.Mutex // serializes each peer's request/response exchange
	mu          sync.RWMutex
	tlsConfig   *tls.Config // nil means plain TCP
	aead        cipher.AEAD // AEAD for encrypted framing; nil is plaintext
}

// NewTCPTransport creates a new TCP transport with optional TLS and AEAD.
// Pass nil for both to use plain TCP (for development only; insecure).
func NewTCPTransport(tlsConfig *tls.Config, aead cipher.AEAD) *TCPTransport {
	return &TCPTransport{
		dialTimeout: 5 * time.Second,
		conns:       make(map[NodeID]net.Conn),
		peerAddrs:   make(map[NodeID]string),
		peerLocks:   make(map[NodeID]*sync.Mutex),
		tlsConfig:   tlsConfig,
		aead:        aead,
	}
}

// peerLock returns the per-peer mutex that serializes a full request/response
// exchange. A single TCP connection per peer is shared by the heartbeat
// ticker and replication goroutines; without this lock their writes and reads
// would interleave on the wire and corrupt the framing.
func (t *TCPTransport) peerLock(peerID NodeID) *sync.Mutex {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.peerLocks[peerID]
	if !ok {
		l = &sync.Mutex{}
		t.peerLocks[peerID] = l
	}
	return l
}

// dropConn closes and forgets a connection (only if it's still the cached one)
// so the next call redials. Called whenever an exchange errors — a half-read
// response would otherwise desync every subsequent RPC on that conn.
func (t *TCPTransport) dropConn(peerID NodeID, conn net.Conn) {
	t.mu.Lock()
	if t.conns[peerID] == conn {
		delete(t.conns, peerID)
	}
	t.mu.Unlock()
	if err := closeRaftConn(conn); err != nil {
		util.Warnf("raft rpc: failed to close dropped connection for peer %s: %v", peerID, err)
	}
}

// exchange performs one request/response RPC over the peer's connection,
// serialized per peer. wantType validates the response frame's type; pass 0
// with a nil resp for one-way messages (snapshot). On any error the connection
// is dropped so the next call starts clean.
func (t *TCPTransport) exchange(ctx context.Context, peerID NodeID, reqType uint8, req any, wantType uint8, resp any) error {
	lock := t.peerLock(peerID)
	lock.Lock()
	defer lock.Unlock()

	conn, err := t.getConn(peerID)
	if err != nil {
		return err
	}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				t.dropConn(peerID, conn)
				return fmt.Errorf("set deadline for peer %s: %w", peerID, err)
			}
		}
	}

	if err := writeRPCMessage(conn, reqType, req, t.aead); err != nil {
		t.dropConn(peerID, conn)
		return err
	}
	if resp == nil {
		return nil // one-way message, no response expected
	}

	fr := newFrameReader(conn, t.aead)
	respType, err := fr.readFramed(resp)
	if err != nil {
		t.dropConn(peerID, conn)
		return err
	}
	if respType != wantType {
		t.dropConn(peerID, conn)
		return fmt.Errorf("unexpected response type %d (want %d)", respType, wantType)
	}
	return nil
}

// SendRequestVote sends a RequestVote RPC and reads the single response frame.
// (The earlier code read a bare type byte AND a frame — double-reading the
// type and corrupting every TCP response, so real multi-node RPC never
// actually worked; the exchange helper now does one matched read.)
func (t *TCPTransport) SendRequestVote(ctx context.Context, peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	var resp VoteResponse
	if err := t.exchange(ctx, peerID, msgTypeVoteRequest, req, msgTypeVoteResponse, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SendAppendEntries sends an AppendEntries RPC and reads the response frame.
func (t *TCPTransport) SendAppendEntries(ctx context.Context, peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	var resp AppendResponse
	if err := t.exchange(ctx, peerID, msgTypeAppendRequest, req, msgTypeAppendResponse, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SendSnapshot sends a snapshot to a peer and reads the install
// acknowledgement frame.
func (t *TCPTransport) SendSnapshot(ctx context.Context, peerID NodeID, req SnapshotRequest) (*SnapshotResponse, error) {
	var resp SnapshotResponse
	if err := t.exchange(ctx, peerID, msgTypeSnapshot, req, msgTypeSnapshotResponse, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// getConn gets or creates a connection to a peer.
//
// Two goroutines (e.g., a heartbeat ticker and a follower-replication
// call) can both reach this with no existing conn entry: both
// observe ok=false under RLock, both dial, both then take the
// write lock and store — the second store overwrites the first,
// orphaning the earlier dialed conn (and any background goroutine
// that may already be reading from it on the peer side once Raft
// starts using the new one). Re-check under the write lock and,
// if another goroutine raced ahead of us, close our duplicate and
// return the winner.
func (t *TCPTransport) getConn(peerID NodeID) (net.Conn, error) {
	// Check for existing connection
	t.mu.RLock()
	conn, ok := t.conns[peerID]
	addr, addrOk := t.peerAddrs[peerID]
	t.mu.RUnlock()

	if ok && conn != nil {
		return conn, nil
	}

	if !addrOk || addr == "" {
		return nil, fmt.Errorf("peer address unknown for %s", peerID)
	}

	// Dial new connection
	dialConn, err := t.dial(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// Store connection — but re-check under the write lock to handle
	// the race where another goroutine dialed and stored concurrently.
	t.mu.Lock()
	if existing, found := t.conns[peerID]; found && existing != nil {
		// Lost the race. Close our duplicate and return the winner so
		// the rest of the transport doesn't see two live conns to one peer.
		t.mu.Unlock()
		if err := closeRaftConn(dialConn); err != nil {
			util.Warnf("raft rpc: failed to close duplicate connection for peer %s: %v", peerID, err)
		}
		return existing, nil
	}
	t.conns[peerID] = dialConn
	t.mu.Unlock()

	return dialConn, nil
}

func (t *TCPTransport) dial(addr string) (net.Conn, error) {
	if t.tlsConfig != nil {
		dialer := &net.Dialer{Timeout: t.dialTimeout}
		return tls.DialWithDialer(dialer, "tcp", addr, t.tlsConfig)
	}
	return net.DialTimeout("tcp", addr, t.dialTimeout)
}

func closeRaftConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	err := conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// SetPeerAddr sets the address for a peer.
func (t *TCPTransport) SetPeerAddr(peerID NodeID, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peerAddrs[peerID] = addr
}

// PeerAddrs returns a copy of the configured peer ID → RPC address map.
func (t *TCPTransport) PeerAddrs() map[NodeID]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[NodeID]string, len(t.peerAddrs))
	for id, addr := range t.peerAddrs {
		out[id] = addr
	}
	return out
}

// Stats contains transport statistics.
type Stats struct {
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
	MessagesSent  atomic.Uint64
}

// InMemoryHub manages in-memory connections between Raft nodes for testing.
// It acts as a switch: each node's InMemoryTransport routes to the peer's
// registered handler. This lets tests run multi-node Raft entirely in-memory,
// with the race detector enabled.
type InMemoryHub struct {
	mu       sync.RWMutex
	handlers map[NodeID]RPCHandler
}

// NewInMemoryHub creates an empty hub. Register each node's RPCHandler
// via AddNode before starting the test.
func NewInMemoryHub() *InMemoryHub {
	return &InMemoryHub{handlers: make(map[NodeID]RPCHandler)}
}

// AddNode registers a peer's RPCHandler. All transports created by this hub
// will route to the registered handler when sending to that peerID.
func (h *InMemoryHub) AddNode(id NodeID, handler RPCHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[id] = handler
}

// NewTransport creates a Transport that routes to other nodes in the hub.
// selfID is this node's own ID (so we can skip routing to ourselves).
func (h *InMemoryHub) NewTransport(selfID NodeID) *InMemoryTransport {
	return &InMemoryTransport{hub: h, selfID: selfID}
}

// InMemoryTransport implements Transport for in-memory multi-node testing.
// It delegates to the peer handler registered with the hub. If the hub
// has no handler for the target peer, all calls return ErrPeerNotFound.
type InMemoryTransport struct {
	hub    *InMemoryHub
	selfID NodeID
}

// ErrPeerNotFound is returned by InMemoryTransport when the target peer
// has not registered with the hub.
var ErrPeerNotFound = fmt.Errorf("peer not found in in-memory hub")

func (t *InMemoryTransport) getHandler(peerID NodeID) (RPCHandler, error) {
	if peerID == t.selfID {
		return nil, fmt.Errorf("InMemoryTransport: self-routing not supported")
	}
	t.hub.mu.RLock()
	defer t.hub.mu.RUnlock()
	h, ok := t.hub.handlers[peerID]
	if !ok {
		return nil, ErrPeerNotFound
	}
	return h, nil
}

func (t *InMemoryTransport) SendRequestVote(ctx context.Context, peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	h, err := t.getHandler(peerID)
	if err != nil {
		return nil, err
	}
	// Handler blocks the caller; run under a goroutine so the transport
	// call isancellable via ctx.
	type result struct{ resp VoteResponse }
	ch := make(chan result, 1)
	go func() {
		ch <- result{resp: h.HandleVoteRequest(req)}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return &r.resp, nil
	}
}

func (t *InMemoryTransport) SendAppendEntries(ctx context.Context, peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	h, err := t.getHandler(peerID)
	if err != nil {
		return nil, err
	}
	type result struct{ resp AppendResponse }
	ch := make(chan result, 1)
	go func() {
		ch <- result{resp: h.HandleAppendRequest(req)}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return &r.resp, nil
	}
}

func (t *InMemoryTransport) SendSnapshot(ctx context.Context, peerID NodeID, req SnapshotRequest) (*SnapshotResponse, error) {
	h, err := t.getHandler(peerID)
	if err != nil {
		return nil, err
	}
	type result struct{ resp SnapshotResponse }
	ch := make(chan result, 1)
	go func() {
		ch <- result{resp: h.HandleSnapshotRequest(req)}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return &r.resp, nil
	}
}
