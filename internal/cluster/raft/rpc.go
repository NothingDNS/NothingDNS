package raft

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	msgTypeVoteRequest    uint8 = 1
	msgTypeVoteResponse   uint8 = 2
	msgTypeAppendRequest  uint8 = 3
	msgTypeAppendResponse uint8 = 4
	msgTypeSnapshot       uint8 = 5
)

// Transport is the network transport interface for Raft RPC.
type Transport interface {
	// SendRequestVote sends a RequestVote RPC to a peer.
	SendRequestVote(peerID NodeID, req VoteRequest) (*VoteResponse, error)
	// SendAppendEntries sends an AppendEntries RPC to a peer.
	SendAppendEntries(peerID NodeID, req AppendRequest) (*AppendResponse, error)
	// SendSnapshot sends a snapshot to a peer.
	SendSnapshot(peerID NodeID, req SnapshotRequest) error
}

// RPCHandler handles incoming RPCs.
type RPCHandler interface {
	// HandleVoteRequest handles a RequestVote RPC.
	HandleVoteRequest(req VoteRequest) VoteResponse
	// HandleAppendRequest handles an AppendEntries RPC.
	HandleAppendRequest(req AppendRequest) AppendResponse
	// HandleSnapshotRequest handles a Snapshot RPC.
	HandleSnapshotRequest(req SnapshotRequest)
}

// RPCServer is the RPC server that handles incoming connections.
type RPCServer struct {
	listener  net.Listener
	handler   RPCHandler
	conns     map[NodeID]net.Conn
	mu        sync.RWMutex
	stopCh    chan struct{}
	wg        sync.WaitGroup
	tlsConfig *tls.Config // nil means plain TCP
}

// NewRPCServer creates a new RPC server with optional TLS.
// Pass nil for tlsConfig to use plain TCP (for development only).
func NewRPCServer(addr string, handler RPCHandler, tlsConfig *tls.Config) (*RPCServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	return &RPCServer{
		listener:  listener,
		handler:  handler,
		conns:    make(map[NodeID]net.Conn),
		stopCh:   make(chan struct{}),
		tlsConfig: tlsConfig,
	}, nil
}

// Start starts the RPC server.
func (s *RPCServer) Start() {
	s.wg.Add(1)
	go s.acceptLoop()
}

// Stop stops the RPC server.
func (s *RPCServer) Stop() {
	close(s.stopCh)
	s.listener.Close()

	s.mu.Lock()
	for _, conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
}

// acceptLoop accepts incoming connections.
func (s *RPCServer) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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

// handleConn handles a single connection.
func (s *RPCServer) handleConn(conn net.Conn, nodeID NodeID) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, nodeID)
		s.mu.Unlock()
	}()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}

		// Read message type
		var msgType uint8
		if err := binary.Read(conn, binary.BigEndian, &msgType); err != nil {
			return
		}

		switch msgType {
		case msgTypeVoteRequest:
			var req VoteRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			resp := s.handler.HandleVoteRequest(req)
			if err := s.writeMessage(conn, msgTypeVoteResponse, resp); err != nil {
				return
			}
		case msgTypeAppendRequest:
			var req AppendRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			resp := s.handler.HandleAppendRequest(req)
			if err := s.writeMessage(conn, msgTypeAppendResponse, resp); err != nil {
				return
			}
		case msgTypeSnapshot:
			var req SnapshotRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			s.handler.HandleSnapshotRequest(req)
		}
	}
}

// writeMessage writes a message with type prefix.
func (s *RPCServer) writeMessage(w io.Writer, msgType uint8, msg any) error {
	return writeRPCMessage(w, msgType, msg)
}

// readMessage reads a message.
func (s *RPCServer) readMessage(r io.Reader, msg any) error {
	return readRPCMessage(r, msg)
}

func writeRPCMessage(w io.Writer, msgType uint8, msg any) error {
	if err := binary.Write(w, binary.BigEndian, msgType); err != nil {
		return err
	}
	return gob.NewEncoder(w).Encode(msg)
}

// maxRPCMessageBytes caps a single gob-framed Raft RPC payload. encoding/gob
// is documented as unsafe against untrusted input — a crafted slice/map length
// prefix makes the decoder pre-allocate before reading, so without this cap a
// single attacker-controlled connection can OOM-kill the leader (VULN-001).
// The cap is deliberately generous for large AppendEntries batches but still
// bounds per-message allocation.
const maxRPCMessageBytes = 16 * 1024 * 1024 // 16 MiB

func readRPCMessage(r io.Reader, msg any) error {
	return gob.NewDecoder(io.LimitReader(r, maxRPCMessageBytes)).Decode(msg)
}

// TCPTransport is a TCP-based Raft transport.
type TCPTransport struct {
	dialTimeout time.Duration
	conns       map[NodeID]net.Conn
	peerAddrs   map[NodeID]string
	mu          sync.RWMutex
	tlsConfig   *tls.Config // nil means plain TCP
}

// NewTCPTransport creates a new TCP transport with optional TLS.
// Pass nil for tlsConfig to use plain TCP (for development only).
func NewTCPTransport(tlsConfig *tls.Config) *TCPTransport {
	return &TCPTransport{
		dialTimeout: 5 * time.Second,
		conns:       make(map[NodeID]net.Conn),
		peerAddrs:   make(map[NodeID]string),
		tlsConfig:   tlsConfig,
	}
}

// SendRequestVote sends a RequestVote RPC.
func (t *TCPTransport) SendRequestVote(peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	conn, err := t.getConn(peerID)
	if err != nil {
		return nil, err
	}

	if err := writeRPCMessage(conn, msgTypeVoteRequest, req); err != nil {
		return nil, err
	}

	var respType uint8
	if err := binary.Read(conn, binary.BigEndian, &respType); err != nil {
		return nil, err
	}
	if respType != msgTypeVoteResponse {
		return nil, fmt.Errorf("unexpected vote response type: %d", respType)
	}

	var resp VoteResponse
	if err := readRPCMessage(conn, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SendAppendEntries sends an AppendEntries RPC.
func (t *TCPTransport) SendAppendEntries(peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	conn, err := t.getConn(peerID)
	if err != nil {
		return nil, err
	}

	if err := writeRPCMessage(conn, msgTypeAppendRequest, req); err != nil {
		return nil, err
	}

	var respType uint8
	if err := binary.Read(conn, binary.BigEndian, &respType); err != nil {
		return nil, err
	}
	if respType != msgTypeAppendResponse {
		return nil, fmt.Errorf("unexpected append response type: %d", respType)
	}

	var resp AppendResponse
	if err := readRPCMessage(conn, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SendSnapshot sends a snapshot to a peer.
func (t *TCPTransport) SendSnapshot(peerID NodeID, req SnapshotRequest) error {
	conn, err := t.getConn(peerID)
	if err != nil {
		return err
	}

	return writeRPCMessage(conn, msgTypeSnapshot, req)
}

// getConn gets or creates a connection to a peer.
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
	var dialConn net.Conn
	var err error
	if t.tlsConfig != nil {
		dialConn, err = tls.Dial("tcp", addr, t.tlsConfig)
	} else {
		dialConn, err = net.DialTimeout("tcp", addr, t.dialTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// Store connection
	t.mu.Lock()
	t.conns[peerID] = dialConn
	t.mu.Unlock()

	return dialConn, nil
}

// SetPeerAddr sets the address for a peer.
func (t *TCPTransport) SetPeerAddr(peerID NodeID, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peerAddrs[peerID] = addr
}

// Stats contains transport statistics.
type Stats struct {
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
	MessagesSent  atomic.Uint64
}
