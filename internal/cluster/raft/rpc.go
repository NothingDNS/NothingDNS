package raft

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
	listener net.Listener
	handler  RPCHandler
	conns    map[NodeID]net.Conn
	mu       sync.RWMutex
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewRPCServer creates a new RPC server.
func NewRPCServer(addr string, handler RPCHandler) (*RPCServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &RPCServer{
		listener: listener,
		handler:  handler,
		conns:    make(map[NodeID]net.Conn),
		stopCh:   make(chan struct{}),
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

		s.mu.Lock()
		s.conns[""] = conn // Could track by remote node ID
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn handles a single connection.
func (s *RPCServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

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
			if err != io.EOF {
				// Log error
			}
			return
		}

		switch msgType {
		case 1: // VoteRequest
			var req VoteRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			resp := s.handler.HandleVoteRequest(req)
			if err := s.writeMessage(conn, 2, resp); err != nil { // VoteResponse = 2
				return
			}
		case 3: // AppendRequest
			var req AppendRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			resp := s.handler.HandleAppendRequest(req)
			if err := s.writeMessage(conn, 4, resp); err != nil { // AppendResponse = 4
				return
			}
		case 5: // SnapshotRequest
			var req SnapshotRequest
			if err := s.readMessage(conn, &req); err != nil {
				return
			}
			s.handler.HandleSnapshotRequest(req)
		}
	}
}

// writeMessage writes a message with type prefix.
func (s *RPCServer) writeMessage(w io.Writer, msgType uint8, msg interface{}) error {
	if err := binary.Write(w, binary.BigEndian, msgType); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, msg)
}

// readMessage reads a message.
func (s *RPCServer) readMessage(r io.Reader, msg interface{}) error {
	return binary.Read(r, binary.BigEndian, msg)
}

// TCPTransport is a TCP-based Raft transport.
type TCPTransport struct {
	dialTimeout time.Duration
	conns       map[NodeID]net.Conn
	mu          sync.RWMutex
}

// NewTCPTransport creates a new TCP transport.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{
		dialTimeout: 5 * time.Second,
		conns:       make(map[NodeID]net.Conn),
	}
}

// SendRequestVote sends a RequestVote RPC.
func (t *TCPTransport) SendRequestVote(peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	conn, err := t.getConn(peerID)
	if err != nil {
		return nil, err
	}

	if err := binary.Write(conn, binary.BigEndian, uint8(1)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return nil, err
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		return nil, err
	}

	var resp VoteResponse
	if err := binary.Read(conn, binary.BigEndian, &resp); err != nil {
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

	if err := binary.Write(conn, binary.BigEndian, uint8(3)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return nil, err
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		return nil, err
	}

	var resp AppendResponse
	if err := binary.Read(conn, binary.BigEndian, &resp); err != nil {
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

	if err := binary.Write(conn, binary.BigEndian, uint8(5)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return err
	}
	return conn.(*net.TCPConn).CloseWrite()
}

// getConn gets or creates a connection to a peer.
func (t *TCPTransport) getConn(peerID NodeID) (net.Conn, error) {
	t.mu.RLock()
	conn, ok := t.conns[peerID]
	t.mu.RUnlock()
	if ok {
		return conn, nil
	}

	// Would need address lookup — placeholder
	return nil, fmt.Errorf("peer address unknown for %s", peerID)
}

// SetPeerAddr sets the address for a peer.
func (t *TCPTransport) SetPeerAddr(peerID NodeID, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Store addr for dialing
	t.conns[peerID] = nil // Placeholder
}

// Stats contains transport statistics.
type Stats struct {
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
	MessagesSent  atomic.Uint64
}
