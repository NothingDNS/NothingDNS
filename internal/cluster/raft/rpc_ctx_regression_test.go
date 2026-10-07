package raft

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// Regression tests for F152 (TCPTransport ignored the RPC context while
// dialing, handshaking and doing I/O) and F153 (a pooled connection kept the
// previous RPC's deadline). Watchdogs below only bound failures; ordering is
// gated by channels.

const rpcCtxWatchdog = 5 * time.Second

// stalledPeer accepts TCP connections and never writes anything back.
func stalledPeer(t *testing.T) (net.Listener, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case c := <-accepted:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return ln, accepted
}

func TestTCPTransport_CancelInterruptsStalledTLSHandshake(t *testing.T) {
	ln, accepted := stalledPeer(t)
	tr := NewTCPTransport(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil)
	tr.dialTimeout = time.Hour // only the ctx may end the handshake
	tr.SetPeerAddr("p", ln.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tr.SendAppendEntries(ctx, "p", AppendRequest{Term: 1})
		done <- err
	}()
	c := <-accepted // the dial reached the peer and the handshake is stalled
	defer c.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(rpcCtxWatchdog):
		t.Fatal("RPC still blocked in TLS handshake after its context was cancelled")
	}
	if _, ok := tr.conns["p"]; ok {
		t.Fatal("cancelled dial must not cache a connection")
	}
}

func TestTCPTransport_ExpiredContextDoesNotDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	tr := NewTCPTransport(nil, nil)
	tr.SetPeerAddr("p", ln.Addr().String())

	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	if _, err := tr.SendRequestVote(ctx, "p", VoteRequest{Term: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	// A completed dial would already sit in the accept backlog.
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, err := ln.Accept(); err == nil {
		_ = c.Close()
		t.Fatal("expired RPC context still dialed the peer")
	}
}

func TestTCPTransport_CancelInterruptsResponseRead(t *testing.T) {
	ln, accepted := stalledPeer(t)
	tr := NewTCPTransport(nil, nil)
	tr.SetPeerAddr("p", ln.Addr().String())

	ctx, cancel := context.WithCancel(context.Background()) // no deadline
	done := make(chan error, 1)
	go func() {
		_, err := tr.SendRequestVote(ctx, "p", VoteRequest{Term: 1})
		done <- err
	}()
	peer := <-accepted
	defer peer.Close()
	// Gate: the request frame has been fully written, so the client is (or
	// is about to be) blocked reading the response that never comes.
	if _, _, err := newFrameReader(peer, nil).readFrameBytes(); err != nil {
		t.Fatalf("peer read request: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled RPC returned success")
		}
	case <-time.After(rpcCtxWatchdog):
		t.Fatal("RPC still blocked reading the response after its context was cancelled")
	}
	tr.mu.RLock()
	_, cached := tr.conns["p"]
	tr.mu.RUnlock()
	if cached {
		t.Fatal("interrupted exchange must drop the connection (half-read stream)")
	}
}

type deadlineRecConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineRecConn) SetDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadline = d
	c.mu.Unlock()
	return c.Conn.SetDeadline(d)
}

func (c *deadlineRecConn) current() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func TestTCPTransport_NoDeadlineContextClearsStaleDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		fr, fw := newFrameReader(server, nil), newFrameWriter(server, nil)
		for {
			_, payload, err := fr.readFrameBytes()
			if err != nil {
				return
			}
			var req VoteRequest
			if decodeNative(&req, payload) != nil {
				return
			}
			if fw.writeFramed(msgTypeVoteResponse, VoteResponse{Term: req.Term}) != nil {
				return
			}
		}
	}()
	rc := &deadlineRecConn{Conn: client}
	tr := NewTCPTransport(nil, nil)
	tr.conns["p"] = rc

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	if _, err := tr.SendRequestVote(ctx, "p", VoteRequest{Term: 1}); err != nil {
		t.Fatalf("call with deadline: %v", err)
	}
	cancel()
	if rc.current().IsZero() {
		t.Fatal("ctx deadline was not applied to the conn")
	}
	for i, c := range []context.Context{context.Background(), nil} {
		resp, err := tr.SendRequestVote(c, "p", VoteRequest{Term: Term(2 + i)})
		if err != nil || resp.Term != Term(2+i) {
			t.Fatalf("call %d without deadline: resp=%v err=%v", i, resp, err)
		}
		if d := rc.current(); !d.IsZero() {
			t.Fatalf("call %d: stale deadline %v left on pooled conn", i, d)
		}
	}
}
