package main

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// dsoConnAdapter bridges the transport servers (TCP/TLS) to the DSO
// manager: it owns the conn→session mapping so each transport connection
// gets exactly one RFC 8490 session, created lazily on the first DSO
// message and torn down when the connection closes.
type dsoConnAdapter struct {
	manager *dso.Manager
	logger  *util.Logger

	mu       sync.Mutex
	sessions map[net.Conn]*dso.Session
}

func newDSOConnAdapter(manager *dso.Manager, logger *util.Logger) *dsoConnAdapter {
	return &dsoConnAdapter{
		manager:  manager,
		logger:   logger,
		sessions: make(map[net.Conn]*dso.Session),
	}
}

// HandleDSO implements server.DSOConnHandler. Session creation happens
// under a.mu so two pipelined DSO messages on the same connection cannot
// race a duplicate session into existence. dso.Manager.CreateSession
// enforces the RFC 8490 §5.1 TLS requirement (plain TCP is refused unless
// the manager was configured with AllowPlainTCP).
func (a *dsoConnAdapter) HandleDSO(conn net.Conn, msg *protocol.Message) (*protocol.Message, error) {
	a.mu.Lock()
	sess, ok := a.sessions[conn]
	if !ok {
		var err error
		sess, err = a.manager.CreateSession(conn)
		if err != nil {
			a.mu.Unlock()
			// A full session table is a resource limit, not a protocol
			// violation: answer SERVFAIL and keep the connection (and any
			// pipelined regular DNS queries on it) alive instead of
			// aborting. Genuine protocol/TLS errors still abort.
			if errors.Is(err, dso.ErrMaxSessions) {
				resp := &protocol.Message{Header: msg.Header}
				resp.Header.Flags.QR = true
				resp.Header.Flags.RCODE = protocol.RcodeServerFailure
				resp.Header.QDCount, resp.Header.ANCount = 0, 0
				resp.Header.NSCount, resp.Header.ARCount = 0, 0
				return resp, nil
			}
			return nil, err
		}
		a.sessions[conn] = sess
	}
	a.mu.Unlock()

	return a.manager.HandleDSORequest(sess, msg)
}

// Touch implements server.DSOConnHandler: it resets the DSO inactivity
// timer for conn on ANY message (RFC 8490 §7.1.1 resets the timer on
// every DNS message on the session). Without this, regular DNS queries
// sharing the connection did not count as activity, so the sweeper closed
// an actively-used connection ~15s after the last DSO-specific message.
func (a *dsoConnAdapter) Touch(conn net.Conn) {
	a.mu.Lock()
	sess, ok := a.sessions[conn]
	a.mu.Unlock()
	if ok {
		sess.UpdateActivity()
	}
}

// ReadTimeout implements server.DSOConnHandler: a connection with a session
// is aborted by the session's inactivity rule, not the transport's idle
// timeout.
func (a *dsoConnAdapter) ReadTimeout(conn net.Conn) time.Duration {
	a.mu.Lock()
	_, ok := a.sessions[conn]
	a.mu.Unlock()
	if !ok {
		return 0
	}
	return a.manager.AbortAfter()
}

// ConnClosed implements server.DSOConnHandler.
func (a *dsoConnAdapter) ConnClosed(conn net.Conn) {
	a.mu.Lock()
	sess, ok := a.sessions[conn]
	delete(a.sessions, conn)
	a.mu.Unlock()

	if ok {
		a.manager.RemoveSession(sess.ID)
	}
}
