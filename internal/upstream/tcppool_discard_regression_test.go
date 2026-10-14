package upstream

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// closeErrConn is an idle pooled connection whose Close reports an error
// (a TLS-wrapped or reset socket does that).
type closeErrConn struct{ net.Conn }

func (closeErrConn) Close() error                    { return errors.New("close: connection reset") }
func (closeErrConn) SetReadDeadline(time.Time) error { return nil }
func (closeErrConn) Read([]byte) (int, error)        { return 0, errors.New("closed") }

func TestPoolDiscardStaleIdleCloseErrorDoesNotFailGet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()

	// control: a healthy pool with nothing idle dials a fresh connection
	ctl := newTCPConnPool(ln.Addr().String(), 4, 8, time.Minute, time.Second)
	c0, err := ctl.get()
	if err != nil {
		t.Fatalf("CONTROL FAILED: %v", err)
	}
	_ = c0.close()

	p := newTCPConnPool(ln.Addr().String(), 4, 8, time.Millisecond, time.Second)
	stale := &tcpConn{conn: closeErrConn{}, pool: p, lastUsedAt: time.Now().Add(-time.Hour)}
	p.idle = []*tcpConn{stale}
	p.active = 1
	c, err := p.get()
	fmt.Printf("EXPECTED: a fresh connection | ACTUAL: conn=%v err=%v\n", c != nil, err)
	if err != nil {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatalf("get failed because an expired idle connection could not be closed: %v", err)
	}
	_ = c.close()
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func TestPoolDiscardsExpiredIdleConnsAndKeepsAccounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()
	addr := ln.Addr().String()
	p := newTCPConnPool(addr, 4, 8, time.Minute, time.Second)

	good, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	goodConn := &tcpConn{conn: good, pool: p, lastUsedAt: time.Now()}
	expired := &tcpConn{conn: closeErrConn{}, pool: p, lastUsedAt: time.Now().Add(-time.Hour)}
	expired2 := &tcpConn{conn: closeErrConn{}, pool: p, lastUsedAt: time.Now().Add(-2 * time.Hour)}
	// LIFO: both expired connections are tried (and fail to close) before the good one.
	p.idle = []*tcpConn{goodConn, expired, expired2}
	p.active = 3

	c, err := p.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c != goodConn {
		t.Fatal("did not reach the healthy idle connection")
	}
	p.mu.Lock()
	active, idle := p.active, len(p.idle)
	p.mu.Unlock()
	if active != 1 || idle != 0 {
		t.Fatalf("active=%d idle=%d, want 1/0 (two discarded connections released their slots)", active, idle)
	}
	_ = c.close()
}
