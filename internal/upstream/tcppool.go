package upstream

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tcpConn wraps a net.Conn with metadata for pooling.
type tcpConn struct {
	conn       net.Conn
	createdAt  time.Time
	lastUsedAt time.Time
	pool       *tcpConnPool
	inUse      atomic.Bool
	closed     atomic.Bool
}

func (c *tcpConn) close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	if c.pool != nil && c.closed.CompareAndSwap(false, true) {
		c.pool.mu.Lock()
		if c.pool.active > 0 {
			c.pool.active--
		}
		c.pool.mu.Unlock()
	}
	return c.conn.Close()
}

// tcpConnPool manages a pool of TCP connections to a single upstream server.
type tcpConnPool struct {
	address     string
	maxIdle     int
	maxTotal    int
	idleTimeout time.Duration
	dialTimeout time.Duration

	mu     sync.Mutex
	idle   []*tcpConn // ready for reuse
	active int        // open pooled connections
	closed bool
}

// newTCPConnPool creates a new TCP connection pool.
func newTCPConnPool(address string, maxIdle, maxTotal int, idleTimeout, dialTimeout time.Duration) *tcpConnPool {
	if maxIdle <= 0 {
		maxIdle = 4
	}
	if maxTotal <= 0 {
		maxTotal = 64
	}
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	return &tcpConnPool{
		address:     address,
		maxIdle:     maxIdle,
		maxTotal:    maxTotal,
		idleTimeout: idleTimeout,
		dialTimeout: dialTimeout,
	}
}

// get retrieves or creates a TCP connection.
func (p *tcpConnPool) get() (*tcpConn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}

	// Try to get an idle connection
	for len(p.idle) > 0 {
		c := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		// Check if the idle connection is still valid
		if tcpIdleTimeoutReachedAt(c.lastUsedAt, time.Now(), p.idleTimeout) {
			if err := p.closeConnLocked(c); err != nil {
				p.mu.Unlock()
				return nil, err
			}
			continue
		}

		// Discard a connection the upstream has already closed. The
		// read-deadline check below performs no I/O and therefore cannot
		// observe a peer close, so without this probe a dead connection is
		// handed back out, its query fails, and queryTCPBuf's deferred
		// markFailure() records a failure against a healthy upstream —
		// enough stale connections flip IsHealthy() false and pull a
		// working upstream out of rotation. See tcppool_liveness_unix.go.
		if !tcpConnReusable(c.conn) {
			if err := p.closeConnLocked(c); err != nil {
				p.mu.Unlock()
				return nil, err
			}
			continue
		}

		// Check if connection is still alive with a zero-read deadline
		if err := c.conn.SetReadDeadline(time.Now()); err != nil {
			if closeErr := p.closeConnLocked(c); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
			p.mu.Unlock()
			return nil, err
		}
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			if closeErr := p.closeConnLocked(c); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
			p.mu.Unlock()
			return nil, err
		}

		c.inUse.Store(true)
		p.mu.Unlock()
		return c, nil
	}

	// Can we create a new connection?
	if p.active >= p.maxTotal {
		p.mu.Unlock()
		// Pool exhausted — create a direct (unpooled) connection
		conn, err := net.DialTimeout("tcp", p.address, p.dialTimeout)
		if err != nil {
			return nil, err
		}
		return &tcpConn{
			conn:       conn,
			createdAt:  time.Now(),
			lastUsedAt: time.Now(),
			pool:       nil, // not pooled — will be closed after use
		}, nil
	}

	p.active++
	p.mu.Unlock()

	// Dial a new connection
	conn, err := net.DialTimeout("tcp", p.address, p.dialTimeout)
	if err != nil {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
		return nil, err
	}

	tc := &tcpConn{
		conn:       conn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		pool:       p,
	}
	tc.inUse.Store(true)
	return tc, nil
}

func tcpIdleTimeoutReachedAt(lastUsedAt, now time.Time, idleTimeout time.Duration) bool {
	return !now.Before(lastUsedAt.Add(idleTimeout))
}

// put returns a connection to the pool or closes it.
func (p *tcpConnPool) put(c *tcpConn) error {
	if c.pool != p {
		// Not part of this pool (overflow connection) — just close
		return c.close()
	}

	c.lastUsedAt = time.Now()
	c.inUse.Store(false)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return p.closeConnLocked(c)
	}

	// If too many idle, close this one
	if len(p.idle) >= p.maxIdle {
		return p.closeConnLocked(c)
	}

	p.idle = append(p.idle, c)
	return nil
}

// closeAll closes all idle connections and marks the pool as closed.
func (p *tcpConnPool) closeAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	var closeErr error
	for _, c := range p.idle {
		if err := p.closeConnLocked(c); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	p.idle = nil
	return closeErr
}

// closeConnLocked closes a pooled connection while p.mu is already held.
func (p *tcpConnPool) closeConnLocked(c *tcpConn) error {
	if c == nil || c.conn == nil {
		return nil
	}
	if c.pool == p && c.closed.CompareAndSwap(false, true) && p.active > 0 {
		p.active--
	}
	return c.conn.Close()
}
