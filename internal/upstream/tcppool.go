package upstream

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tcpConn wraps a net.Conn with metadata for pooling.
type tcpConn struct {
	conn        net.Conn
	createdAt   time.Time
	lastUsedAt  time.Time
	pool        *tcpConnPool
	inUse       atomic.Bool
}

func (c *tcpConn) close() error {
	return c.conn.Close()
}

// tcpConnPool manages a pool of TCP connections to a single upstream server.
type tcpConnPool struct {
	address     string
	maxIdle     int
	maxTotal    int
	idleTimeout time.Duration
	dialTimeout time.Duration

	mu       sync.Mutex
	idle     []*tcpConn // ready for reuse
	active   int         // currently in-flight
	closed   bool
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

	// Try to get an idle connection
	for len(p.idle) > 0 {
		c := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		// Check if the idle connection is still valid
		if time.Since(c.lastUsedAt) > p.idleTimeout {
			c.close()
			p.active--
			continue
		}

		// Check if connection is still alive with a zero-read deadline
		if err := c.conn.SetReadDeadline(time.Now()); err != nil {
			c.close()
			p.active--
			continue
		}
		// Reset deadline to zero (blocking)
		_ = c.conn.SetReadDeadline(time.Time{})

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

	return &tcpConn{
		conn:       conn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		pool:       p,
		inUse:      atomic.Bool{},
	}, nil
}

// put returns a connection to the pool or closes it.
func (p *tcpConnPool) put(c *tcpConn) {
	if c.pool != p {
		// Not part of this pool (overflow connection) — just close
		c.close()
		return
	}

	c.lastUsedAt = time.Now()
	c.inUse.Store(false)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		c.close()
		p.active--
		return
	}

	// If too many idle, close this one
	if len(p.idle) >= p.maxIdle {
		c.close()
		p.active--
		return
	}

	p.idle = append(p.idle, c)
}

// closeAll closes all idle connections and marks the pool as closed.
func (p *tcpConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for _, c := range p.idle {
		c.close()
	}
	p.idle = nil
}

// stats returns pool statistics.
func (p *tcpConnPool) stats() (idle, active int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle), p.active
}
