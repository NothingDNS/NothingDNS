package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TCP Constants.
const (
	// TCPMaxMessageSize is the maximum DNS message size over TCP (2-byte length prefix max).
	TCPMaxMessageSize = 65535

	// TCPReadTimeout is the read timeout for TCP connections.
	TCPReadTimeout = 30 * time.Second

	// TCPWriteTimeout is the write timeout for TCP connections.
	TCPWriteTimeout = 30 * time.Second

	// TCPWorkerMultiplier determines workers per CPU core.
	TCPWorkerMultiplier = 2

	// TCPMaxConnections is the maximum number of concurrent TCP connections.
	TCPMaxConnections = 1000

	// TCPMaxConnectionsPerIP is the maximum number of concurrent TCP connections per source IP.
	TCPMaxConnectionsPerIP = 10

	// TCPMaxPipelineQueries is the maximum number of concurrent in-flight queries per TCP connection.
	TCPMaxPipelineQueries = 16
)

// TCPConn is a wrapper around net.Conn for testing/mocking.
type TCPConn interface {
	net.Conn
}

// TCPServer handles TCP DNS queries.
type TCPServer struct {
	addr     string
	handler  Handler
	listener atomic.Value // stores net.Listener atomically
	workers  int

	// Context and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Connection limiting
	connSem     chan struct{}
	ipConnCount map[string]int
	ipConnMu    sync.Mutex

	// Buffer pool for zero-alloc response path
	responsePool sync.Pool

	// Metrics
	connectionsAccepted uint64
	connectionsClosed   uint64
	messagesReceived    uint64
	messagesSent        uint64
	errors              uint64
}

// NewTCPServer creates a new TCP DNS server.
func NewTCPServer(addr string, handler Handler) *TCPServer {
	return NewTCPServerWithWorkers(addr, handler, 0)
}

// NewTCPServerWithWorkers creates a new TCP DNS server with a specific worker count.
// If workers is 0, it defaults to runtime.NumCPU() * TCPWorkerMultiplier.
func NewTCPServerWithWorkers(addr string, handler Handler, workers int) *TCPServer {
	if workers == 0 {
		workers = runtime.NumCPU() * TCPWorkerMultiplier
	}
	if workers < 1 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TCPServer{
		addr:    addr,
		handler: &ServeDNSWithRecovery{Handler: handler},
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
		connSem: make(chan struct{}, TCPMaxConnections),
		ipConnCount: make(map[string]int),
		responsePool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate a commonly-used size; larger responses allocate fresh
				return make([]byte, 4096)
			},
		},
	}
}

// Listen starts listening on the TCP address.
// On platforms that support SO_REUSEPORT, the socket is created with
// reuseport enabled for better multi-core scalability.
func (s *TCPServer) Listen() error {
	ln, err := listenTCPWithReusePort(s.addr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}

	s.listener.Store(ln) // atomic store of interface value
	return nil
}

// ListenWithListener uses an existing listener (for testing).
func (s *TCPServer) ListenWithListener(ln net.Listener) {
	s.listener.Store(ln) // atomic store of interface value
}

// Serve starts serving DNS requests.
// This blocks until the server is stopped.
func (s *TCPServer) Serve() error {
	// Load listener atomically - handle uninitialized case
	rawListener := s.listener.Load()
	if rawListener == nil {
		return errors.New("server not listening")
	}
	listener, ok := rawListener.(net.Listener)
	if !ok || listener == nil {
		return errors.New("server not listening")
	}

	// Start connection handler workers
	connChan := make(chan net.Conn, s.workers*2)

	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(connChan)
	}

	// Accept loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				// Shutting down
				close(connChan)
				s.wg.Wait()
				return nil
			}
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Check global connection limit
		select {
		case s.connSem <- struct{}{}:
			atomic.AddUint64(&s.connectionsAccepted, 1)
		default:
			// Too many connections, close this one
			conn.Close()
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Check per-IP connection limit
		ip := getIP(conn.RemoteAddr())
		s.ipConnMu.Lock()
		if s.ipConnCount[ip] >= TCPMaxConnectionsPerIP {
			s.ipConnMu.Unlock()
			conn.Close()
			<-s.connSem
			atomic.AddUint64(&s.errors, 1)
			continue
		}
		s.ipConnCount[ip]++
		s.ipConnMu.Unlock()

		// Send to worker, respecting shutdown
		select {
		case connChan <- conn:
		case <-s.ctx.Done():
			s.ipConnMu.Lock()
			s.ipConnCount[ip]--
			s.ipConnMu.Unlock()
			conn.Close()
			<-s.connSem
		}
	}
}

// worker handles TCP connections.
func (s *TCPServer) worker(connChan <-chan net.Conn) {
	defer s.wg.Done()

	for conn := range connChan {
		ip := getIP(conn.RemoteAddr())
		s.handleConnection(conn)
		s.ipConnMu.Lock()
		s.ipConnCount[ip]--
		s.ipConnMu.Unlock()
		<-s.connSem // Release slot
	}
}

// handleConnection processes a single TCP connection.
// Reads are sequential (TCP requires this), but message processing is concurrent
// up to TCPMaxPipelineQueries in-flight queries (TCP pipelining).
func (s *TCPServer) handleConnection(conn net.Conn) {
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	pipeSem := make(chan struct{}, TCPMaxPipelineQueries)

	defer func() {
		wg.Wait()
		conn.Close()
		atomic.AddUint64(&s.connectionsClosed, 1)
	}()

	for {
		// Set read timeout
		if err := conn.SetReadDeadline(time.Now().Add(TCPReadTimeout)); err != nil {
			atomic.AddUint64(&s.errors, 1)
			return
		}

		// Read 2-byte length prefix
		var lengthBuf [2]byte
		_, err := io.ReadFull(conn, lengthBuf[:])
		if err != nil {
			if !errors.Is(err, io.EOF) {
				atomic.AddUint64(&s.errors, 1)
			}
			return
		}

		msgLen := binary.BigEndian.Uint16(lengthBuf[:])

		// Sanity check message length
		if msgLen == 0 || msgLen > TCPMaxMessageSize {
			atomic.AddUint64(&s.errors, 1)
			return
		}

		// Read message body
		msgBuf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, msgBuf)
		if err != nil {
			atomic.AddUint64(&s.errors, 1)
			return
		}

		atomic.AddUint64(&s.messagesReceived, 1)

		// Acquire pipeline semaphore slot
		pipeSem <- struct{}{}

		// Process the message concurrently
		wg.Add(1)
		go func(data []byte) {
			defer wg.Done()
			defer func() { <-pipeSem }()
			s.handleMessage(conn, data, &writeMu)
		}(msgBuf)
	}
}

// handleMessage processes a single DNS message over TCP.
// writeMu serializes writes on the connection to prevent interleaving during pipelining.
func (s *TCPServer) handleMessage(conn net.Conn, data []byte, writeMu *sync.Mutex) {
	// Unpack the message
	msg, err := protocol.UnpackMessage(data)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Build client info
	client := &ClientInfo{
		Addr:     conn.RemoteAddr(),
		Protocol: "tcp",
	}

	// Check for EDNS0 in additional section
	for _, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeOPT {
			client.HasEDNS0 = true
			client.EDNS0UDPSize = rr.Class

			if optData, ok := rr.Data.(*protocol.RDataOPT); ok {
				for _, opt := range optData.Options {
					if opt.Code == protocol.OptionCodeClientSubnet {
						if ecs, err := protocol.UnpackEDNS0ClientSubnet(opt.Data); err == nil {
							client.ClientSubnet = ecs
						}
						break
					}
				}
			}
			break
		}
	}

	// Create response writer
	rw := &tcpResponseWriter{
		conn:    conn,
		client:  client,
		maxSize: TCPMaxMessageSize,
		server:  s,
		writeMu: writeMu,
	}

	// Call handler
	s.handler.ServeDNS(rw, msg)
}

// tcpResponseWriter implements ResponseWriter for TCP.
type tcpResponseWriter struct {
	conn       net.Conn
	client     *ClientInfo
	maxSize    int
	writeCount int          // Number of writes (for AXFR support)
	server     *TCPServer   // Reference for metrics
	writeMu    *sync.Mutex  // Serializes writes for pipelining safety
}

func (w *tcpResponseWriter) ClientInfo() *ClientInfo {
	return w.client
}

func (w *tcpResponseWriter) MaxSize() int {
	return w.maxSize
}

func (w *tcpResponseWriter) Write(msg *protocol.Message) (int, error) {
	// Estimate buffer size from wire length (+2 for length prefix)
	estimated := msg.WireLength() + 2
	if estimated < 512 {
		estimated = 512
	}
	if estimated > TCPMaxMessageSize {
		estimated = TCPMaxMessageSize
	}

	// Try to get a buffer from the pool; fall back to allocation if too small
	var buf []byte
	if w.server != nil {
		if p, ok := w.server.responsePool.Get().([]byte); ok {
			buf = p
		} else {
			buf = make([]byte, estimated)
		}
		if cap(buf) < estimated {
			// Pool buffer too small — allocate fresh and don't return to pool
			buf = make([]byte, estimated)
		} else {
			defer w.server.responsePool.Put(buf)
		}
	} else {
		buf = make([]byte, estimated)
	}

	// Pack the response (done outside the lock — CPU work, no I/O)
	n, err := msg.Pack(buf[2:]) // Leave room for length prefix
	if err != nil {
		return 0, err
	}

	if n > w.maxSize-2 {
		msg.Header.Flags.TC = true
		msg.Truncate(w.maxSize - 2)
		n, err = msg.Pack(buf[2:])
		if err != nil {
			return 0, err
		}
	}

	// Write length prefix
	binary.BigEndian.PutUint16(buf[0:], uint16(n))

	// Serialize writes on the connection to prevent interleaving
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	// Set write timeout
	w.conn.SetWriteDeadline(time.Now().Add(TCPWriteTimeout))

	// Write response
	sent, err := w.conn.Write(buf[:n+2])
	if err == nil && sent > 0 {
		if w.server != nil {
			atomic.AddUint64(&w.server.messagesSent, 1)
		}
	}

	w.writeCount++
	return sent, err
}

// Stop gracefully shuts down the server.
func (s *TCPServer) Stop() error {
	s.cancel()

	listener, ok := s.listener.Load().(net.Listener)
	if ok && listener != nil {
		return listener.Close()
	}
	return nil
}

// Addr returns the server's listener address.
func (s *TCPServer) Addr() net.Addr {
	listener, ok := s.listener.Load().(net.Listener)
	if !ok || listener == nil {
		return nil
	}
	return listener.Addr()
}

// Listener returns the underlying net.Listener for testing purposes.
func (s *TCPServer) Listener() net.Listener {
	listener, _ := s.listener.Load().(net.Listener)
	return listener
}

// Stats returns server statistics.
func (s *TCPServer) Stats() TCPServerStats {
	return TCPServerStats{
		ConnectionsAccepted: atomic.LoadUint64(&s.connectionsAccepted),
		ConnectionsClosed:   atomic.LoadUint64(&s.connectionsClosed),
		MessagesReceived:    atomic.LoadUint64(&s.messagesReceived),
		MessagesSent:        atomic.LoadUint64(&s.messagesSent),
		Errors:              atomic.LoadUint64(&s.errors),
		Workers:             s.workers,
	}
}

// TCPServerStats contains runtime statistics for the TCP server.
type TCPServerStats struct {
	ConnectionsAccepted uint64
	ConnectionsClosed   uint64
	MessagesReceived    uint64
	MessagesSent        uint64
	Errors              uint64
	Workers             int
}

// getIP extracts the IP address string from a net.Addr.
func getIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return ip
}
