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
	"github.com/nothingdns/nothingdns/internal/util"
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

	// defaultFrameBufSize is the pooled frame buffer size for stream
	// transports (TCP/TLS): 2-byte length prefix + payload. It covers the
	// overwhelming majority of responses; larger ones take the exact-size
	// fallback in packFramedDNSPayload.
	defaultFrameBufSize = 4096
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

	// dsoHandler, when non-nil, receives DSO (RFC 8490, opcode 6) messages
	// instead of the regular handler. Set before Serve; not safe to change
	// while serving.
	dsoHandler DSOConnHandler

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
		addr:        addr,
		handler:     &ServeDNSWithRecovery{Handler: handler},
		workers:     workers,
		ctx:         ctx,
		cancel:      cancel,
		connSem:     make(chan struct{}, TCPMaxConnections),
		ipConnCount: make(map[string]int),
		responsePool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate a commonly-used size; larger responses allocate fresh
				return make([]byte, defaultFrameBufSize)
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
			s.decrementIPConn(ip)
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
		s.decrementIPConn(ip)
		<-s.connSem // Release slot
	}
}

func (s *TCPServer) decrementIPConn(ip string) {
	s.ipConnMu.Lock()
	defer s.ipConnMu.Unlock()

	if s.ipConnCount[ip] <= 1 {
		delete(s.ipConnCount, ip)
		return
	}
	s.ipConnCount[ip]--
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
		if s.dsoHandler != nil {
			s.dsoHandler.ConnClosed(conn)
		}
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
	// L-2: per-goroutine recover so a panic in UnpackMessage / EDNS0
	// parsing — both of which run before any ServeDNSWithRecovery
	// wrapper sees the message — can't crash the daemon. The
	// integratedHandler's recover only covers the post-Unpack pipeline.
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&s.errors, 1)
		}
	}()

	// Unpack the message
	msg, err := protocol.UnpackMessage(data)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}
	defer msg.Release()

	// Any message on this connection resets a co-hosted DSO session's
	// inactivity timer (RFC 8490 §7.1.1).
	if s.dsoHandler != nil {
		s.dsoHandler.Touch(conn)
	}

	// DSO (RFC 8490, opcode 6) is per-connection stateful and never enters
	// the regular query pipeline.
	if msg.Header.Flags.Opcode == protocol.OpcodeDSO {
		s.handleDSO(conn, msg, writeMu)
		return
	}

	// Build client info
	client := &ClientInfo{
		Addr:     conn.RemoteAddr(),
		Protocol: "tcp",
	}
	populateEDNS0ClientInfo(client, msg)

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

// SetDSOHandler installs the DSO (RFC 8490) handler for this server.
// Must be called before Serve.
func (s *TCPServer) SetDSOHandler(h DSOConnHandler) {
	s.dsoHandler = h
}

// handleDSO dispatches a DSO message (opcode 6) to the configured
// DSOConnHandler. Without a handler the server answers NOTIMP; a handler
// error is fatal per RFC 8490 §5.2 and forcibly aborts the connection.
func (s *TCPServer) handleDSO(conn net.Conn, msg *protocol.Message, writeMu *sync.Mutex) {
	rw := &tcpResponseWriter{
		conn:    conn,
		client:  &ClientInfo{Addr: conn.RemoteAddr(), Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
		server:  s,
		writeMu: writeMu,
	}

	if s.dsoHandler == nil {
		if msg.Header.ID != 0 {
			if _, err := rw.Write(dsoErrorResponse(msg, protocol.RcodeNotImplemented)); err != nil {
				atomic.AddUint64(&s.errors, 1)
			}
		}
		return
	}

	resp, err := s.dsoHandler.HandleDSO(conn, msg)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		conn.Close()
		return
	}
	// RFC 8490 §5.4: unidirectional messages (ID 0) MUST NOT be answered.
	if resp != nil && msg.Header.ID != 0 {
		if _, err := rw.Write(resp); err != nil {
			atomic.AddUint64(&s.errors, 1)
		}
	}
}

// tcpResponseWriter implements ResponseWriter for TCP.
type tcpResponseWriter struct {
	conn       net.Conn
	client     *ClientInfo
	maxSize    int
	writeCount int         // Number of writes (for AXFR support)
	server     *TCPServer  // Reference for metrics
	writeMu    *sync.Mutex // Serializes writes for pipelining safety
}

func (w *tcpResponseWriter) ClientInfo() *ClientInfo {
	return w.client
}

func (w *tcpResponseWriter) MaxSize() int {
	return w.maxSize
}

func (w *tcpResponseWriter) Write(msg *protocol.Message) (int, error) {
	// Get a frame buffer from the pool (zero-alloc hot path). Responses
	// that don't fit take the exact-size fallback inside
	// packFramedDNSPayload — no per-response WireLength traversal here.
	var buf []byte
	if w.server != nil {
		if pooled := w.server.responsePool.Get(); pooled != nil {
			switch p := pooled.(type) {
			case []byte:
				buf = p
			case *[]byte:
				if p != nil {
					buf = *p
				}
			}
		}
		if cap(buf) < defaultFrameBufSize {
			buf = make([]byte, defaultFrameBufSize)
		} else {
			buf = buf[:cap(buf)]
		}
		defer w.server.responsePool.Put(&buf)
	} else {
		buf = make([]byte, defaultFrameBufSize)
	}

	// Pack the response (done outside the lock - CPU work, no I/O).
	// frame is buf on the common path, or a fresh exact-size buffer when
	// the response was too large for the pooled one.
	frame, n, err := packFramedDNSPayload(msg, buf, w.maxSize, "TCP")
	if err != nil {
		return 0, err
	}

	// Write length prefix
	binary.BigEndian.PutUint16(frame[0:], uint16(n))

	// Serialize writes on the connection to prevent interleaving
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	// Set write timeout
	if err := w.conn.SetWriteDeadline(time.Now().Add(TCPWriteTimeout)); err != nil {
		return 0, fmt.Errorf("set write deadline: %w", err)
	}

	// Write response
	sent, err := writeFullDNSFrame(w.conn, frame[:n+2])
	if err == nil && sent > 0 {
		if w.server != nil {
			atomic.AddUint64(&w.server.messagesSent, 1)
		}
	}

	w.writeCount++
	return sent, err
}

// writeFullDNSFrame writes a length-prefixed DNS frame in full, returning
// len(frame) on success so callers can report the bytes sent.
func writeFullDNSFrame(conn net.Conn, frame []byte) (int, error) {
	if err := util.WriteFull(conn, frame); err != nil {
		return 0, err
	}
	return len(frame), nil
}

// packFramedDNSPayload packs msg into frameBuf[2:], leaving room for the
// 2-byte length prefix. The common path is a single pack attempt into the
// caller's (pooled) buffer; only when Pack reports ErrBufferTooSmall does it
// compute the wire length, allocate an exact-size frame, and repack. It
// returns the frame actually used — frameBuf, or the fallback allocation —
// and the payload length; the caller must write the prefix into and send
// from the returned frame.
func packFramedDNSPayload(msg *protocol.Message, frameBuf []byte, maxSize int, transport string) ([]byte, int, error) {
	n, err := msg.Pack(frameBuf[2:])
	if errors.Is(err, protocol.ErrBufferTooSmall) {
		// Rare path: response exceeds the supplied buffer. Size exactly
		// (one WireLength traversal) and repack.
		frameBuf = make([]byte, msg.WireLength()+2)
		n, err = msg.Pack(frameBuf[2:])
	}
	if err != nil {
		return nil, 0, err
	}

	if n > maxSize {
		// Record-boundary-aware truncation (sets TC, drops whole RRs).
		// The truncated message can only shrink, so it fits in the frame
		// that just held the full response.
		//
		// Do NOT pre-set TC here: Truncate decides per RFC 2181 §9 — TC
		// is set only when required Answer/Authority records are dropped
		// (or the message still does not fit); dropping only Additional
		// records (OPT, glue) must not set it. The UDP writer calls
		// Truncate directly and relies on this logic; pre-setting TC
		// here made the TCP path inconsistent.
		msg.Truncate(maxSize)
		n, err = msg.Pack(frameBuf[2:])
		if err != nil {
			return nil, 0, err
		}
		if n > maxSize {
			return nil, 0, fmt.Errorf("packed %s response length %d exceeds max payload size %d", transport, n, maxSize)
		}
	}

	return frameBuf, n, nil
}

// Stop gracefully shuts down the server.
func (s *TCPServer) Stop() error {
	s.cancel()

	listener, ok := s.listener.Load().(net.Listener)
	if ok && listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
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
