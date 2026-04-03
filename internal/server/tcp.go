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
)

// TCPConn is a wrapper around net.Conn for testing/mocking.
type TCPConn interface {
	net.Conn
}

// TCPServer handles TCP DNS queries.
type TCPServer struct {
	addr     string
	handler  Handler
	listener net.Listener
	workers  int

	// Context and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Connection limiting
	connSem chan struct{}

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
		handler: handler,
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
		connSem: make(chan struct{}, TCPMaxConnections),
	}
}

// Listen starts listening on the TCP address.
func (s *TCPServer) Listen() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}

	s.listener = ln
	return nil
}

// ListenWithListener uses an existing listener (for testing).
func (s *TCPServer) ListenWithListener(ln net.Listener) {
	s.listener = ln
}

// Serve starts serving DNS requests.
// This blocks until the server is stopped.
func (s *TCPServer) Serve() error {
	if s.listener == nil {
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
		conn, err := s.listener.Accept()
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

		// Check connection limit
		select {
		case s.connSem <- struct{}{}:
			atomic.AddUint64(&s.connectionsAccepted, 1)
		default:
			// Too many connections, close this one
			conn.Close()
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Send to worker, respecting shutdown
		select {
		case connChan <- conn:
		case <-s.ctx.Done():
			conn.Close()
			<-s.connSem
		}
	}
}

// worker handles TCP connections.
func (s *TCPServer) worker(connChan <-chan net.Conn) {
	defer s.wg.Done()

	for conn := range connChan {
		s.handleConnection(conn)
		<-s.connSem // Release slot
	}
}

// handleConnection processes a single TCP connection.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer func() {
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

		// Process the message
		s.handleMessage(conn, msgBuf)
	}
}

// handleMessage processes a single DNS message over TCP.
func (s *TCPServer) handleMessage(conn net.Conn, data []byte) {
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
	}

	// Call handler
	s.handler.ServeDNS(rw, msg)
}

// tcpResponseWriter implements ResponseWriter for TCP.
type tcpResponseWriter struct {
	conn       net.Conn
	client     *ClientInfo
	maxSize    int
	writeCount int        // Number of writes (for AXFR support)
	server     *TCPServer // Reference for metrics
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
	buf := make([]byte, estimated)

	// Pack the response
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

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the server's listener address.
func (s *TCPServer) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
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
