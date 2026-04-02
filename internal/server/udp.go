package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// DefaultUDP sizes and limits.
const (
	// DefaultUDPPayloadSize is the default maximum UDP payload size.
	DefaultUDPPayloadSize = 512

	// MaxUDPPayloadSize is the maximum practical UDP payload size.
	MaxUDPPayloadSize = 4096

	// UDPWorkerMultiplier determines how many workers per CPU core.
	UDPWorkerMultiplier = 4

	// UDPReadBufferSize is the size of the read buffer for UDP sockets.
	UDPReadBufferSize = 4096
)

// UDPConn is a wrapper around *net.UDPConn for testing/mocking.
type UDPConn interface {
	ReadFromUDP(buf []byte) (int, *net.UDPAddr, error)
	WriteToUDP(buf []byte, addr *net.UDPAddr) (int, error)
	Close() error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
}

// UDPServer handles UDP DNS queries.
type UDPServer struct {
	addr     string
	handler  Handler
	conn     UDPConn
	workers  int

	// Context and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	packetsReceived uint64
	packetsSent     uint64
	errors          uint64

	// Pool for request buffers
	bufferPool sync.Pool
}

// NewUDPServer creates a new UDP DNS server.
func NewUDPServer(addr string, handler Handler) *UDPServer {
	return NewUDPServerWithWorkers(addr, handler, 0)
}

// NewUDPServerWithWorkers creates a new UDP DNS server with a specific worker count.
// If workers is 0, it defaults to runtime.NumCPU() * UDPWorkerMultiplier.
func NewUDPServerWithWorkers(addr string, handler Handler, workers int) *UDPServer {
	if workers == 0 {
		workers = runtime.NumCPU() * UDPWorkerMultiplier
	}
	if workers < 1 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &UDPServer{
		addr:     addr,
		handler:  handler,
		workers:  workers,
		ctx:      ctx,
		cancel:   cancel,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, UDPReadBufferSize)
				return &buf
			},
		},
	}

	return s
}

// Listen starts listening on the UDP address.
func (s *UDPServer) Listen() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}

	s.conn = conn
	return nil
}

// ListenWithConn uses an existing UDP connection (for testing).
func (s *UDPServer) ListenWithConn(conn UDPConn) {
	s.conn = conn
}

// Serve starts serving DNS requests.
// This blocks until the server is stopped.
func (s *UDPServer) Serve() error {
	if s.conn == nil {
		return errors.New("server not listening")
	}

	// Start worker pool
	requestChan := make(chan *udpRequest, s.workers*2)

	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(requestChan)
	}

	// Start reader goroutine with its own WaitGroup so we can wait for it
	// to finish before closing requestChan.
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go s.reader(requestChan, &readerWg)

	// Wait for shutdown
	<-s.ctx.Done()

	// Close the connection to unblock the reader from ReadFromUDP.
	if s.conn != nil {
		s.conn.Close()
	}

	// Wait for the reader to stop sending on requestChan.
	readerWg.Wait()

	// Now safe to close - workers will drain and exit.
	close(requestChan)
	s.wg.Wait()

	return nil
}

// udpRequest represents a single UDP DNS request.
type udpRequest struct {
	data []byte
	addr *net.UDPAddr
	n    int
}

// reader reads packets from the UDP socket and dispatches to workers.
func (s *UDPServer) reader(requestChan chan<- *udpRequest, readerWg *sync.WaitGroup) {
	defer readerWg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Get a buffer from the pool
		bufPtr, ok := s.bufferPool.Get().(*[]byte)
		if !ok {
			continue
		}
		buf := *bufPtr

		// Read packet
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.bufferPool.Put(bufPtr)

			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}

			atomic.AddUint64(&s.errors, 1)
			continue
		}

		atomic.AddUint64(&s.packetsReceived, 1)

		// Send to workers (non-blocking with ctx check)
		select {
		case requestChan <- &udpRequest{data: buf, addr: addr, n: n}:
		case <-s.ctx.Done():
			s.bufferPool.Put(bufPtr)
			return
		}
	}
}

// worker processes DNS requests.
func (s *UDPServer) worker(requestChan <-chan *udpRequest) {
	defer s.wg.Done()

	for req := range requestChan {
		s.handleRequest(req)
		// Return buffer to pool
		bufPtr := &req.data
		s.bufferPool.Put(bufPtr)
	}
}

// handleRequest processes a single DNS request.
func (s *UDPServer) handleRequest(req *udpRequest) {
	// Unpack the message
	msg, err := protocol.UnpackMessage(req.data[:req.n])
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Build client info
	client := &ClientInfo{
		Addr:     req.addr,
		Protocol: "udp",
	}

	// Check for EDNS0 in additional section
	for _, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeOPT {
			client.HasEDNS0 = true
			client.EDNS0UDPSize = rr.Class // UDP payload size is in Class field

			// Check for Client Subnet option
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
	maxSize := ResponseSizeLimit(client)
	rw := &udpResponseWriter{
		server:  s,
		client:  client,
		maxSize: maxSize,
	}

	// Call handler
	s.handler.ServeDNS(rw, msg)
}

// udpResponseWriter implements ResponseWriter for UDP.
type udpResponseWriter struct {
	server  *UDPServer
	client  *ClientInfo
	maxSize int
	written bool
}

func (w *udpResponseWriter) ClientInfo() *ClientInfo {
	return w.client
}

func (w *udpResponseWriter) MaxSize() int {
	return w.maxSize
}

func (w *udpResponseWriter) Write(msg *protocol.Message) (int, error) {
	if w.written {
		return 0, errors.New("response already written")
	}
	w.written = true

	// Pack the response
	buf := make([]byte, MaxUDPPayloadSize)
	n, err := msg.Pack(buf)
	if err != nil {
		return 0, err
	}

	// Truncate if necessary (set TC bit)
	if n > w.maxSize {
		msg.Header.Flags.TC = true
		msg.Authorities = nil
		msg.Additionals = nil

		// Reduce answers until the message fits
		for len(msg.Answers) > 0 {
			// Remove one answer at a time from the end
			msg.Answers = msg.Answers[:len(msg.Answers)-1]
			n, err = msg.Pack(buf)
			if err != nil {
				return 0, err
			}
			if n <= w.maxSize {
				break
			}
		}

		// If still too large (or no answers left), send header + question only
		if n > w.maxSize || len(msg.Answers) == 0 {
			msg.Answers = nil
			n, err = msg.Pack(buf)
			if err != nil {
				return 0, err
			}
		}
	}

	// Send response
	addr, ok := w.client.Addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("udp: expected *net.UDPAddr, got %T", w.client.Addr)
	}
	sent, err := w.server.conn.WriteToUDP(buf[:n], addr)
	if err == nil {
		atomic.AddUint64(&w.server.packetsSent, 1)
	}
	return sent, err
}

// truncateRRSet reduces the answer set to fit within size limit.
func truncateRRSet(answers []*protocol.ResourceRecord, maxSize int) []*protocol.ResourceRecord {
	if maxSize <= 0 {
		return nil
	}

	size := 0
	var result []*protocol.ResourceRecord

	for _, rr := range answers {
		if rr == nil || rr.Data == nil {
			continue
		}

		rrSize := 12 + len(rr.Name.Labels) + rr.Data.Len() // Approximate
		if size+rrSize > maxSize {
			break
		}
		size += rrSize
		result = append(result, rr)
	}

	return result
}

// Stop gracefully shuts down the server.
func (s *UDPServer) Stop() error {
	s.cancel()

	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// Addr returns the server's listener address.
func (s *UDPServer) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Stats returns server statistics.
func (s *UDPServer) Stats() UDPServerStats {
	return UDPServerStats{
		PacketsReceived: atomic.LoadUint64(&s.packetsReceived),
		PacketsSent:     atomic.LoadUint64(&s.packetsSent),
		Errors:          atomic.LoadUint64(&s.errors),
		Workers:         s.workers,
	}
}

// UDPServerStats contains runtime statistics for the UDP server.
type UDPServerStats struct {
	PacketsReceived uint64
	PacketsSent     uint64
	Errors          uint64
	Workers         int
}
