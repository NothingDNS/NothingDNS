package transfer

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// NOTIFYRequest represents a DNS NOTIFY request
// RFC 1996 - A Mechanism for Prompt Notification of Zone Changes
// NOTIFY messages inform slave servers that a zone has changed
type NOTIFYRequest struct {
	ZoneName string
	Serial   uint32 // SOA serial of the zone
	ClientIP net.IP
}

// NOTIFYResponse represents the result of a NOTIFY request
type NOTIFYResponse struct {
	Success  bool
	Message  string
	ZoneName string
}

// NOTIFYSender sends NOTIFY messages to slave servers
type NOTIFYSender struct {
	serverAddr string        // Address to send from (usually ":53")
	timeout    time.Duration // Response timeout
}

// NewNOTIFYSender creates a new NOTIFY sender
func NewNOTIFYSender(serverAddr string) *NOTIFYSender {
	return &NOTIFYSender{
		serverAddr: serverAddr,
		timeout:    5 * time.Second,
	}
}

// SetTimeout sets the response timeout
func (s *NOTIFYSender) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

// SendNOTIFY sends a NOTIFY message to a slave server
// The slave should respond with a matching NOTIFY response
func (s *NOTIFYSender) SendNOTIFY(zoneName string, serial uint32, slaveAddr string) error {
	// Build NOTIFY request message
	req, err := s.buildNOTIFYRequest(zoneName, serial)
	if err != nil {
		return fmt.Errorf("building NOTIFY request: %w", err)
	}

	// Send UDP message (NOTIFY uses UDP by default, TCP for large messages)
	conn, err := net.DialTimeout("udp", slaveAddr, s.timeout)
	if err != nil {
		return fmt.Errorf("connecting to slave: %w", err)
	}
	defer conn.Close()

	// Pack and send message
	buf := make([]byte, 65535)
	n, err := req.Pack(buf)
	if err != nil {
		return fmt.Errorf("packing NOTIFY request: %w", err)
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("sending NOTIFY: %w", err)
	}

	// Wait for response
	if err := conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	respBuf := make([]byte, 65535)
	n, err = conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("reading NOTIFY response: %w", err)
	}

	// Parse response
	resp, err := protocol.UnpackMessage(respBuf[:n])
	if err != nil {
		return fmt.Errorf("unpacking NOTIFY response: %w", err)
	}

	// Check response
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		return fmt.Errorf("NOTIFY failed with rcode: %d", resp.Header.Flags.RCODE)
	}

	// Verify it's a NOTIFY response (QR=1, Opcode=NOTIFY)
	if !resp.Header.Flags.QR {
		return fmt.Errorf("invalid NOTIFY response: QR bit not set")
	}

	if resp.Header.Flags.Opcode != protocol.OpcodeNotify {
		return fmt.Errorf("invalid NOTIFY response: opcode mismatch")
	}

	return nil
}

// buildNOTIFYRequest builds a NOTIFY request message
func (s *NOTIFYSender) buildNOTIFYRequest(zoneName string, serial uint32) (*protocol.Message, error) {
	name, err := protocol.ParseName(zoneName)
	if err != nil {
		return nil, err
	}

	// Create NOTIFY request per RFC 1996:
	// - QR=0 (query), Opcode=NOTIFY
	// - Question section: zone name, type=SOA, class=IN
	// - Answer section: SOA record with current serial
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      generateMessageID(),
			QDCount: 1,
			ANCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Add SOA record in Answer section
	origin, err := protocol.ParseName(zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid zone name %q: %w", zoneName, err)
	}
	mname, err := protocol.ParseName("ns1." + zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid mname: %w", err)
	}
	rname, err := protocol.ParseName("admin." + zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid rname: %w", err)
	}

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  serial,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}

	msg.Answers = append(msg.Answers, soaRR)

	return msg, nil
}

// NOTIFYSlaveHandler handles incoming NOTIFY requests on slave servers
type NOTIFYSlaveHandler struct {
	zones       map[string]*zone.Zone
	zonesMu     sync.RWMutex
	notifyChan  chan *NOTIFYRequest
	serialCheck SerialChecker
	closeOnce   sync.Once
}

// SerialChecker is called to check if the serial has changed
type SerialChecker func(zoneName string, serial uint32) bool

// NewNOTIFYSlaveHandler creates a new NOTIFY handler for slave servers
func NewNOTIFYSlaveHandler(zones map[string]*zone.Zone) *NOTIFYSlaveHandler {
	return &NOTIFYSlaveHandler{
		zones:      zones,
		notifyChan: make(chan *NOTIFYRequest, 100),
	}
}

// SetSerialChecker sets the function used to check serial numbers
func (h *NOTIFYSlaveHandler) SetSerialChecker(checker SerialChecker) {
	h.serialCheck = checker
}

// Close shuts down the handler, closing the notify channel.
func (h *NOTIFYSlaveHandler) Close() {
	h.closeOnce.Do(func() {
		close(h.notifyChan)
	})
}

// GetNotifyChannel returns the channel that receives NOTIFY events
// Callers can listen on this channel to trigger zone transfers
func (h *NOTIFYSlaveHandler) GetNotifyChannel() <-chan *NOTIFYRequest {
	return h.notifyChan
}

// HandleNOTIFY processes an incoming NOTIFY request
// Returns the response to send back to the master
func (h *NOTIFYSlaveHandler) HandleNOTIFY(req *protocol.Message, clientIP net.IP) (*protocol.Message, error) {
	// Validate request
	if len(req.Questions) != 1 {
		return nil, fmt.Errorf("NOTIFY requires exactly one question")
	}

	question := req.Questions[0]
	if question.QType != protocol.TypeSOA {
		return nil, fmt.Errorf("NOTIFY question type must be SOA")
	}

	zoneName := strings.ToLower(question.Name.String())

	// Check if we have this zone configured as a slave
	h.zonesMu.RLock()
	z, ok := h.zones[zoneName]
	h.zonesMu.RUnlock()
	if !ok {
		return h.createNOTIFYResponse(req, protocol.RcodeNotAuth), nil
	}

	// Extract serial from Answer section
	var receivedSerial uint32
	for _, rr := range req.Answers {
		if rr.Type == protocol.TypeSOA {
			if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
				receivedSerial = soaData.Serial
				break
			}
		}
	}

	// If no serial in Answer section, check Authority section (older implementations)
	if receivedSerial == 0 {
		for _, rr := range req.Authorities {
			if rr.Type == protocol.TypeSOA {
				if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
					receivedSerial = soaData.Serial
					break
				}
			}
		}
	}

	// If we still don't have a serial, check our local zone
	if receivedSerial == 0 && z.SOA != nil {
		receivedSerial = z.SOA.Serial
	}

	// Check if this is a new serial
	needsUpdate := true
	if h.serialCheck != nil {
		needsUpdate = h.serialCheck(zoneName, receivedSerial)
	} else if z.SOA != nil && receivedSerial <= z.SOA.Serial {
		// If we have the zone and serial hasn't increased, no update needed
		needsUpdate = false
	}

	// Only send NOTIFY event if update is needed
	if needsUpdate {
		select {
		case h.notifyChan <- &NOTIFYRequest{
			ZoneName: zoneName,
			Serial:   receivedSerial,
			ClientIP: clientIP,
		}:
		default:
			// Channel full, log but don't block
		}
	}

	// Return success response
	resp := h.createNOTIFYResponse(req, protocol.RcodeSuccess)
	return resp, nil
}

// createNOTIFYResponse creates a NOTIFY response message
// Per RFC 1996 Section 3: the response MUST have QR=1, Opcode=NOTIFY, and AA=1.
func (h *NOTIFYSlaveHandler) createNOTIFYResponse(req *protocol.Message, rcode uint8) *protocol.Message {
	flags := protocol.NewResponseFlags(rcode)
	flags.AA = true
	flags.Opcode = protocol.OpcodeNotify
	return &protocol.Message{
		Header: protocol.Header{
			ID:    req.Header.ID,
			Flags: flags,
		},
		Questions: req.Questions,
	}
}

// IsNOTIFYRequest checks if a message is a NOTIFY request
func IsNOTIFYRequest(msg *protocol.Message) bool {
	return msg.Header.Flags.Opcode == protocol.OpcodeNotify && !msg.Header.Flags.QR
}

// IsNOTIFYResponse checks if a message is a NOTIFY response
func IsNOTIFYResponse(msg *protocol.Message) bool {
	return msg.Header.Flags.Opcode == protocol.OpcodeNotify && msg.Header.Flags.QR
}
