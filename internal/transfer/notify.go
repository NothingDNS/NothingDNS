package transfer

import (
	"context"
	"fmt"
	"io"
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
	// SerialUnknown is set when the NOTIFY carried no SOA serial hint
	// (RFC 1996 §3.7): Serial is then meaningless and the slave must check
	// its master as if the refresh timer had expired (§3.11) (F208).
	SerialUnknown bool
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
	timeout    time.Duration // Response timeout per transmission
	// retransmits is how many times an unanswered UDP NOTIFY is resent
	// (RFC 1996 §3.6), each waiting timeout (F209).
	retransmits int
	// tsigKey, when set, signs every outgoing NOTIFY (RFC 8945) (F547).
	tsigKey *TSIGKey
}

// notifyDefaultRetransmits is RFC 1996 §3.6's suggested maximum of 5
// retransmissions.
const notifyDefaultRetransmits = 5

// NewNOTIFYSender creates a new NOTIFY sender
func NewNOTIFYSender(serverAddr string) *NOTIFYSender {
	return &NOTIFYSender{
		serverAddr:  serverAddr,
		timeout:     5 * time.Second,
		retransmits: notifyDefaultRetransmits,
	}
}

// SetTimeout sets the response timeout
func (s *NOTIFYSender) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

// SetTSIGKey makes the sender TSIG-sign every NOTIFY with key (nil: unsigned).
func (s *NOTIFYSender) SetTSIGKey(key *TSIGKey) {
	s.tsigKey = key
}

// SendNOTIFY sends a NOTIFY message to a slave server
// The slave should respond with a matching NOTIFY response
func (s *NOTIFYSender) SendNOTIFY(zoneName string, serial uint32, slaveAddr string) error {
	return s.SendNOTIFYContext(context.Background(), zoneName, serial, slaveAddr)
}

// SendNOTIFYContext is SendNOTIFY with cancellation: when ctx is done the
// socket is closed, any pending wait ends and ctx.Err() is returned (F547).
func (s *NOTIFYSender) SendNOTIFYContext(ctx context.Context, zoneName string, serial uint32, slaveAddr string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Build NOTIFY request message
	req, err := s.buildNOTIFYRequest(zoneName, serial)
	if err != nil {
		return fmt.Errorf("building NOTIFY request: %w", err)
	}
	if s.tsigKey != nil {
		tsigRR, err := SignMessage(req, s.tsigKey, 300)
		if err != nil {
			return fmt.Errorf("signing NOTIFY: %w", err)
		}
		req.Additionals = append(req.Additionals, tsigRR)
	}

	// Send UDP message (NOTIFY uses UDP by default, TCP for large messages)
	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "udp", slaveAddr)
	if err != nil {
		return fmt.Errorf("connecting to slave: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// Pack and send message
	buf := make([]byte, 65535)
	n, err := req.Pack(buf)
	if err != nil {
		return fmt.Errorf("packing NOTIFY request: %w", err)
	}

	// RFC 1996 §3.6: retransmit the same message until it is answered or
	// the retransmissions are exhausted (F209).
	var lastErr error
	for attempt := 0; attempt <= s.retransmits; attempt++ {
		if _, err := writePacket(conn, buf[:n]); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("sending NOTIFY: %w", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("setting read deadline: %w", err)
		}
		done, err := awaitNOTIFYResponse(conn, req.Header.ID)
		if done {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		lastErr = err
	}
	return lastErr
}

// awaitNOTIFYResponse reads until the read deadline. Datagrams that are not
// a reply to this request (unparseable or a different ID, e.g. a stale or
// spoofed reply) are discarded and reading continues (F210). It returns
// done=false with the read error when no matching reply arrived in time.
func awaitNOTIFYResponse(conn net.Conn, id uint16) (bool, error) {
	respBuf := make([]byte, 65535)
	var discarded error
	for {
		n, err := conn.Read(respBuf)
		if err != nil {
			if discarded != nil {
				return false, fmt.Errorf("reading NOTIFY response: %w (discarded: %w)", err, discarded)
			}
			return false, fmt.Errorf("reading NOTIFY response: %w", err)
		}

		resp, err := protocol.UnpackMessage(respBuf[:n])
		if err != nil {
			discarded = fmt.Errorf("unpacking NOTIFY response: %w", err)
			continue
		}

		// The request uses a random transaction ID (RFC 1996 §3.2.2 /
		// RFC 1035 §4.1.1) so a response can be bound to its request; a
		// mismatched ID is not our reply and must neither succeed nor
		// fail this NOTIFY.
		if resp.Header.ID != id {
			discarded = fmt.Errorf("NOTIFY response ID mismatch: got %d, want %d", resp.Header.ID, id)
			resp.Release()
			continue
		}
		err = checkNOTIFYResponse(resp)
		resp.Release()
		return true, err
	}
}

// checkNOTIFYResponse validates a reply whose ID matches the request.
func checkNOTIFYResponse(resp *protocol.Message) error {
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

func writePacket(conn net.Conn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
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
	zones           map[string]*zone.Zone
	zonesMu         *sync.RWMutex
	notifyChan      chan *NOTIFYRequest
	serialCheck     SerialChecker
	closeOnce       sync.Once
	notifyAllowList []net.IPNet // authorized master IPs
	keyStore        *KeyStore   // TSIG keys for authentication (VULN-061)
}

// SerialChecker is called to check if the serial has changed
type SerialChecker func(zoneName string, serial uint32) bool

// NewNOTIFYSlaveHandler creates a new NOTIFY handler for slave servers
func NewNOTIFYSlaveHandler(zones map[string]*zone.Zone) *NOTIFYSlaveHandler {
	return &NOTIFYSlaveHandler{
		zones:      zones,
		zonesMu:    &sync.RWMutex{},
		notifyChan: make(chan *NOTIFYRequest, 100),
	}
}

// SetZonesMu sets an external mutex to protect the shared zones map.
// Use this when multiple components share the same zones map.
func (h *NOTIFYSlaveHandler) SetZonesMu(mu *sync.RWMutex) {
	h.zonesMu = mu
}

// AddNotifyAllowed adds an authorized master IP or CIDR range.
func (h *NOTIFYSlaveHandler) AddNotifyAllowed(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as a single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid NOTIFY allowed CIDR/IP: %s", cidr)
		}
		if ip.To4() != nil {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}
	h.notifyAllowList = append(h.notifyAllowList, *ipNet)
	return nil
}

// SetKeyStore sets the TSIG key store for NOTIFY authentication.
// When keys are configured, all NOTIFY requests must be TSIG-signed.
func (h *NOTIFYSlaveHandler) SetKeyStore(ks *KeyStore) {
	h.keyStore = ks
}

// isNOTIFYAllowed checks if the given IP is authorized to send NOTIFY.
// If no allowlist is configured, NOTIFY is denied by default (fail closed).
func (h *NOTIFYSlaveHandler) isNOTIFYAllowed(ip net.IP) bool {
	if len(h.notifyAllowList) == 0 {
		return false
	}
	for _, allowed := range h.notifyAllowList {
		if allowed.Contains(ip) {
			return true
		}
	}
	return false
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
	if req == nil {
		return nil, fmt.Errorf("nil NOTIFY request")
	}

	// Check if client IP is authorized
	if !h.isNOTIFYAllowed(clientIP) {
		return h.createNOTIFYResponse(req, protocol.RcodeRefused), nil
	}

	// Verify TSIG — if keyStore has keys, TSIG is required for NOTIFY (VULN-061)
	if h.keyStore != nil && h.keyStore.HasKeys() {
		if !hasTSIG(req) {
			return h.createNOTIFYResponse(req, protocol.RcodeRefused), fmt.Errorf("TSIG authentication required for NOTIFY")
		}
		keyName, err := getTSIGKeyName(req)
		if err != nil {
			return h.createNOTIFYResponse(req, protocol.RcodeFormatError), fmt.Errorf("getting TSIG key name: %w", err)
		}
		key, ok := h.keyStore.GetKey(keyName)
		if !ok {
			return h.createNOTIFYResponse(req, protocol.RcodeNotAuth), fmt.Errorf("TSIG key not found: %s", keyName)
		}
		if err := h.keyStore.ValidateKeySource(keyName, clientIP); err != nil {
			return h.createNOTIFYResponse(req, protocol.RcodeNotAuth), fmt.Errorf("TSIG client IP check failed: %w", err)
		}
		if err := VerifyMessage(req, key, nil); err != nil {
			return h.createNOTIFYResponse(req, protocol.RcodeNotAuth), fmt.Errorf("TSIG verification failed: %w", err)
		}
	}

	// Validate request
	if len(req.Questions) != 1 || req.Questions[0] == nil || req.Questions[0].Name == nil {
		return h.createNOTIFYResponse(req, protocol.RcodeFormatError), fmt.Errorf("NOTIFY requires exactly one valid question")
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

	// Extract serial from Answer section. Serial 0 is a valid RFC 1982
	// serial, so presence is tracked separately (F207).
	var receivedSerial uint32
	haveSerial := false
	for _, rr := range req.Answers {
		if rr == nil {
			continue
		}
		if rr.Type == protocol.TypeSOA {
			if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
				receivedSerial = soaData.Serial
				haveSerial = true
				break
			}
		}
	}

	// If no serial in Answer section, check Authority section (older implementations)
	if !haveSerial {
		for _, rr := range req.Authorities {
			if rr == nil {
				continue
			}
			if rr.Type == protocol.TypeSOA {
				if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
					receivedSerial = soaData.Serial
					haveSerial = true
					break
				}
			}
		}
	}

	// Check if this is a new serial. Without a serial hint the NOTIFY is
	// still a change signal (RFC 1996 §3.11): forward it as SerialUnknown
	// instead of comparing the local serial with itself (F208).
	needsUpdate := true
	if !haveSerial {
		needsUpdate = true
	} else if h.serialCheck != nil {
		needsUpdate = h.serialCheck(zoneName, receivedSerial)
	} else if z.SOA != nil && !serialIsNewer(receivedSerial, z.SOA.Serial) {
		// If the received serial is not strictly newer per RFC 1982, no update
		// is needed. Using plain '<=' would mis-handle the 2^32 wraparound.
		needsUpdate = false
	}

	// Only send NOTIFY event if update is needed
	if needsUpdate {
		select {
		case h.notifyChan <- &NOTIFYRequest{
			ZoneName:      zoneName,
			Serial:        receivedSerial,
			ClientIP:      clientIP,
			SerialUnknown: !haveSerial,
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
	if req == nil {
		return &protocol.Message{
			Header: protocol.Header{
				Flags: flags,
			},
		}
	}
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
	if msg == nil {
		return false
	}
	return msg.Header.Flags.Opcode == protocol.OpcodeNotify && !msg.Header.Flags.QR
}

// IsNOTIFYResponse checks if a message is a NOTIFY response
func IsNOTIFYResponse(msg *protocol.Message) bool {
	if msg == nil {
		return false
	}
	return msg.Header.Flags.Opcode == protocol.OpcodeNotify && msg.Header.Flags.QR
}
