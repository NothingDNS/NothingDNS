package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// digQueryTCP performs a single-shot DNS-over-TCP query (RFC 1035
// §4.2.2 two-byte length prefix) and returns the parsed response.
// Used by cmdDig when the UDP response has the TC bit set.
func digQueryTCP(addr string, query []byte) (*protocol.Message, error) {
	if len(query) > 0xffff {
		return nil, fmt.Errorf("tcp query too large: %d bytes (max 65535)", len(query))
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
	if err := util.WriteFull(conn, prefix[:]); err != nil {
		return nil, fmt.Errorf("write tcp len-prefix: %w", err)
	}
	if err := util.WriteFull(conn, query); err != nil {
		return nil, fmt.Errorf("write tcp body: %w", err)
	}

	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, fmt.Errorf("read tcp len-prefix: %w", err)
	}
	respLen := binary.BigEndian.Uint16(prefix[:])
	if respLen == 0 {
		return nil, fmt.Errorf("tcp response empty")
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("read tcp body: %w", err)
	}
	return protocol.UnpackMessage(respBuf)
}

func cmdDig(args []string) error {
	// Parse dig-style arguments: [@server] <name> [<type>] [+dnssec]
	var server string
	var qname string
	var qtypeStr string
	var wantDNSSEC bool

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "@"):
			server = arg[1:]
		case strings.HasPrefix(arg, "+"):
			switch strings.ToLower(arg) {
			case "+dnssec":
				wantDNSSEC = true
			case "+cd":
				// checking disabled - ignored for now
			}
		case strings.HasPrefix(arg, "-"):
			// dig uses positional @server / +flag syntax — not GNU long
			// flags. Catching this here avoids a confusing
			// "unsupported query type: --server" later on when a user
			// reaches for the flag form by reflex.
			return fmt.Errorf("dig uses positional syntax — try @%s instead of %s", strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")+"=value", arg)
		case qname == "":
			qname = arg
		case qtypeStr == "":
			qtypeStr = strings.ToUpper(arg)
		}
	}

	if qname == "" {
		return fmt.Errorf("query name required: dnsctl dig [@server] <name> [<type>]")
	}
	if server == "" {
		server = "127.0.0.1"
	}
	if qtypeStr == "" {
		qtypeStr = "A"
	}

	// Resolve query type
	qtype, ok := protocol.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		return fmt.Errorf("unsupported query type: %s", qtypeStr)
	}

	// Parse the query name
	qname = strings.TrimSuffix(qname, ".")
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	name, err := protocol.ParseName(qname)
	if err != nil {
		return fmt.Errorf("invalid name %q: %w", qname, err)
	}

	// Build query message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      uint16(time.Now().UnixNano() & 0xFFFF),
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  qtype,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Set DO bit if DNSSEC requested. Use the protocol.SetEDNS0 helper
	// rather than open-coding the OPT record: that helper sets the
	// OPT owner name to root ("."), as RFC 6891 §6.1.2 requires.
	// The previous code attached the query name as the OPT owner,
	// which an RFC-strict resolver may reject as malformed (the wire
	// bytes are still parseable, but a peer that validates OPT owner
	// per spec sees a violation and may drop the EDNS0 option set
	// entirely — losing the DO bit and silently demoting the query
	// to a non-DNSSEC one).
	if wantDNSSEC {
		msg.SetEDNS0(4096, true)
	}

	// Pack message
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		return fmt.Errorf("packing query: %w", err)
	}

	// Send via UDP
	addr := server
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}
	if _, err := writePacket(conn, buf[:n]); err != nil {
		return fmt.Errorf("sending query: %w", err)
	}

	// Read response
	respBuf := make([]byte, 65535)
	respN, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Unpack response
	resp, err := protocol.UnpackMessage(respBuf[:respN])
	if err != nil {
		return fmt.Errorf("unpacking response: %w", err)
	}

	// RFC 1035 §4.2.1: if the UDP response has TC=1, the answer was
	// truncated and the caller is expected to retry over TCP. Real `dig`
	// does this automatically; without it our subcommand silently drops
	// records the daemon explicitly told us to refetch. Try once.
	if resp.Header.Flags.TC {
		if tcpResp, tcpErr := digQueryTCP(addr, buf[:n]); tcpErr == nil {
			resp = tcpResp
		} else {
			fmt.Fprintf(os.Stderr, ";; warning: UDP response truncated and TCP retry failed: %v\n", tcpErr)
		}
	}

	defer resp.Release()
	printDigResponse(qname, qtypeStr, server, addr, wantDNSSEC, resp)
	return nil
}

func printDigResponse(qname, qtypeStr, server, addr string, wantDNSSEC bool, resp *protocol.Message) {
	fmt.Printf("; Query: %s %s @%s\n", qname, qtypeStr, server)
	if wantDNSSEC {
		fmt.Println("; +dnssec")
	}
	fmt.Println()

	// Header
	fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n",
		protocol.RcodeString(int(resp.Header.Flags.RCODE)), resp.Header.ID)
	fmt.Printf(";; flags: qr")
	if resp.Header.Flags.AA {
		fmt.Printf(" aa")
	}
	if resp.Header.Flags.TC {
		fmt.Printf(" tc")
	}
	if resp.Header.Flags.RD {
		fmt.Printf(" rd")
	}
	if resp.Header.Flags.RA {
		fmt.Printf(" ra")
	}
	if resp.Header.Flags.AD {
		fmt.Printf(" ad")
	}
	if resp.Header.Flags.CD {
		fmt.Printf(" cd")
	}
	fmt.Printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		resp.Header.QDCount, resp.Header.ANCount, resp.Header.NSCount, resp.Header.ARCount)
	fmt.Println()

	// Question section
	fmt.Println(";; QUESTION SECTION:")
	for _, q := range resp.Questions {
		printDigQuestion(q)
	}
	fmt.Println()

	// Answer section
	if len(resp.Answers) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, rr := range resp.Answers {
			printDigRR(rr)
		}
		fmt.Println()
	}

	// Authority section
	if len(resp.Authorities) > 0 {
		fmt.Println(";; AUTHORITY SECTION:")
		for _, rr := range resp.Authorities {
			printDigRR(rr)
		}
		fmt.Println()
	}

	// Additional section
	if len(resp.Additionals) > 0 {
		fmt.Println(";; ADDITIONAL SECTION:")
		for _, rr := range resp.Additionals {
			printDigRR(rr)
		}
		fmt.Println()
	}

	fmt.Printf(";; Query time: ~0ms\n")
	// `addr` is the host:port we actually dialed (server, plus :53 if
	// the user didn't include one). Splitting it back out keeps the
	// dig-style "SERVER: host#port" output honest when a non-53 port
	// is in play (the previous hard-coded #53 lied to operators using
	// 5353/15353 for local testing).
	if host, port, splitErr := net.SplitHostPort(addr); splitErr == nil {
		fmt.Printf(";; SERVER: %s#%s\n", host, port)
	} else {
		fmt.Printf(";; SERVER: %s\n", addr)
	}
	fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
}

func printDigQuestion(q *protocol.Question) {
	if q == nil {
		fmt.Printf(";%s\t\t%s\t%s\n", "<nil>", "IN", "UNKNOWN")
		return
	}
	name := "<nil>"
	if q.Name != nil {
		name = q.Name.String()
	}
	fmt.Printf(";%s\t\t%s\t%s\n", name, "IN", protocol.TypeString(q.QType))
}

func printDigRR(rr *protocol.ResourceRecord) {
	if rr == nil {
		fmt.Printf("%s\t%d\t%s\t%s\t%s\n", "<nil>", 0, "IN", "UNKNOWN", "; NODATA")
		return
	}
	name := "<nil>"
	if rr.Name != nil {
		name = rr.Name.String()
	}
	fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
		name, rr.TTL, "IN", protocol.TypeString(rr.Type), formatDigRData(rr.Data))
}

func formatDigRData(data protocol.RData) string {
	if isNilDigRData(data) {
		return "; NODATA"
	}
	return data.String()
}

func isNilDigRData(data protocol.RData) bool {
	if data == nil {
		return true
	}
	value := reflect.ValueOf(data)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func writePacket(conn net.Conn, data []byte) (int, error) {
	n, err := conn.Write(data)
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
