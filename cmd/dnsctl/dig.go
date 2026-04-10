package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func cmdDig(args []string) error {
	// Parse dig-style arguments: [@server] <name> [<type>] [+dnssec]
	var server string
	var qname string
	var qtypeStr string
	var wantDNSSEC bool

	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			server = arg[1:]
		} else if strings.HasPrefix(arg, "+") {
			switch strings.ToLower(arg) {
			case "+dnssec":
				wantDNSSEC = true
			case "+cd":
				// checking disabled - ignored for now
			}
		} else if qname == "" {
			qname = arg
		} else if qtypeStr == "" {
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

	// Set DO bit if DNSSEC requested
	if wantDNSSEC {
		msg.Additionals = []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeOPT,
				Class: 4096,   // UDP payload size
				TTL:   0x8000, // DO bit set
			},
		}
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
	if _, err := conn.Write(buf[:n]); err != nil {
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

	// Display results
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
		fmt.Printf(";%s\t\t%s\t%s\n", q.Name.String(), "IN", protocol.TypeString(q.QType))
	}
	fmt.Println()

	// Answer section
	if len(resp.Answers) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, rr := range resp.Answers {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	// Authority section
	if len(resp.Authorities) > 0 {
		fmt.Println(";; AUTHORITY SECTION:")
		for _, rr := range resp.Authorities {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	// Additional section
	if len(resp.Additionals) > 0 {
		fmt.Println(";; ADDITIONAL SECTION:")
		for _, rr := range resp.Additionals {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	fmt.Printf(";; Query time: ~0ms\n")
	fmt.Printf(";; SERVER: %s#53\n", server)
	fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))

	return nil
}
