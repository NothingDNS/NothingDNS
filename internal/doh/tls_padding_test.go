package doh

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// The handlers the API server registers (NewHandler, NewWSHandler) pad the
// answer to a padded query over TLS and never in cleartext (RFC 7830 §4, §6;
// F737).

func tlsPadDNS() server.Handler {
	return server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: r.Questions,
		}
		resp.SetEDNS0(1232, false)
		w.Write(resp)
	})
}

func tlsPadQuery(t *testing.T, pad bool) []byte {
	q, err := protocol.NewQuery(0, "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	q.SetEDNS0(1232, false)
	if pad {
		q.GetOPT().Data.(*protocol.RDataOPT).AddOption(protocol.OptionCodePadding, make([]byte, 64))
	}
	buf := make([]byte, 512)
	n, _ := q.Pack(buf)
	return buf[:n]
}

type tlsPadWSClient struct {
	conn net.Conn
	br   *bufio.Reader
}

func tlsPadDial(t *testing.T, srv *httptest.Server, useTLS bool) *tlsPadWSClient {
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("tcp", srv.Listener.Addr().String())
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /dns-ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade failed: %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return &tlsPadWSClient{conn: conn, br: br}
}

func (c *tlsPadWSClient) ask(t *testing.T, q []byte) []byte {
	mask := []byte{9, 8, 7, 6}
	frame := []byte{0x82, 0x80 | byte(len(q))}
	frame = append(frame, mask...)
	for i, b := range q {
		frame = append(frame, b^mask[i%4])
	}
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := int(hdr[1] & 0x7f)
	if n == 126 {
		var ext [2]byte
		io.ReadFull(c.br, ext[:])
		n = int(binary.BigEndian.Uint16(ext[:]))
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(c.br, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func tlsPadCount(t *testing.T, wire []byte) int {
	m, err := protocol.UnpackMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	c := 0
	if opt := m.GetOPT(); opt != nil {
		for _, o := range opt.Data.(*protocol.RDataOPT).Options {
			if o.Code == protocol.OptionCodePadding {
				c++
			}
		}
	}
	return c
}

func TestDoHAndDoWSPadOverTLSOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/dns-query", NewHandler(tlsPadDNS()))
	mux.Handle("/dns-ws", NewWSHandler(tlsPadDNS(), nil))
	tlsSrv := httptest.NewTLSServer(mux)
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(mux)
	defer plainSrv.Close()
	padQ, plainQ := tlsPadQuery(t, true), tlsPadQuery(t, false)

	// DoWS over TLS: repeated padded queries on one connection, one option each;
	// an unpadded query in between stays unpadded.
	c := tlsPadDial(t, tlsSrv, true)
	for i, q := range [][]byte{padQ, plainQ, padQ, padQ} {
		want := 1
		if i == 1 {
			want = 0
		}
		if got := tlsPadCount(t, c.ask(t, q)); got != want {
			t.Fatalf("DoWS/TLS query %d: %d padding options, want %d", i, got, want)
		}
	}
	c.conn.Close()

	// Cleartext DoWS never pads (RFC 7830 §6).
	c = tlsPadDial(t, plainSrv, false)
	if got := tlsPadCount(t, c.ask(t, padQ)); got != 0 {
		t.Fatalf("cleartext DoWS padded (%d options)", got)
	}
	c.conn.Close()

	// DoH GET over TLS pads; cleartext GET does not.
	enc := base64.RawURLEncoding.EncodeToString(padQ)
	for _, tc := range []struct {
		srv  *httptest.Server
		want int
	}{{tlsSrv, 1}, {plainSrv, 0}} {
		resp, err := tc.srv.Client().Get(tc.srv.URL + "/dns-query?dns=" + enc)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := tlsPadCount(t, b); got != tc.want {
			t.Fatalf("DoH GET %s: %d padding options, want %d", tc.srv.URL, got, tc.want)
		}
	}
}
