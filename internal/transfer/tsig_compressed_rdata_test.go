package transfer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// BIND compresses the domain names inside the RDATA of CNAME/MX/NS/PTR
// records; Message.Pack does not. A TSIG MAC covers the bytes on the wire
// (RFC 8945 §5.3), so verifying a re-packed copy rejected every signed UPDATE
// that adds such a record with an in-zone target (nsupdate: NOTAUTH).
func TestVerifyMessageDigestsReceivedBytes(t *testing.T) {
	key := &TSIGKey{Name: "compress-key.example.", Algorithm: HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}

	// header: ID, OPCODE UPDATE, ZOCOUNT 1, UPCOUNT 1 (in NSCOUNT), ADCOUNT 0
	wire := []byte{0x12, 0x34, 5 << 3, 0, 0, 1, 0, 0, 0, 1, 0, 0}
	// zone section: sl.example. SOA IN, the name starts at offset 12
	wire = append(wire, 2, 's', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 6, 0, 1)
	// update: c2.sl.example. CNAME IN 60 -> www.sl.example., both names
	// compressed against the zone name
	wire = append(wire, 2, 'c', '2', 0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 'w', 'w', 'w', 0xC0, 12)

	keyWire := []byte{12, 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', '-', 'k', 'e', 'y', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	algoWire := []byte{11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0}
	now := time.Now().Unix()
	timeSigned := []byte{0, 0, byte(now >> 24), byte(now >> 16), byte(now >> 8), byte(now)}
	vars := append([]byte{}, keyWire...)
	vars = append(vars, 0, 255, 0, 0, 0, 0) // CLASS ANY, TTL 0
	vars = append(vars, algoWire...)
	vars = append(vars, timeSigned...)
	vars = append(vars, 0x01, 0x2C, 0, 0, 0, 0) // fudge 300, error 0, other len 0

	mac := hmac.New(sha256.New, key.Secret)
	mac.Write(wire)
	mac.Write(vars)
	sum := mac.Sum(nil)

	rdata := append([]byte{}, algoWire...)
	rdata = append(rdata, timeSigned...)
	rdata = append(rdata, 0x01, 0x2C, 0, 32)
	rdata = append(rdata, sum...)
	rdata = append(rdata, 0x12, 0x34, 0, 0, 0, 0) // original ID, error, other len
	signed := append([]byte{}, wire...)
	binary.BigEndian.PutUint16(signed[10:12], 1)
	signed = append(signed, keyWire...)
	signed = append(signed, 0, 250, 0, 255, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata)))
	signed = append(signed, rdata...)

	msg, err := protocol.UnpackMessage(signed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if err := VerifyMessage(msg, key, nil); err != nil {
		t.Fatalf("a correctly signed UPDATE with compressed RDATA names was rejected: %v", err)
	}

	// Tampering with the received bytes must still fail.
	signed[len(wire)-9] ^= 1 // the record TTL
	bad, err := protocol.UnpackMessage(signed)
	if err != nil {
		t.Fatalf("unpack tampered: %v", err)
	}
	if err := VerifyMessage(bad, key, nil); err == nil {
		t.Fatal("a tampered message verified")
	}
}
