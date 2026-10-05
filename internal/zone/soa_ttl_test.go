package zone

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const soaTTLTestRData = "ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300"

func parseSOATTLTestZone(t *testing.T, ttl string) *Zone {
	t.Helper()
	text := "$ORIGIN example.test.\n$TTL 3600\n@ " + ttl + " IN SOA " + soaTTLTestRData + "\n"
	z, err := ParseFile("soa-ttl.zone", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func expectedSOATTLTestDigest(t *testing.T, ttl uint32) []byte {
	t.Helper()
	rd := protocol.ParseRDataText("SOA", soaTTLTestRData)
	if rd == nil {
		t.Fatal("SOA fixture did not parse")
	}
	data := make([]byte, rd.Len())
	if _, err := rd.Pack(data, 0); err != nil {
		t.Fatal(err)
	}
	wire := protocol.CanonicalWireName("example.test.")
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header, protocol.TypeSOA)
	binary.BigEndian.PutUint16(header[2:], protocol.ClassIN)
	binary.BigEndian.PutUint32(header[4:], ttl)
	binary.BigEndian.PutUint16(header[8:], uint16(len(data)))
	wire = append(wire, header...)
	wire = append(wire, data...)
	digest := sha512.Sum384(wire)
	return digest[:]
}

func TestSOATTLExportAndDigestPreserveStoredTTL(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  uint32
	}{{"0", 0}, {"300", 300}, {"", 3600}} {
		t.Run(fmt.Sprintf("ttl_%q", tc.field), func(t *testing.T) {
			z := parseSOATTLTestZone(t, tc.field)
			text, err := WriteZone(z)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseFile("export.zone", strings.NewReader(text))
			if err != nil {
				t.Fatal(err)
			}
			if got.SOA.TTL != tc.want {
				t.Fatalf("export SOA TTL=%d want %d", got.SOA.TTL, tc.want)
			}
			md, err := ComputeZoneMD(z, ZONEMDSHA384)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(md.Hash, expectedSOATTLTestDigest(t, tc.want)) {
				t.Fatal("digest differs from independent canonical SOA wire bytes")
			}
		})
	}
}

func TestSOATTLProgrammaticFallback(t *testing.T) {
	z := parseSOATTLTestZone(t, "0")
	z.Records = make(map[string][]Record)
	text, err := WriteZone(z)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile("export.zone", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if got.SOA.TTL != 3600 {
		t.Fatalf("programmatic SOA fallback TTL=%d want3600", got.SOA.TTL)
	}
	md, err := ComputeZoneMD(z, ZONEMDSHA384)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(md.Hash, expectedSOATTLTestDigest(t, 3600)) {
		t.Fatal("programmatic SOA fallback digest changed")
	}
}
