package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type fetchDNSKEYCopyResolver struct{ msg *protocol.Message }

func (r *fetchDNSKEYCopyResolver) Query(context.Context, string, uint16) (*protocol.Message, error) {
	return r.msg, nil
}

func TestFetchDNSKEYReturnsOwnedCopies_F824(t *testing.T) {
	name, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	msg := protocol.AcquireMessage()
	msg.Answers = append(msg.Answers, &protocol.ResourceRecord{
		Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: protocol.AlgorithmECDSAP256SHA256, PublicKey: []byte{1, 2, 3}},
	})

	v := NewValidator(DefaultValidatorConfig(), nil, &fetchDNSKEYCopyResolver{msg: msg})
	keys, err := v.fetchDNSKEY(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	defer keys[0].Release()
	dnskey, ok := keys[0].Data.(*protocol.RDataDNSKEY)
	if keys[0].Name == nil || keys[0].Name.String() != "example.com." ||
		keys[0].Type != protocol.TypeDNSKEY || !ok || dnskey.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Fatalf("returned key was cleared with its source message: %+v", keys[0])
	}
	if len(msg.Answers) != 0 {
		t.Fatal("source message was not released")
	}
}
