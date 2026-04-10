package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestRDataSVCBRoundTrip(t *testing.T) {
	target, err := ParseName("svc.example.com.")
	if err != nil {
		t.Fatalf("ParseName failed: %v", err)
	}

	tests := []struct {
		name string
		svcb *RDataSVCB
	}{
		{
			name: "AliasMode_no_params",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   target,
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_alpn_only",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
				},
			},
		},
		{
			name: "ServiceMode_alpn_and_port",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}}, // port 443
				},
			},
		},
		{
			name: "ServiceMode_ipv4hint",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1}},
				},
			},
		},
		{
			name: "ServiceMode_ipv6hint",
			svcb: &RDataSVCB{
				Priority: 2,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "ServiceMode_all_common_params",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1, 198, 51, 100, 2}},
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "ServiceMode_no_default_alpn",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
					{Key: SvcParamKeyNoDefaultALPN, Value: []byte{}},
				},
			},
		},
		{
			name: "ServiceMode_ech",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyECH, Value: []byte{0xAB, 0xCD, 0xEF, 0x01}},
				},
			},
		},
		{
			name: "ServiceMode_dohpath",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyDOHPath, Value: []byte("/dns-query{?dns}")},
				},
			},
		},
		{
			name: "AliasMode_root_target",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   &Name{Labels: []string{}, FQDN: true},
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_mandatory",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x03}}, // alpn, port
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, 512)
			n, err := tt.svcb.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if n != tt.svcb.Len() {
				t.Errorf("Packed %d bytes, expected %d", n, tt.svcb.Len())
			}

			// Unpack
			unpacked := &RDataSVCB{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify Priority
			if unpacked.Priority != tt.svcb.Priority {
				t.Errorf("Priority mismatch: got %d, want %d", unpacked.Priority, tt.svcb.Priority)
			}

			// Verify Target
			if tt.svcb.Target != nil {
				if unpacked.Target == nil {
					t.Fatal("Target is nil after unpack")
				}
				if !strings.EqualFold(tt.svcb.Target.String(), unpacked.Target.String()) {
					t.Errorf("Target mismatch: got %q, want %q", unpacked.Target.String(), tt.svcb.Target.String())
				}
			}

			// Verify Params count
			if len(unpacked.Params) != len(tt.svcb.Params) {
				t.Fatalf("Params count mismatch: got %d, want %d", len(unpacked.Params), len(tt.svcb.Params))
			}

			// Verify each param
			for i, want := range tt.svcb.Params {
				got := unpacked.Params[i]
				if got.Key != want.Key {
					t.Errorf("Param[%d] Key mismatch: got %d, want %d", i, got.Key, want.Key)
				}
				if !bytes.Equal(got.Value, want.Value) {
					t.Errorf("Param[%d] Value mismatch: got %x, want %x", i, got.Value, want.Value)
				}
			}

			// Verify Type
			if unpacked.Type() != TypeSVCB {
				t.Errorf("Type() = %d, want %d", unpacked.Type(), TypeSVCB)
			}

			// Verify String() does not panic
			s := unpacked.String()
			if s == "" {
				t.Error("String() returned empty")
			}

			// Verify Copy
			copied := unpacked.Copy().(*RDataSVCB)
			if copied.Priority != unpacked.Priority {
				t.Error("Copy failed to preserve Priority")
			}
			if len(copied.Params) != len(unpacked.Params) {
				t.Error("Copy failed to preserve Params count")
			}
			for i, p := range copied.Params {
				if !bytes.Equal(p.Value, unpacked.Params[i].Value) {
					t.Errorf("Copy Param[%d] Value mismatch", i)
				}
			}
		})
	}
}

func TestRDataHTTPSRoundTrip(t *testing.T) {
	target, err := ParseName("cdn.example.com.")
	if err != nil {
		t.Fatalf("ParseName failed: %v", err)
	}

	tests := []struct {
		name  string
		https *RDataHTTPS
	}{
		{
			name: "AliasMode",
			https: &RDataHTTPS{
				Priority: 0,
				Target:   target,
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_alpn_port",
			https: &RDataHTTPS{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
		},
		{
			name: "ServiceMode_ipv4_ipv6",
			https: &RDataHTTPS{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{10, 0, 0, 1}},
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "AliasMode_root_target",
			https: &RDataHTTPS{
				Priority: 0,
				Target:   &Name{Labels: []string{}, FQDN: true},
				Params:   nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, 512)
			n, err := tt.https.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if n != tt.https.Len() {
				t.Errorf("Packed %d bytes, expected %d", n, tt.https.Len())
			}

			// Unpack
			unpacked := &RDataHTTPS{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify Priority
			if unpacked.Priority != tt.https.Priority {
				t.Errorf("Priority mismatch: got %d, want %d", unpacked.Priority, tt.https.Priority)
			}

			// Verify Target
			if tt.https.Target != nil {
				if unpacked.Target == nil {
					t.Fatal("Target is nil after unpack")
				}
				if !strings.EqualFold(tt.https.Target.String(), unpacked.Target.String()) {
					t.Errorf("Target mismatch: got %q, want %q", unpacked.Target.String(), tt.https.Target.String())
				}
			}

			// Verify Params count
			if len(unpacked.Params) != len(tt.https.Params) {
				t.Fatalf("Params count mismatch: got %d, want %d", len(unpacked.Params), len(tt.https.Params))
			}

			// Verify each param
			for i, want := range tt.https.Params {
				got := unpacked.Params[i]
				if got.Key != want.Key {
					t.Errorf("Param[%d] Key mismatch: got %d, want %d", i, got.Key, want.Key)
				}
				if !bytes.Equal(got.Value, want.Value) {
					t.Errorf("Param[%d] Value mismatch: got %x, want %x", i, got.Value, want.Value)
				}
			}

			// Verify Type
			if unpacked.Type() != TypeHTTPS {
				t.Errorf("Type() = %d, want %d", unpacked.Type(), TypeHTTPS)
			}

			// Verify String() does not panic
			s := unpacked.String()
			if s == "" {
				t.Error("String() returned empty")
			}

			// Verify Copy
			copied := unpacked.Copy().(*RDataHTTPS)
			if copied.Priority != unpacked.Priority {
				t.Error("Copy failed to preserve Priority")
			}
			if len(copied.Params) != len(unpacked.Params) {
				t.Error("Copy failed to preserve Params count")
			}
		})
	}
}

func TestSVCBCreateRData(t *testing.T) {
	// Verify createRData returns correct types
	svcbRData := createRData(TypeSVCB)
	if svcbRData == nil {
		t.Fatal("createRData(TypeSVCB) returned nil")
	}
	if _, ok := svcbRData.(*RDataSVCB); !ok {
		t.Errorf("createRData(TypeSVCB) returned %T, want *RDataSVCB", svcbRData)
	}

	httpsRData := createRData(TypeHTTPS)
	if httpsRData == nil {
		t.Fatal("createRData(TypeHTTPS) returned nil")
	}
	if _, ok := httpsRData.(*RDataHTTPS); !ok {
		t.Errorf("createRData(TypeHTTPS) returned %T, want *RDataHTTPS", httpsRData)
	}
}

func TestSVCBStringFormat(t *testing.T) {
	target, _ := ParseName("svc.example.com.")

	tests := []struct {
		name     string
		svcb     *RDataSVCB
		contains []string
	}{
		{
			name: "AliasMode",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   target,
			},
			contains: []string{"0", "svc.example.com."},
		},
		{
			name: "alpn_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
				},
			},
			contains: []string{"1", "svc.example.com.", "alpn=", "h2", "h3"},
		},
		{
			name: "port_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
			contains: []string{"port=443"},
		},
		{
			name: "ipv4hint_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1}},
				},
			},
			contains: []string{"ipv4hint=192.0.2.1"},
		},
		{
			name: "ipv6hint_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
			contains: []string{"ipv6hint=2001:db8::1"},
		},
		{
			name: "no_default_alpn",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyNoDefaultALPN, Value: []byte{}},
				},
			},
			contains: []string{"no-default-alpn"},
		},
		{
			name: "dohpath_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyDOHPath, Value: []byte("/dns-query{?dns}")},
				},
			},
			contains: []string{"dohpath=/dns-query{?dns}"},
		},
		{
			name: "mandatory_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x03}},
				},
			},
			contains: []string{"mandatory=alpn,port"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.svcb.String()
			for _, want := range tt.contains {
				if !strings.Contains(s, want) {
					t.Errorf("String() = %q, missing %q", s, want)
				}
			}
		})
	}
}

func TestSVCBPackBufferTooSmall(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
		},
	}

	// Buffer too small for priority
	_, err := svcb.Pack(make([]byte, 1), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for tiny buffer, got %v", err)
	}

	// Buffer too small for name
	_, err = svcb.Pack(make([]byte, 3), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for name, got %v", err)
	}

	// Buffer too small for params
	nameSize := 2 + target.WireLength() // priority + name
	_, err = svcb.Pack(make([]byte, nameSize), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for params, got %v", err)
	}
}

func TestSVCBUnpackBufferTooSmall(t *testing.T) {
	svcb := &RDataSVCB{}

	// Empty buffer
	_, err := svcb.Unpack([]byte{}, 0, 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for empty buffer, got %v", err)
	}

	// Buffer with priority but no name
	_, err = svcb.Unpack([]byte{0x00, 0x01}, 0, 2)
	if err == nil {
		t.Error("expected error for buffer with no name data")
	}

	// Buffer with truncated SvcParam
	// Priority(2) + root name(1) + incomplete param header
	buf := []byte{0x00, 0x01, 0x00, 0x00, 0x01}
	_, err = svcb.Unpack(buf, 0, uint16(len(buf)))
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for truncated param, got %v", err)
	}

	// Buffer with SvcParam header but truncated value
	buf = []byte{0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x05}
	_, err = svcb.Unpack(buf, 0, uint16(len(buf)))
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for truncated param value, got %v", err)
	}
}

func TestSVCBTypeMapEntries(t *testing.T) {
	// Verify TypeToString entries
	if s, ok := TypeToString[TypeSVCB]; !ok || s != "SVCB" {
		t.Errorf("TypeToString[TypeSVCB] = %q, %v; want \"SVCB\", true", s, ok)
	}
	if s, ok := TypeToString[TypeHTTPS]; !ok || s != "HTTPS" {
		t.Errorf("TypeToString[TypeHTTPS] = %q, %v; want \"HTTPS\", true", s, ok)
	}

	// Verify StringToType entries
	if v, ok := StringToType["SVCB"]; !ok || v != TypeSVCB {
		t.Errorf("StringToType[\"SVCB\"] = %d, %v; want %d, true", v, ok, TypeSVCB)
	}
	if v, ok := StringToType["HTTPS"]; !ok || v != TypeHTTPS {
		t.Errorf("StringToType[\"HTTPS\"] = %d, %v; want %d, true", v, ok, TypeHTTPS)
	}
}

func TestSVCBPackUnpackAtOffset(t *testing.T) {
	target, _ := ParseName("example.com.")
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyPort, Value: []byte{0x00, 0x50}}, // port 80
		},
	}

	// Pack at a non-zero offset
	offset := 20
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, offset)
	if err != nil {
		t.Fatalf("Pack at offset %d failed: %v", offset, err)
	}

	// Unpack from the same offset
	unpacked := &RDataSVCB{}
	n2, err := unpacked.Unpack(buf, offset, uint16(n))
	if err != nil {
		t.Fatalf("Unpack at offset %d failed: %v", offset, err)
	}
	if n2 != n {
		t.Errorf("Unpacked %d bytes, expected %d", n2, n)
	}
	if unpacked.Priority != 1 {
		t.Errorf("Priority = %d, want 1", unpacked.Priority)
	}
	if len(unpacked.Params) != 1 || unpacked.Params[0].Key != SvcParamKeyPort {
		t.Error("Params not preserved through offset pack/unpack")
	}
}

func TestSVCBNilTarget(t *testing.T) {
	svcb := &RDataSVCB{
		Priority: 0,
		Target:   nil,
		Params:   nil,
	}

	// Len should handle nil target
	expectedLen := 2 + 1 // priority + root label
	if svcb.Len() != expectedLen {
		t.Errorf("Len() = %d, want %d", svcb.Len(), expectedLen)
	}

	// String should handle nil target
	s := svcb.String()
	if !strings.Contains(s, ".") {
		t.Errorf("String() = %q, expected root target", s)
	}

	// Pack should handle nil target
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack with nil target failed: %v", err)
	}
	if n != expectedLen {
		t.Errorf("Packed %d bytes, expected %d", n, expectedLen)
	}

	// Copy should handle nil target
	copied := svcb.Copy().(*RDataSVCB)
	if copied.Target != nil {
		t.Error("Copy should preserve nil target")
	}
}

func TestSVCBMultipleIPv4Hints(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	// Two IPv4 addresses: 192.0.2.1 and 198.51.100.2
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1, 198, 51, 100, 2}},
		},
	}

	s := svcb.String()
	if !strings.Contains(s, "192.0.2.1") {
		t.Errorf("String() missing first IPv4: %q", s)
	}
	if !strings.Contains(s, "198.51.100.2") {
		t.Errorf("String() missing second IPv4: %q", s)
	}

	// Round-trip
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	unpacked := &RDataSVCB{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}
	if !bytes.Equal(unpacked.Params[0].Value, svcb.Params[0].Value) {
		t.Error("IPv4 hint values not preserved")
	}
}
