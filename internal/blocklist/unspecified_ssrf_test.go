package blocklist

import "testing"

func TestValidateBlocklistURLRejectsUnspecifiedIPv4_F826(t *testing.T) {
	if err := validateBlocklistURL("https://0.0.0.0/list.txt"); err == nil {
		t.Fatal("unspecified IPv4 blocklist URL was accepted")
	}
	if err := validateBlocklistURL("https://1.1.1.1/list.txt"); err != nil {
		t.Fatalf("public IPv4 control was rejected: %v", err)
	}
}
