package dns64

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func filteredAAAAAD(t *testing.T, active bool, addrs ...string) (bool, bool) {
	t.Helper()
	s := excludeAAAAFixture(t, "2001:db8::/32")
	s.SetEnabled(active)
	msg := &protocol.Message{}
	msg.Header.Flags.AD = true
	for _, addr := range addrs {
		msg.AddAnswer(aaaaRecord(t, "example.com.", addr))
	}
	msg.AddAnswer(rrsigRecord(t, "example.com.", protocol.TypeAAAA))
	return s.FilterExcludedAAAA(aaaaQuestion(t), msg), msg.Header.Flags.AD
}

func TestFilteredAAAAClearsAuthentication_F894(t *testing.T) {
	if filtered, ad := filteredAAAAAD(t, true, "2001:db8::1", "2001:db9::1"); !filtered || ad {
		t.Fatalf("REGRESSION: filtered=%v AD=%v, want true/false", filtered, ad)
	}
}
