package zone

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestParseFileQuotedParenthesisDoesNotOpenContinuation(t *testing.T) {
	for _, value := range []string{"hello(", "hello)", "hello()", "(", "escaped\"("} {
		text := "$ORIGIN example.test.\n$TTL 300\ntext IN TXT " + quoteZoneCharacterString(value) + "\nnext IN A 192.0.2.1\n"
		z, err := ParseFile("quoted.zone", strings.NewReader(text))
		if err != nil {
			t.Fatalf("value %q: %v", value, err)
		}
		records := z.Lookup("text.example.test.", "TXT")
		if len(records) != 1 {
			t.Fatalf("value %q: missing TXT", value)
		}
		rd, ok := protocol.ParseRDataText("TXT", records[0].RData).(*protocol.RDataTXT)
		if !ok || len(rd.Strings) != 1 || rd.Strings[0] != value {
			t.Fatalf("value %q changed: %v", value, rd)
		}
		if len(z.Lookup("next.example.test.", "A")) != 1 {
			t.Fatal("following record missing")
		}
	}
}

func TestParseFileOpeningParenthesesInCommentIgnored(t *testing.T) {
	text := "$ORIGIN example.test.\ntext 300 IN TXT \"normal\" ; (comment\nnext 300 IN A 192.0.2.1\n"
	z, err := ParseFile("comment.zone", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Lookup("text.example.test.", "TXT")) != 1 || len(z.Lookup("next.example.test.", "A")) != 1 {
		t.Fatal("records missing")
	}
}
