package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestDigResponseMatchesCompleteQuestion(t *testing.T) {
	query, err := protocol.NewQuery(0x1234, "wanted.example.", protocol.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	defer query.Release()

	matching := query.Copy()
	matching.Header.Flags.QR = true
	if !digResponseMatchesQuery(matching, query) {
		t.Fatal("matching response rejected")
	}

	cases := map[string]func(*protocol.Message){
		"request direction": func(m *protocol.Message) { m.Header.Flags.QR = false },
		"wrong ID":          func(m *protocol.Message) { m.Header.ID++ },
		"wrong name": func(m *protocol.Message) {
			m.Questions[0], _ = protocol.NewQuestion("other.example.", protocol.TypeA, protocol.ClassIN)
		},
		"wrong type":     func(m *protocol.Message) { m.Questions[0].QType = protocol.TypeAAAA },
		"wrong class":    func(m *protocol.Message) { m.Questions[0].QClass = protocol.ClassCH },
		"empty question": func(m *protocol.Message) { m.Questions = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			resp := matching.Copy()
			mutate(resp)
			if digResponseMatchesQuery(resp, query) {
				t.Fatal("mismatched response accepted")
			}
		})
	}

	caseChanged := matching.Copy()
	caseChanged.Questions[0], _ = protocol.NewQuestion("WANTED.EXAMPLE.", protocol.TypeA, protocol.ClassIN)
	if !digResponseMatchesQuery(caseChanged, query) {
		t.Fatal("DNS case-only difference rejected")
	}
}
