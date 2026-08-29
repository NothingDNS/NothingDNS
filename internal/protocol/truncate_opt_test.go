package protocol

import "testing"

func txtRR(name string, text string) *ResourceRecord {
	return &ResourceRecord{
		Name:  NewName([]string{name, "example", "com"}, true),
		Type:  TypeTXT,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataTXT{Strings: []string{text}},
	}
}

func truncTestMessage(answers int) *Message {
	m := &Message{
		Header:    Header{ID: 1, Flags: NewResponseFlags(RcodeSuccess)},
		Questions: []*Question{{Name: NewName([]string{"www", "example", "com"}, true), QType: TypeTXT, QClass: ClassIN}},
	}
	for i := 0; i < answers; i++ {
		m.AddAnswer(txtRR("www", "padding-padding-padding-padding-padding-padding-padding"))
	}
	m.AddAdditional(&ResourceRecord{
		Name:  NewName(nil, true),
		Type:  TypeOPT,
		Class: 1232,
		TTL:   BuildEDNSTTL(0, 0, false, 0),
		Data:  &RDataOPT{},
	})
	return m
}

// TestTruncate_KeepsOPT is the regression for RFC 6891 §7: a truncated
// response must still carry the OPT record. Truncate used to trim the whole
// Additional section first, so the OPT went out with the padding and the
// requestor saw a TC=1 answer from what looked like a non-EDNS server —
// which pushes a conforming resolver into an EDNS downgrade on its TCP retry
// and silently drops any DNS Cookie in the same record.
func TestTruncate_KeepsOPT(t *testing.T) {
	m := truncTestMessage(40)
	if m.WireLength() <= 512 {
		t.Fatalf("test message is only %d bytes; it must exceed the limit", m.WireLength())
	}

	m.Truncate(512)

	if !m.Header.Flags.TC {
		t.Error("TC not set on a message that had answers removed")
	}
	if m.GetOPT() == nil {
		t.Fatal("OPT record was dropped from the truncated response")
	}
	if m.WireLength() > 512 {
		t.Errorf("truncated message is %d bytes, over the 512 limit", m.WireLength())
	}
	if int(m.Header.ARCount) != len(m.Additionals) {
		t.Errorf("ARCount = %d, want %d", m.Header.ARCount, len(m.Additionals))
	}
	if len(m.Answers) == 0 {
		t.Error("every answer was removed even though some fit")
	}
}

// TestTruncate_DropsOtherAdditionalsBeforeOPT checks that keeping the OPT
// does not stop ordinary Additional records (glue and the like) from being
// trimmed first, and that trimming them alone still does not set TC
// (RFC 2181 §9).
func TestTruncate_DropsOtherAdditionalsBeforeOPT(t *testing.T) {
	m := truncTestMessage(2)
	for i := 0; i < 20; i++ {
		m.AddAdditional(txtRR("glue", "additional-padding-additional-padding-additional-padding"))
	}
	if m.WireLength() <= 512 {
		t.Fatalf("test message is only %d bytes", m.WireLength())
	}

	m.Truncate(512)

	if m.GetOPT() == nil {
		t.Fatal("OPT dropped while ordinary Additional records were available to trim")
	}
	if len(m.Answers) != 2 {
		t.Errorf("answers = %d, want 2 (answers must not be touched while additionals remain)", len(m.Answers))
	}
	if m.Header.Flags.TC {
		t.Error("TC set although only Additional-section records were removed (RFC 2181 §9)")
	}
}

// TestTruncate_ReleasesOPTAsLastResort: when nothing else is left to drop and
// the message still does not fit, the OPT has to go too — an unsendable
// packet serves the requestor worse than an EDNS-less truncated one.
func TestTruncate_ReleasesOPTAsLastResort(t *testing.T) {
	m := truncTestMessage(1)

	m.Truncate(m.WireLength() - m.Answers[0].WireLength() - 1)

	if m.WireLength() > 40 {
		// Header + question + (no records) is well under 40 bytes.
		t.Errorf("message still %d bytes after full truncation", m.WireLength())
	}
	if m.GetOPT() != nil {
		t.Error("OPT retained even though the message could not otherwise fit")
	}
	if !m.Header.Flags.TC {
		t.Error("TC not set")
	}
}

func TestTruncate_NoOPTUnchanged(t *testing.T) {
	m := truncTestMessage(40)
	m.Additionals = nil
	m.Header.ARCount = 0

	m.Truncate(512)

	if !m.Header.Flags.TC {
		t.Error("TC not set")
	}
	if m.WireLength() > 512 {
		t.Errorf("message is %d bytes, over the limit", m.WireLength())
	}
}
