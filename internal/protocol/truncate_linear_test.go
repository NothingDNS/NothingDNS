package protocol

import (
	"fmt"
	"testing"
)

// truncateReference preserves the pre-optimization behavior for equivalence
// testing. It deliberately re-packs after every removal and measures the
// packed (compressed) size, which is what Truncate budgets against (F102).
func truncateReference(m *Message, maxSize int) {
	if m == nil || packedLenForTest(m) <= maxSize {
		return
	}
	for len(m.Additionals) > 0 && packedLenForTest(m) > maxSize {
		m.Additionals = m.Additionals[:len(m.Additionals)-1]
	}
	m.Header.ARCount = uint16(len(m.Additionals))
	if packedLenForTest(m) <= maxSize {
		return
	}

	truncated := false
	for len(m.Authorities) > 0 && packedLenForTest(m) > maxSize {
		m.Authorities = m.Authorities[:len(m.Authorities)-1]
		truncated = true
	}
	m.Header.NSCount = uint16(len(m.Authorities))
	if packedLenForTest(m) <= maxSize {
		if truncated {
			m.Header.SetTruncated(true)
		}
		return
	}

	for len(m.Answers) > 0 && packedLenForTest(m) > maxSize {
		m.Answers = m.Answers[:len(m.Answers)-1]
		truncated = true
	}
	m.Header.ANCount = uint16(len(m.Answers))
	if truncated || packedLenForTest(m) > maxSize {
		m.Header.SetTruncated(true)
	}
}

func TestMessageTruncateLinearMatchesReference(t *testing.T) {
	base := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	question, err := NewQuestion("bulk.example.", TypeA, ClassIN)
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	base.AddQuestion(question)

	for i := 0; i < 256; i++ {
		name, err := ParseName(fmt.Sprintf("host-%03d.bulk.example.", i))
		if err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
		record := func(octet byte) *ResourceRecord {
			return &ResourceRecord{
				Name:  name,
				Type:  TypeA,
				Class: ClassIN,
				TTL:   uint32(60 + i),
				Data:  &RDataA{Address: [4]byte{192, 0, 2, octet}},
			}
		}
		base.AddAnswer(record(byte(i)))
		base.AddAuthority(record(byte(i + 1)))
		base.AddAdditional(record(byte(i + 2)))
	}

	fullSize := base.WireLength()
	questionOnly := HeaderLen + question.WireLength()
	budgets := []int{
		fullSize + 1,
		fullSize - 1,
		fullSize * 3 / 4,
		fullSize / 2,
		questionOnly,
		HeaderLen - 1,
	}

	for _, budget := range budgets {
		t.Run(fmt.Sprintf("budget_%d", budget), func(t *testing.T) {
			got := base.Copy()
			want := base.Copy()

			got.Truncate(budget)
			truncateReference(want, budget)

			if len(got.Answers) != len(want.Answers) ||
				len(got.Authorities) != len(want.Authorities) ||
				len(got.Additionals) != len(want.Additionals) {
				t.Fatalf("section lengths got=(%d,%d,%d) want=(%d,%d,%d)",
					len(got.Answers), len(got.Authorities), len(got.Additionals),
					len(want.Answers), len(want.Authorities), len(want.Additionals))
			}
			if got.Header.ANCount != want.Header.ANCount ||
				got.Header.NSCount != want.Header.NSCount ||
				got.Header.ARCount != want.Header.ARCount {
				t.Fatalf("header counts got=(%d,%d,%d) want=(%d,%d,%d)",
					got.Header.ANCount, got.Header.NSCount, got.Header.ARCount,
					want.Header.ANCount, want.Header.NSCount, want.Header.ARCount)
			}
			if got.Header.Flags.TC != want.Header.Flags.TC {
				t.Fatalf("TC got=%v want=%v", got.Header.Flags.TC, want.Header.Flags.TC)
			}
			if packedLenForTest(got) != packedLenForTest(want) {
				t.Fatalf("packed length got=%d want=%d", packedLenForTest(got), packedLenForTest(want))
			}
		})
	}
}
