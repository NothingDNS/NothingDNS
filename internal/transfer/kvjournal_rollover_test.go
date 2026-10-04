package transfer

import (
	"reflect"
	"testing"
	"time"
)

func TestKVJournalStoreSerialRollover(t *testing.T) {
	for _, tc := range []struct {
		name          string
		serials, want []uint32
		keep          int
		truncate      bool
	}{
		{"ordinary", []uint32{10, 11, 12}, []uint32{11, 12}, 2, false},
		{"automatic rollover", []uint32{4294967294, 4294967295, 0}, []uint32{4294967295, 0}, 2, false},
		{"explicit rollover", []uint32{4294967295, 0, 1}, []uint32{0, 1}, 2, true},
		{"load rollover", []uint32{4294967295, 0}, []uint32{4294967295, 0}, 2, false},
		{"keep zero", []uint32{4294967295, 0}, []uint32{}, 0, true},
		{"empty", []uint32{}, []uint32{}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := NewKVJournalStore(dir)
			if !tc.truncate {
				s.SetMaxJournalSize(tc.keep)
			}
			for _, serial := range tc.serials {
				if err := s.SaveEntry("example.test.", &IXFRJournalEntry{Serial: serial, Timestamp: time.Unix(100, 0)}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.truncate {
				if err := s.Truncate("example.test.", tc.keep); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				entries, err := NewKVJournalStore(dir).LoadEntries("example.test.")
				if err != nil {
					t.Fatal(err)
				}
				got := []uint32{}
				for _, e := range entries {
					got = append(got, e.Serial)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("serials = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
