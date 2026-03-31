package transfer

import "errors"

// Sentinel errors for IXFR/AXFR operations.
var (
	// ErrNoJournal indicates that no journal is available for incremental transfer.
	ErrNoJournal = errors.New("no journal available for incremental transfer")

	// ErrSerialNotInRange indicates the client's serial is not covered by the journal.
	ErrSerialNotInRange = errors.New("client serial not in journal range")
)

// serialIsNewer returns true if s1 is newer than s2 using RFC 1982 serial arithmetic.
func serialIsNewer(s1, s2 uint32) bool {
	if s1 == s2 {
		return false
	}
	diff := int32(s1 - s2)
	return diff > 0
}
