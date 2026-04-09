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
	// RFC 1982: s1 is newer if (s1 > s2 AND s1-s2 < 2^31) OR (s1 < s2 AND s2-s1 > 2^31)
	const half uint32 = 1 << 31
	if s1 > s2 {
		return s1-s2 < half
	}
	return s2-s1 > half
}
