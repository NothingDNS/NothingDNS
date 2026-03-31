package transfer

import "errors"

// Sentinel errors for IXFR/AXFR operations.
var (
	// ErrNoJournal indicates that no journal is available for incremental transfer.
	ErrNoJournal = errors.New("no journal available for incremental transfer")

	// ErrSerialNotInRange indicates the client's serial is not covered by the journal.
	ErrSerialNotInRange = errors.New("client serial not in journal range")
)
