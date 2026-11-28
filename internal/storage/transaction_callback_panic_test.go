package storage

import (
	"testing"
)

func transactionClosedAfterPanic(t *testing.T, writable bool) (bool, bool) {
	t.Helper()
	s, err := OpenKVStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	execute := s.View
	if writable {
		execute = s.Update
	}
	sentinel := new(int)
	var tx *Tx
	gotPanic := func() (value any) {
		defer func() { value = recover() }()
		if err := execute(func(callbackTx *Tx) error {
			tx = callbackTx
			if writable {
				if _, err := tx.CreateBucket([]byte("pending")); err != nil {
					return err
				}
			}
			panic(sentinel)
		}); err != nil {
			t.Fatalf("unexpected transaction error: %v", err)
		}
		return nil
	}()
	closed := tx.closed
	if !closed {
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.View(func(tx *Tx) error {
		if tx.Bucket([]byte("pending")) != nil {
			t.Error("uncommitted bucket remained visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return closed, gotPanic == sentinel
}

func TestTransactionCallbackPanicClosesTransaction_F896(t *testing.T) {
	for _, writable := range []bool{true, false} {
		if closed, panicked := transactionClosedAfterPanic(t, writable); !closed || !panicked {
			t.Errorf("REGRESSION: writable=%v closed=%v original panic=%v, want both true", writable, closed, panicked)
		}
	}
}
