package dnssec

import "testing"

func TestGenerateSaltRejectsNegativeLength_F822(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("GenerateSalt(-1) panicked: %v", recovered)
		}
	}()

	salt, err := GenerateSalt(-1)
	if err == nil {
		t.Fatalf("GenerateSalt(-1) = %x, nil; want an error", salt)
	}
}
