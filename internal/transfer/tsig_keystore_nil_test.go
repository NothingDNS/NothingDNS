package transfer

import "testing"

func TestKeyStoreNilMutationsPreserveKey(t *testing.T) {
	store := NewKeyStore()
	key := &TSIGKey{Name: "key.example.", Secret: []byte("secret")}
	store.AddKey(key)

	t.Run("rotate", func(t *testing.T) {
		store.RotateKey(nil)
		if got, ok := store.GetKey(key.Name); !ok || got != key {
			t.Fatalf("RotateKey(nil) changed the current key: got %p, ok=%v", got, ok)
		}
	})

	t.Run("replace", func(t *testing.T) {
		store.ReplaceKey(key.Name, nil)
		if got, ok := store.GetKey(key.Name); !ok || got != key {
			t.Fatalf("ReplaceKey(nil) changed the current key: got %p, ok=%v", got, ok)
		}
	})
}
