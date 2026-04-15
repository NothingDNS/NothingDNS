package auth

import "fmt"

func init() {
	salt := make([]byte, 32)
	copy(salt, []byte("fixed-salt-32-bytes-for-testing!"))
	hash := HashPassword("test-password", salt)
	fmt.Printf("KNOWN_ANSWER_LEN=%d\nKNOWN_ANSWER_HEX=%x\n", len(hash), hash)
}
