package set1

import (
	"encoding/hex"
)

func RepeatingKeyXor(input, key string) string {
	input_hex := hex.EncodeToString([]byte(input))
	key_hex := hex.EncodeToString([]byte(key))

	// extend key to be of the same length of input
	key_hex = Extend(key_hex, input_hex)

	// returns hex-encoded XOR of the two hex-encoded inputs
	result := Xor(input_hex, key_hex)

	return result
}
