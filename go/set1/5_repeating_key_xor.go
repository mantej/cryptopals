package set1

import (
	"encoding/hex"
)

func Repeating_Key_Xor(input, key string) string {
	input_hex := hex.EncodeToString([]byte(input))
	key_hex := hex.EncodeToString([]byte(key))

	// extend key to be of the same length of input
	key_hex = extend(key_hex, input_hex)

	// returns hex-encoded XOR of the two hex-encoded inputs
	result := xor(input_hex, key_hex)

	return result
}
