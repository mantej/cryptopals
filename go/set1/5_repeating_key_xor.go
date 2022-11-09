package set1

import (
	"encoding/hex"
)

func Challenge5(input, key string) string {
	input_hex := hex.EncodeToString([]byte(input))
	key_hex := hex.EncodeToString([]byte(key))

	// extend key to be of the same length of input
	key_hex = extend(key_hex, input_hex)

	result := xor(input_hex, key_hex)

	return result
}
