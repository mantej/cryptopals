package cryptopals

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func Challenge3() (string, byte) {
	target, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	return BreakSingleByteXor(target)
}

func SingleByteXor(key byte, data []byte) []byte {
	output := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		output[i] = data[i] ^ key
	}
	return output
}

// BreakSingleByteXor returns the best plaintext candidate and the corresponding best byte
func BreakSingleByteXor(data []byte) (string, byte) {
	var bestScore float64
	var bestPlaintext []byte
	var bestByte byte

	for i := 0; i <= 255; i++ {
		key := byte(i)
		plaintext := SingleByteXor(key, data)

		score := Score(hex.EncodeToString(plaintext))
		if score > bestScore {
			bestScore = score
			bestPlaintext = plaintext
			bestByte = key
		}
	}

	return string(bestPlaintext), bestByte
}

// Score returns the ratio of characters in the english alphabet (and spaces) to total length of the string
func Score(hexstring string) float64 {
	bytes, err := hex.DecodeString(hexstring)
	if err != nil {
		fmt.Println("Unable to convert hex to byte")
	}

	length := float64(len(bytes))
	var count int
	var letter rune

	for _, b := range bytes {
		letter = rune(b)
		if letter >= 'a' && letter <= 'z' || letter >= 'A' && letter <= 'Z' || letter == ' ' {
			count = count + 1
		}
	}

	return float64(count) / length
}

// extend a hex string x to target string's length
func Extend(x, target string) string {
	multiplier := len(target) / len(x)
	extended := strings.Repeat(x, multiplier)

	// if len(x) doesn't divide len(target), need additional padding before returning
	diff := len(target) - len(extended)
	if diff == 0 {
		return extended
	} else {
		return extended + x[:diff]
	}
}
