package cryptopals

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func Challenge3() string {
	target := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	hex_string, result := "", ""
	var score float64

	for i := 0; ; i++ {
		hex_string = strconv.FormatInt(int64(i), 16)
		if len(hex_string) == 1 {
			hex_string = "0" + hex_string
		}

		// extend single-byte to the length of the target hex_string string
		hex_string = Extend(hex_string, target)

		// hex strings that we xor should be the same length
		if len(hex_string) != len(target) {
			panic("hex_string strings are not the same length!")
		} else {
			result = Xor(hex_string, target)
		}

		score = Score(result)

		// high score = english
		if score > 0.85 {
			byteArray, err := hex.DecodeString(result)
			if err != nil {
				fmt.Println("Unable to convert hex to byte")
			}
			// print something human readable instead of an array of bytes
			return string(byteArray)
		}

		if i == 255 {
			break
		}
	}
	return "null"
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
