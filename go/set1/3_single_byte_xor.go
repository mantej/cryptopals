package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func main() {
	target := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	hex_string, result := "", ""
	var score float32

	for i := 0; ; i++ {
		hex_string = strconv.FormatInt(int64(i), 16)
		if len(hex_string) == 1 {
			hex_string = "0" + hex_string
		}

		// extend single-byte to the length of the target hex_string string
		hex_string = extend(hex_string, target)

		if len(hex_string) != len(target) {
			panic("hex_string strings are not the same length!")
		} else {
			result = xor(hex_string, target)
		}

		score = Score(result)

		// high score = english
		if score > 0.95 {
			byteArray, err := hex.DecodeString(result)
			if err != nil {
				fmt.Println("Unable to convert hex to byte")
			}
			fmt.Println(byteArray)
		}

		if i == 255 {
			break
		}
	}
}

func Score(string hex) float32 {

	return 0.0
}

func extend(x, target string) string {
	multiplier := len(target) / len(x)
	return strings.Repeat(x, multiplier)
}

// xor against two hex strings and returns the result in hex format
func xor(a, b string) string {
	byteArray1, err := hex.DecodeString(a)
	if err != nil {
		fmt.Println("Unable to convert hex to byte")
	}

	byteArray2, err := hex.DecodeString(b)
	if err != nil {
		fmt.Println("Unable to convert hex to byte")
	}

	c := make([]byte, len(byteArray1))
	for i := range byteArray1 {
		c[i] = byteArray1[i] ^ byteArray2[i]
	}

	return hex.EncodeToString(c)
}
