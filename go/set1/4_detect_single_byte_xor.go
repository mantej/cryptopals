package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	lines := readFile("/set1/4.txt")

	// iterate over all encrypted hex strings
	for i := 0; i < len(lines); i++ {
		hex_string, result := "", ""
		var score float64

		// iterate over all single-bytes
		for j := 0; ; j++ {
			hex_string = strconv.FormatInt(int64(j), 16)
			if len(hex_string) == 1 {
				hex_string = "0" + hex_string
			}

			// extend single-byte to the length of the target hex_string string
			hex_string = extend(hex_string, lines[i])

			if len(hex_string) != len(lines[i]) {
				panic("hex strings are not the same length!")
			} else {
				result = xor(hex_string, lines[i])
			}

			score = Score(result)

			// high score == english
			if score > 0.90 {
				byteArray, err := hex.DecodeString(result)
				if err != nil {
					fmt.Println("Unable to convert hex to byte")
				}
				// print human-readable instead of an array of bytes
				fmt.Println(string(byteArray))
			}

			if j == 255 {
				break
			}
		}
	}
}

// readFile reads a file line by line and returns a string array containing those lines
func readFile(fn string) []string {
	var encryptedstrings []string

	// get working directory
	wd, err := os.Getwd()
	if err != nil {
		panic("couldn't get working directory")
	}

	// open file for reading
	file, err := os.Open(wd + fn)
	if err != nil {
		panic("unable to open file for reading")
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		encryptedstrings = append(encryptedstrings, scanner.Text())
	}

	return encryptedstrings
}

// TODO: move the following reusable crypto utility functions to their own package

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

// extend a single-byte hex string to target string's length
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
