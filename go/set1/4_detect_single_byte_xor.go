package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func Challenge4() string {
	lines := ReadFile("/4.txt")

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
			hex_string = Extend(hex_string, lines[i])

			if len(hex_string) != len(lines[i]) {
				panic("hex strings are not the same length!")
			} else {
				result = Xor(hex_string, lines[i])
			}

			score = Score(result)

			// high score == english
			if score > 0.90 {
				byteArray, err := hex.DecodeString(result)
				if err != nil {
					fmt.Println("Unable to convert hex to byte")
				}
				// print human-readable instead of an array of bytes
				//fmt.Println(string(byteArray))
				return string(byteArray)
			}

			if j == 255 {
				break
			}
		}
	}
	return ""
}

// readFile reads a file line by line and returns a string array containing those lines
func ReadFile(fn string) []string {
	var encryptedstrings []string

	// get working directory
	wd, err := os.Getwd()
	if err != nil {
		panic("couldn't get working directory")
	}

	// open file for reading
	file, err := os.Open(wd + fn)
	if err != nil {
		fmt.Println(wd)
		fmt.Println(fn)
		panic("unable to open file for reading")
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		encryptedstrings = append(encryptedstrings, scanner.Text())
	}

	return encryptedstrings
}
