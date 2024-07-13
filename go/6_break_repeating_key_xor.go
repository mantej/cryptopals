package cryptopals

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// TransposeBlocks will return an array of blocks, with the first block being
// the all the first bytes of the keySize length blocks, and so on
func TransposeBlocks(data []byte, keySize int) []string {

	return []string{
		string([]byte{0}),
		string([]byte{0}),
	}
}

func GetKeySize(data []byte) int {
	var keysize int
	var smallest float64
	smallest = 50.0

	for ks := 2; ks < 40; ks++ {
		i := ks * 4 // sample 4x the number of bytes per key size for more accuracy
		b1 := data[:i]
		b2 := data[i : 2*i]
		b3 := data[2*i : 3*i]
		b4 := data[3*i : 4*i]
		b5 := data[4*i : 5*i]
		b6 := data[5*i : 6*i]

		hamming1, _ := HammingDistance(string(b1), string(b2))
		hamming2, _ := HammingDistance(string(b3), string(b4))
		hamming3, _ := HammingDistance(string(b5), string(b6))
		hamming := (float64(hamming1) + float64(hamming2) + float64(hamming3)) / (float64(i) * 3.0)

		if hamming < smallest {
			smallest = hamming
			keysize = ks
		}
	}
	return keysize
}

func HammingDistance(s1, s2 string) (int, error) {
	if len(s1) != len(s2) {
		err := fmt.Errorf("strings are different lengths")
		return 0, err
	}

	b1, b2 := toByte(s1), toByte(s2)
	// need to count the number of 1s (differing bits) in result
	result := xor(b1, b2)

	var distance int
	for _, value := range result {
		b := strconv.FormatInt(int64(value), 2)
		distance += strings.Count(b, "1")
	}

	return distance, nil
}

func xor(b1, b2 []byte) []byte {
	c := make([]byte, len(b1))
	for i := range b1 {
		c[i] = b1[i] ^ b2[i]
	}
	return c
}

func toByte(s1 string) []byte {
	return []byte(s1)
}

// readFile returns the []byte representation of a (base-64 encoded) file after stripping newlines
func readFile(fileName string) []byte {
	wd, err := os.Getwd()
	if err != nil {
		panic("couldn't get working directory")
	}

	data, err := os.ReadFile(wd + fileName)
	dataStripNewline := strings.ReplaceAll(string(data), "\n", "")

	if err != nil {
		fmt.Println(wd)
		fmt.Println(fileName)
		panic("unable to open file for reading")
	}

	return []byte(dataStripNewline)
}
