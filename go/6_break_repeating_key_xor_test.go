package cryptopals

import (
	"fmt"
	"testing"
)

func TestChallenge6(t *testing.T) {
	// this should throw an error
	hammingDistance, err := HammingDistance("hello", "omg")
	if err == nil {
		t.Fail()
	}

	hammingDistance, err = HammingDistance("this is a test", "wokka wokka!!!")
	if hammingDistance != 37 {
		t.Fail()
	}

	bytes := readFile("/6.txt")
	keySize := GetKeySize(bytes)

	fmt.Println(keySize)

}
