package cryptopals

import (
	"fmt"
	"testing"
)

func TestXor(t *testing.T) {
	hex1 := "1c0111001f010100061a024b53535009181c"
	hex2 := "686974207468652062756c6c277320657965"

	expectedResult := "746865206b696420646f6e277420706c6179"
	result := HexXor(hex1, hex2)

	if result != expectedResult {
		t.Fail()
	} else {
		fmt.Println("[*] Challenge 2 Passed")
	}
}
