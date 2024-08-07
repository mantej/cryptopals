package cryptopals

import (
	"encoding/hex"
	"fmt"
)

func HexXor(a, b string) string {
	byteArray1, err := hex.DecodeString(a)
	if err != nil {
		fmt.Println("Unable to convert hex to byte")
		panic(err)
	}

	byteArray2, err := hex.DecodeString(b)
	if err != nil {
		fmt.Println("Unable to convert hex to byte")
		panic(err)
	}

	c := make([]byte, len(byteArray1))
	for i := range byteArray1 {
		c[i] = byteArray1[i] ^ byteArray2[i]
	}

	return hex.EncodeToString(c)
}
