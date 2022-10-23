package set1

import (
	"encoding/hex"
	"fmt"
)

/*
func main() {
	hex1 := "1c0111001f010100061a024b53535009181c"
	hex2 := "686974207468652062756c6c277320657965"

	fmt.Println("Computing XOR between the following hex strings:")
	fmt.Println(hex1)
	fmt.Println(hex2)
	fmt.Println("\nResult:")

	fmt.Println(xor(hex1, hex2))

}
*/

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
