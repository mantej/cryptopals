package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	byteArray, err := hex.DecodeString(hexString)

	if err != nil {
		fmt.Println("Unable to convert hex to byte")
	}

	fmt.Printf("Converting %s to base64 ...\n", hexString)

	b64 := base64.StdEncoding.EncodeToString(byteArray)

	fmt.Printf("Base64 representation: %s", b64)

}
