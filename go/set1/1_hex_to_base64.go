package set1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func Challenge1(hexString string) string {
	byteArray, err := hex.DecodeString(hexString)

	if err != nil {
		fmt.Println("Unable to convert hex to byte")
	}

	//fmt.Printf("Converting %s to base64 ...\n", hexString)

	b64 := base64.StdEncoding.EncodeToString(byteArray)

	//fmt.Printf("Base64 representation: %s\n", b64)

	return b64
}
