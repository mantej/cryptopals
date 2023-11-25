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

	b64 := base64.StdEncoding.EncodeToString(byteArray)

	return b64
}
