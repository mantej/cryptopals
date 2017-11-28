package main

import "fmt"
import "log"
import b64 "encoding/base64"
import hex "encoding/hex"

func main(){
    h := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    decoded, err := hex.DecodeString(h)
    if err != nil{
        log.Fatal(err)
    }
    b := b64.StdEncoding.EncodeToString([]byte(decoded))
    fmt.Println(b)
}
