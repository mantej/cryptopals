package main

import "fmt"
import "log"
import hex "encoding/hex"

// INPUT:  byte array
// OUTPUT: hex-encoded string
func encode(raw []byte) string{
  return hex.EncodeToString(raw)
}

// INPUT:  hex-encoded string
// OUTPUT: byte array
func decode(encoded string) []byte{
  decoded, err := hex.DecodeString(encoded)
  if err != nil{
    log.Fatal(err)
  }
  return decoded
}

// INPUT:  two hex-encoded strings of the same length
// OUTPUT: XOR of INPUT (hex-encoded)
func xor(s1 string, s2 string) string{
  len := len(s1)/2
  buf := make([]byte, len)
  a := decode(s1)
  b := decode(s2)
  for i := 0; i < len; i++ {
    x := a[i] ^ b[i]
    buf[i] = byte(x)
  }
  return encode(buf)
}

func main(){
  test := xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
  fmt.Println(test)
}
