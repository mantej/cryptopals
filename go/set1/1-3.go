package main

import "fmt"
import "strings"
import "log"
import "unicode"
import hex "encoding/hex"


// INPUT:  num to convert to hex, len (in hex) of output string
// OUTPUT: hex pad of num of length len
func generate_pad(num int, len int) string{
  hex := fmt.Sprintf("%x", num)
  if num < 16{
    hex = string('0') + fmt.Sprintf("%x", num)
  }
  return strings.Repeat(hex, len/2)
}

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

// INPUT: a string
// OUTPUT: true if over 92% of the characters in the string are letters or spaces
func is_english(s string) bool {
  score := 0.0
  for _, r := range s {
    if unicode.IsLetter(r) {
      score = score + 1
    }else if unicode.IsSpace(r) {
      score = score + 1
    }
  }
  if score / float64(len(s)) > 0.92{
    return true
  }
  return false
}

func main(){
  encrypted := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  for i:= 0; i < 256; i++ {
    pad := generate_pad(i, len(encrypted))
    decrypted := xor(encrypted, pad)
    // convert hex into byte array into string
    if is_english(string(decode(decrypted))){
      fmt.Println(string(decode(decrypted)))
    }
  }
}
