package set1

import (
	"fmt"
	"testing"
)

func TestChallenge3(t *testing.T) {
	result := Challenge3()
	expected := "Cooking MC's like a pound of bacon"

	if result != expected {
		t.Fail()
	} else {
		fmt.Println("[*] Challenge 3 Passed")
	}
}
