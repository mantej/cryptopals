package cryptopals

import (
	"testing"
)

func TestChallenge3(t *testing.T) {
	result, _ := Challenge3()
	expected := "Cooking MC's like a pound of bacon"

	if result != expected {
		t.Fail()
	}
}
