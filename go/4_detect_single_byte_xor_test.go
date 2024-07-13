package cryptopals

import (
	"fmt"
	"strings"
	"testing"
)

func TestChallenge4(t *testing.T) {
	result := Challenge4()
	expected := "Now that the party is jumping"

	if strings.TrimSuffix(result, "\n") != expected {
		t.Fail()
	} else {
		fmt.Println("[*] Challenge 4 Passed")
	}
}
