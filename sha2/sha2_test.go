package sha2

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"testing"
)

func TestSha2_256(t *testing.T) {

	for i := 0; i < 1000; i++ {

		n := rand.Int() & ((1 << 16) - 1)
		data := make([]byte, n)
		rand.Read(data)

		x := Sha2_256(data)
		y := sha256.Sum256(data)

		if bytes.Compare(x[:], y[:]) != 0 {
			t.Error("FAIL")
		}
	}

}
