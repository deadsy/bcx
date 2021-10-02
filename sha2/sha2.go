//-----------------------------------------------------------------------------
/*

SHA2-256 Implementation

https://en.wikipedia.org/wiki/SHA-2

*/
//-----------------------------------------------------------------------------

package sha2

import (
	"encoding/hex"
	"errors"
	"math/bits"

	"github.com/deadsy/bcx/util"
)

//-----------------------------------------------------------------------------

const Size256 = 32

type Hash256 [8]uint32

func (h *Hash256) Bytes() [Size256]byte {
	var out [Size256]byte
	util.Conv32to8(out[:], h[:])
	return out
}

func (h *Hash256) Copy(dst []byte) {
	if len(dst) != Size256 {
		panic("len(dst) != Size256")
	}
	var src [Size256]byte
	util.Conv32to8(src[:], h[:])
	copy(dst, src[:])
}

func FromString(s string) (Hash256, error) {
	var out Hash256
	x, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(x) != Size256 {
		return out, errors.New("string is not 32 bytes")
	}
	util.Conv8to32(out[:], x)
	return out, nil
}

//-----------------------------------------------------------------------------

// pad512 pads a slice to a multiple of 512 bits (64 bytes)
func pad512(data []byte) []byte {

	n := uint64(len(data))

	pad := 64 - (n % 64)

	if pad < 9 {
		pad += 64
	}

	data = append(data, make([]byte, pad)...)

	data[n] = 0x80
	end := n + pad - 1
	n *= 8

	data[end-7] = uint8(n >> 56)
	data[end-6] = uint8(n >> 48)
	data[end-5] = uint8(n >> 40)
	data[end-4] = uint8(n >> 32)
	data[end-3] = uint8(n >> 24)
	data[end-2] = uint8(n >> 16)
	data[end-1] = uint8(n >> 8)
	data[end-0] = uint8(n >> 0)

	return data
}

//-----------------------------------------------------------------------------

var hInit = Hash256{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func (x *Hash256) Add512(data []byte) {

	// create a 64-entry message schedule array w[0..63] of 32-bit words
	var w [64]uint32

	// copy chunk into first 16 words w[0..15] of the message schedule array
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = (uint32(data[j]) << 24) |
			(uint32(data[j+1]) << 16) |
			(uint32(data[j+2]) << 8) |
			uint32(data[j+3])
	}

	for i := 16; i < 64; i++ {
		v0 := w[i-15]
		s0 := bits.RotateLeft32(v0, -7) ^ bits.RotateLeft32(v0, -18) ^ (v0 >> 3)
		v1 := w[i-2]
		s1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	// Initialize working variables to current hash value
	a, b, c, d, e, f, g, h := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]

	// Compression function main loop
	for i := 0; i < 64; i++ {

		s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		ch := (e & f) ^ ((^e) & g)
		tmp1 := h + s1 + ch + k[i] + w[i]
		s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		tmp2 := s0 + maj

		h = g
		g = f
		f = e
		e = d + tmp1
		d = c
		c = b
		b = a
		a = tmp1 + tmp2
	}

	// Add the compressed chunk to the current hash value
	x[0] += a
	x[1] += b
	x[2] += c
	x[3] += d
	x[4] += e
	x[5] += f
	x[6] += g
	x[7] += h
}

func Sha2_256(data []byte) [Size256]byte {

	// pad to a multiple of 512 bits
	data = pad512(data)

	x := hInit

	// for each 512 bit chunk
	for i := 0; i < len(data)/64; i++ {
		j := i * 64
		x.Add512(data[j : j+64])
	}

	return x.Bytes()
}

//-----------------------------------------------------------------------------
