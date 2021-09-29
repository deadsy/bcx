package sha2

import (
	"fmt"
	"math/bits"
	"strings"
)

/*

https://en.wikipedia.org/wiki/SHA-2

Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380

Initialize hash values:
(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
h0 := 0x6a09e667
h1 := 0xbb67ae85
h2 := 0x3c6ef372
h3 := 0xa54ff53a
h4 := 0x510e527f
h5 := 0x9b05688c
h6 := 0x1f83d9ab
h7 := 0x5be0cd19

Initialize array of round constants:
(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
k[0..63] :=
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

Pre-processing (Padding):
begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
such that the bits in the message are L 1 00..<K 0's>..00 <L as 64 bit integer> = k*512 total bits

Process the message in successive 512-bit chunks:
break message into 512-bit chunks
for each chunk
    create a 64-entry message schedule array w[0..63] of 32-bit words
    (The initial values in w[0..63] don't matter, so many implementations zero them here)
    copy chunk into first 16 words w[0..15] of the message schedule array

    Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    for i from 16 to 63
        s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
        s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
        w[i] := w[i-16] + s0 + w[i-7] + s1

    Initialize working variables to current hash value:
    a := h0
    b := h1
    c := h2
    d := h3
    e := h4
    f := h5
    g := h6
    h := h7

    Compression function main loop:
    for i from 0 to 63
        S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        ch := (e and f) xor ((not e) and g)
        temp1 := h + S1 + ch + k[i] + w[i]
        S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        maj := (a and b) xor (a and c) xor (b and c)
        temp2 := S0 + maj

        h := g
        g := f
        f := e
        e := d + temp1
        d := c
        c := b
        b := a
        a := temp1 + temp2

    Add the compressed chunk to the current hash value:
    h0 := h0 + a
    h1 := h1 + b
    h2 := h2 + c
    h3 := h3 + d
    h4 := h4 + e
    h5 := h5 + f
    h6 := h6 + g
    h7 := h7 + h

Produce the final hash value (big-endian):
digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7

*/

//-----------------------------------------------------------------------------

func dump8(x []byte) string {
	s := make([]string, len(x))
	for i := 0; i < len(x); i++ {
		s[i] = fmt.Sprintf("%02x ", x[i])
	}
	return strings.Join(s, "") + fmt.Sprintf("(%d)", len(x))
}

func dump32(x []uint32) string {
	s := make([]string, len(x))
	for i := 0; i < len(x); i++ {
		s[i] = fmt.Sprintf("%08x ", x[i])
	}
	return strings.Join(s, "") + fmt.Sprintf("(%d)", len(x))
}

//-----------------------------------------------------------------------------

// conv8to32 converts a slice of byte to a slice of uint32
func conv8to32(dst []uint32, src []byte) {
	if len(src) != 4*len(dst) {
		panic("len(src) != 4 * len(dst)")
	}
	for i := 0; i < len(dst); i++ {
		dst[i] = (uint32(src[i*4+0]) << 24) |
			(uint32(src[i*4+1]) << 16) |
			(uint32(src[i*4+2]) << 8) |
			(uint32(src[i*4+3]) << 0)
	}
}

// conv32to82 converts a slice of uint32 to a slice of byte
func conv32to8(dst []byte, src []uint32) {
	if len(dst) != 4*len(src) {
		panic("len(dst) != 4 * len(src)")
	}
	for i := 0; i < len(src); i++ {
		dst[i*4+0] = uint8(src[i] >> 24)
		dst[i*4+1] = uint8(src[i] >> 16)
		dst[i*4+2] = uint8(src[i] >> 8)
		dst[i*4+3] = uint8(src[i] >> 0)
	}
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

var hInit = [8]uint32{
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

const Size256 = 32

func rRotate(x uint32, k int) uint32 {
	return bits.RotateLeft32(x, -k)
}

func Sha2_256(data []byte) [Size256]byte {

	// pad to a multiple of 512 bits
	data = pad512(data)

	// convert to []uint32
	data32 := make([]uint32, len(data)/4)
	conv8to32(data32, data)

	// initial hash value
	h := hInit

	// for each 512 bit chunk
	for i := 0; i < len(data32)/16; i++ {
		// create a 64-entry message schedule array w[0..63] of 32-bit words
		var w [64]uint32

		// copy chunk into first 16 words w[0..15] of the message schedule array
		for j := 0; j < 16; j++ {
			w[j] = data32[i*16+j]
		}

		for j := 16; j < 64; j++ {
			s0 := rRotate(w[j-15], 7) ^ rRotate(w[j-15], 18) ^ (w[j-15] >> 3)
			s1 := rRotate(w[j-2], 17) ^ rRotate(w[j-2], 19) ^ (w[j-2] >> 10)
			w[j] = w[j-16] + s0 + w[j-7] + s1
		}

		// Initialize working variables to current hash value:
		work := h

		// Compression function main loop
		for j := 0; j < 64; j++ {

			s1 := rRotate(work[4], 6) ^ rRotate(work[4], 11) ^ rRotate(work[4], 25)
			ch := (work[4] & work[5]) ^ ((^work[4]) & work[6])
			tmp1 := work[7] + s1 + ch + k[j] + w[j]
			s0 := rRotate(work[0], 2) ^ rRotate(work[0], 13) ^ rRotate(work[0], 22)
			maj := (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2])
			tmp2 := s0 + maj

			work[7] = work[6]
			work[6] = work[5]
			work[5] = work[4]
			work[4] = work[3] + tmp1
			work[3] = work[2]
			work[2] = work[1]
			work[1] = work[0]
			work[0] = tmp1 + tmp2
		}

		// Add the compressed chunk to the current hash value
		for j := 0; j < 8; j++ {
			h[j] += work[j]
		}
	}

	var out [Size256]byte
	conv32to8(out[:], h[:])
	return out
}

//-----------------------------------------------------------------------------
