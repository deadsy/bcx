package util

import (
	"fmt"
	"strings"
)

func Dump8(x []byte) string {
	s := make([]string, len(x))
	for i := 0; i < len(x); i++ {
		s[i] = fmt.Sprintf("%02x ", x[i])
	}
	return strings.Join(s, "") + fmt.Sprintf("(%d)", len(x))
}

func Dump32(x []uint32) string {
	s := make([]string, len(x))
	for i := 0; i < len(x); i++ {
		s[i] = fmt.Sprintf("%08x ", x[i])
	}
	return strings.Join(s, "") + fmt.Sprintf("(%d)", len(x))
}

// Conv32to82 converts a slice of uint32 to a slice of byte
func Conv32to8(dst []byte, src []uint32) {
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

// Conv8to32 converts a slice of byte to a slice of uint32
func Conv8to32(dst []uint32, src []byte) {
	if len(src) != 4*len(dst) {
		panic("len(src) != 4*len(dst)")
	}
	for i := 0; i < len(dst); i++ {
		dst[i] = (uint32(src[i*4+0]) << 24) |
			(uint32(src[i*4+1]) << 16) |
			(uint32(src[i*4+2]) << 8) |
			(uint32(src[i*4+3]) << 0)
	}
}
