package base58

import (
	"errors"
)

const chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const nChars = len(chars)

var revChars [128]int8

func init() {
	for i := range revChars {
		revChars[i] = -1
	}
	for i, c := range chars {
		revChars[c] = int8(i)
	}
}

func Encode(data []byte) string {

	// count the leading zero bytes
	zeroes := 0
	for ; zeroes < len(data); zeroes++ {
		if data[zeroes] != 0 {
			break
		}
	}

	// how many non-zero base 58 symbols do we need?
	// log(256)/log(58) = 1.365..
	buf := make([]byte, (((len(data)-zeroes)*137)/100)+1)
	high := len(buf) - 1

	for i := zeroes; i < len(data); i++ {
		carry := int(data[i])
		var j int
		for j = len(buf) - 1; (j > high) || (carry != 0); j-- {
			carry += int(buf[j]) << 8
			buf[j] = byte(carry % nChars)
			carry /= nChars
			if j == 0 {
				break
			}
		}
		high = j
	}

	// remove the zero-valued symbol bytes
	i := 0
	for ; i < len(buf); i++ {
		if buf[i] != 0 {
			break
		}
	}
	buf = buf[i:]

	// build the encoded buffer
	encode := make([]byte, zeroes+len(buf))
	// add '1's for leading zero bytes
	for i := 0; i < zeroes; i++ {
		encode[i] = '1'
	}
	// add the encoded symbols
	for i := zeroes; i < len(encode); i++ {
		encode[i] = chars[buf[i-zeroes]]
	}

	return string(encode)
}

func Decode(s string) ([]byte, error) {

	if len(s) == 0 {
		return nil, errors.New("no input")
	}

	return nil, nil

}
