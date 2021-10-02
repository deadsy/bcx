/*

https://developer.bitcoin.org/reference/block_chain.html

02000000 ........................... Block version: 2

b6ff0b1b1680a2862a30ca44d346d9e8
910d334beb48ca0c0000000000000000 ... Hash of previous block's header
9d10aa52ee949386ca9385695f04ede2
70dda20810decd12bc9b048aaab31471 ... Merkle root

24d95a54 ........................... [Unix time][unix epoch time]: 1415239972
30c31b18 ........................... Target: 0x1bc330 * 256**(0x18-3)
fe9f0864 ........................... Nonce

*/

package block

import (
	"encoding/binary"

	"github.com/deadsy/bcx/sha2"
)

type Hdr struct {
	Version uint32       // block version
	Prev    sha2.Hash256 // hash of previous block's header
	Merkle  sha2.Hash256 // merkle root
	Time    uint32       // unix epoch time
	Target  uint32       // target for hash
	Nonce   uint32       // variable nonce
}

func New(prev, merkle *sha2.Hash256, version, time, target, nonce uint32) *Hdr {

	return &Hdr{
		Version: version,
		Prev:    *prev,
		Merkle:  *merkle,
		Time:    time,
		Target:  target,
		Nonce:   nonce,
	}
}

func (h *Hdr) Bytes() []byte {
	var x [4 + 32 + 32 + 4 + 4 + 4]byte
	binary.LittleEndian.PutUint32(x[0:0+4], h.Version)
	h.Prev.Copy(x[4 : 4+32])
	h.Merkle.Copy(x[36 : 36+32])
	binary.LittleEndian.PutUint32(x[68:68+4], h.Time)
	binary.LittleEndian.PutUint32(x[72:72+4], h.Target)
	binary.LittleEndian.PutUint32(x[76:76+4], h.Nonce)
	return x[:]
}
