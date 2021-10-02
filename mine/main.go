/*

https://developer.bitcoin.org/reference/block_chain.html

block 125552
https://www.blockchain.com/btc/block/00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d

*/

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/deadsy/bcx/block"
	"github.com/deadsy/bcx/sha2"
	"github.com/deadsy/bcx/util"
)

func mine() error {

	prev, err := sha2.FromString("81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000")
	if err != nil {
		return err
	}

	merkle, err := sha2.FromString("e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b")
	if err != nil {
		return err
	}

	location, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		return err
	}

	// 2011-05-21 10:26
	t := time.Date(2011, 5, 21, 10, 26, 0, 0, location)
	fmt.Printf("time: %d\n", t.Unix())

	version := uint32(1)
	time := uint32(t.Unix() + 31)
	target := uint32(440711666) // bits
	nonce := uint32(2504433986)

	h := block.New(&prev, &merkle, version, time, target, nonce)

	x := h.Bytes()

	fmt.Printf("header: %s\n", util.Dump8(x))

	hash0 := sha2.Sha2_256(x)
	fmt.Printf("hash0: %s\n", util.Dump8(hash0[:]))

	hash1 := sha2.Sha2_256(hash0[:])
	fmt.Printf("hash1: %s\n", util.Dump8(hash1[:]))

	return nil
}

func main() {

	err := mine()

	if err != nil {
		log.Fatalf("%s\n", err)
	}

}
