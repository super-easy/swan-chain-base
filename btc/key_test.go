package btc

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	helper "github.com/galaxym31/swan-helper"
	"log"
	"testing"
)

// https://gobittest.appspot.com/Address
func TestPublicKeyToAddress(t *testing.T) {
	_, pub := KeysFromBytes(helper.HexToBytes("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"))
	addr := PublicKeyToAddress(pub, &chaincfg.MainNetParams)
	t.Log(addr)
	if addr != "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S" {
		t.Error("generate address from pubkey error")
	}
}

// https://allprivatekeys.com/generate-segwit-address
// https://matthewdowney.github.io/create-segwit-address.html
func TestKeysFromBytes(t *testing.T) {
	wif := "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
	pk := helper.WifToPk(wif)
	log.Println(helper.BytesToHex(pk))
	_, pub := KeysFromBytes(pk)
	key := pub.(*btcec.PublicKey)
	addr := PublicKeyToSegwitAddress(key, &chaincfg.MainNetParams)
	log.Println(addr)
}

