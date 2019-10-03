package eth

import (
	helper "github.com/galaxym31/swan-helper"
	"log"
	"testing"
)

// https://fullstacks.org/materials/ethereumbook/05_keys-addresses.html

func TestPublicKeyToAddress(t *testing.T) {
	_, pub := KeysFromBytes(helper.HexToBytes("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))
	addr := PublicKeyToAddress(pub)
	if addr != "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9" {
		t.Error("generate address from pubkey error")
	}
	_, pub = KeysFromBytes(helper.HexToBytes("08f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))
	addr = PublicKeyToAddress(pub)
	log.Println(addr)
	if addr != "0x351cb4cddf5038877f5f687fc7dd20a870b1ad23" {
		t.Error("generate address from pubkey error")
	}
}

