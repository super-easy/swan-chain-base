package tron

import (
	"log"
	"testing"
)

func TestBytesToTronAddress(t *testing.T) {
	h := "411bc8214660d623ec30d078dbfe5a1ef9db99b5f7"
	addr := "TCW6zWiiMjZf43rMJtGAqunqfaMut26aXf"
	a := hexToTronAddress(h)
	if a != addr {
		t.Errorf("fail")
	}
	ah := tronAddressToHex(addr)
	if h != ah {
		t.Errorf("decode fail")
	}
}

func TestKeysFromBytes(t *testing.T) {
	log.Println(tronAddressToHex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"))
	log.Println(hexToTronAddress("411d73b103494955ea76ec47a8eedf734a751140ea"))
}
