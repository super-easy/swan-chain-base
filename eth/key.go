package eth

import (
	"crypto"
	"crypto/ecdsa"
	"github.com/btcsuite/btcd/btcec"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"strings"
)

var emptyData = make([]byte, 0, 0)

func KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	a, b := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	return a.ToECDSA(), b.ToECDSA()
}

func PublicKeyToAddress(ckey crypto.PublicKey) string {
	key := ckey.(*ecdsa.PublicKey)
	return strings.ToLower(ethCrypto.PubkeyToAddress(*key).String())
}
