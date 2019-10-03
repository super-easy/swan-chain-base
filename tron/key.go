package tron

import (
	"crypto"
	"crypto/ecdsa"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

const AddressLength = 21
const AddressPrefix = 65

// https://github.com/tronprotocol/tron-demo/blob/master/demo/go-client-api/common/crypto/crypto.go

func KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	a, b := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	return a.ToECDSA(), b.ToECDSA()
}

func PublicKeyToAddress(ckey crypto.PublicKey) string {
	key := ckey.(*ecdsa.PublicKey)
	address := ethCrypto.PubkeyToAddress(*key)

	return base58.CheckEncode(address.Bytes(), AddressPrefix)
}
