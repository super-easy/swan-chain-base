package btc

import (
	"crypto"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

/*
	P2SH-P2WPKH https://bitcoincore.org/en/segwit_wallet_dev/
*/

func KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	return btcec.PrivKeyFromBytes(btcec.S256(), pk)
}

func PublicKeyToAddress(ckey crypto.PublicKey, params *chaincfg.Params) string {
	key := ckey.(*btcec.PublicKey)
	mainNetAddr, err := btcutil.NewAddressPubKey(key.SerializeUncompressed(), params)
	if err != nil {
		panic(err)
	}
	return mainNetAddr.EncodeAddress()
}

func PublicKeyToSegwitAddress(ckey crypto.PublicKey, params *chaincfg.Params) string {
	key := ckey.(*btcec.PublicKey)
	btcutil.Hash160(key.SerializeCompressed())
	x, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(btcutil.Hash160(key.SerializeCompressed())).Script()
	return base58.CheckEncode(btcutil.Hash160(x), params.ScriptHashAddrID)
}
