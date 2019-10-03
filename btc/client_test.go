package btc

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	helper "github.com/galaxym31/swan-helper"
	"log"
	"testing"
)

func TestNormal(t *testing.T) {
	client := NewBtcClient(ChainConfigTestBtc)
	_, pub := client.KeysFromBytes(helper.HexToBytes("c4bbcb1fbec99d65bf59d85c8cb68ee2db963f0fe106f483d9afa73bd4e39a8a"))
	addr := client.PublicKeyToAddress(pub)
	if addr != "2Mv7CNcf35bxUWExZk9khwSnYAU7FF8gGNW" {
		t.Error("fail")
	}
	log.Println(addr)
	_, pub = client.KeysFromBytes(helper.HexToBytes("04bbcb1fbec99d65bf59d85c8cb624e2db963f0fe106f483d9afa73bd4e39a8a"))
	addr = client.PublicKeyToAddress(pub)
	if addr != "2Mys77JtjHFTfVYqstdUGSR9sKF4kgKUZ3M" {
		t.Error("fail")
	}
	log.Println(addr)
}

func TestClient_GetCurrentHeight(t *testing.T) {
	client := NewBtcClient(ChainConfigRegBtc)
	err := client.Connect(RegBtcConnectEndPoint)
	log.Println(err)
	if err != nil {
		t.Error(err)
		return
	}
	h, err := client.GetCurrentHeight()
	log.Println(err)
	log.Println(h)
}

func TestClient_PrepareTransferContextForTestnet(t *testing.T) {
	client := NewBtcClient(ChainConfigTestBtc)
	priv, pub := client.KeysFromBytes(helper.HexToBytes("c4bbcb1fbec99d65bf59d85c8cb68ee2db963f0fe106f483d9afa73bd4e39a8a"))
	fromAddr := client.PublicKeyToAddress(pub)

	Vins := []Vinput{
		{
			Txid:    "ccedccbe3c0affd4832c8660298e933936947012dda96b43af3244ed764ceeef",
			Vout:    1,
			Address: fromAddr,
			Amount:  decimal.NewFromFloat32(0.01),
		},
	}
	x, _ := json.Marshal(Vins)
	Vouts := []Voutput{
		{
			Address: "2Mys77JtjHFTfVYqstdUGSR9sKF4kgKUZ3M",
			Amount:  decimal.NewFromFloat32(0.009),
		},
	}
	y, _ := json.Marshal(Vouts)
	ctx, err := client.PrepareTransferContext(client.chainConfig.GetMainAsset(), string(x), string(y), decimal.Zero, "")

	h, d, err := client.ExecuteTransferTransaction(map[string]crypto.PrivateKey{fromAddr: priv}, ctx)
	log.Println(err)
	log.Println(h)
	log.Println(d)
}

func TestClient_PrepareTransferContextForReg(t *testing.T) {
	client := NewBtcClient(ChainConfigRegBtc)
	err := client.Connect(RegBtcConnectEndPoint)
	//priv, pub := client.KeysFromBytes(helper.HexToBytes("edc42814819257308024357416ecd3027b66ac56ae635b86a56485de9447323c")) // 2NB21FD11Mv21waXcRJ6Mdn7g2E18HRwZhS
	priv, pub := client.KeysFromBytes(helper.HexToBytes("04bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")) // 2N6RT6TSZypzUAS5Vpdc7ijfaxgFAdfKF1w
	fromAddr := client.PublicKeyToAddress(pub)
	log.Println(fromAddr)

	Vins := []Vinput{
		{
			Txid:    "f59f776c45ac5ee88616d193eb721b409df9b535929a7a6ebd789d753bafa29b",
			Vout:    0,
			Address: "2N6RT6TSZypzUAS5Vpdc7ijfaxgFAdfKF1w",
			Amount:  decimal.NewFromFloat32(19.9899),
		},
	}
	x, _ := json.Marshal(Vins)
	Vouts := []Voutput{
		{
			Address: "2N6RT6TSZypzUAS5Vpdc7ijfaxgFAdfKF1w",
			Amount:  decimal.NewFromFloat32(19.9799),
		},
	}
	y, _ := json.Marshal(Vouts)
	ctx, err := client.PrepareTransferContext(client.chainConfig.GetMainAsset(), string(x), string(y), decimal.Zero, "")

	h, d, err := client.ExecuteTransferTransaction(map[string]crypto.PrivateKey{fromAddr: priv}, ctx)
	log.Println(err)
	log.Println(h)
	log.Println(d)
}

// https://medium.com/coinmonks/how-to-create-a-raw-bitcoin-transaction-step-by-step-239b888e87f2
// https://github.com/xuanzhui/cryptocoin-py/blob/master/btc_sample.py
func TestPublicKeyToSegwitAddress(t *testing.T) {
	//m := base58.CheckEncode(helper.HexToBytes("c2f23833c0938fe13274c6e293e12884eb560421"), chaincfg.RegressionNetParams.ScriptHashAddrID)
	//log.Println(m)
	x := "020000000001018e16a9a654ed9b5529cc9a2f4027cf373ce97eb04c0ae9ea569e20bce7b533ac00000000171600142b74dc982c1e52923af088cb0f26ae3f617082a6ffffffff01b02a26770000000017a9149088bc49c9f9c7d8b80405a510341d7330b49991870247304402201ba1eea271338b06ed3a49811644aa031a35ce03fc1f42d73e2f16f3a159a4b002200fe7271e73dd51cd33de3e68ade56ebbeae135d60299e1f3927a94d8a9e49bc5012103c3b63599241ba6df9fa584e6e833d933e796a9c265771a9011012e63f28d080b00000000"
	var tx wire.MsgTx
	err := tx.Deserialize(bytes.NewReader(helper.HexToBytes(x)))

	log.Println(err)
	log.Println(tx)
	log.Println(len(tx.TxIn))
	v := tx.TxIn[0]
	log.Println(helper.BytesToHex(v.SignatureScript))
	log.Println(helper.BytesToHex(v.Witness[0]))
	log.Println(helper.BytesToHex(v.Witness[1]))

	log.Println()
	log.Println(txHexString(&tx))
	log.Println()

	client := NewBtcClient(ChainConfigRegBtc)
	err = client.Connect(RegBtcConnectEndPoint)
	cpriv, cpub := client.KeysFromBytes(helper.HexToBytes("edc42814819257308024357416ecd3027b66ac56ae635b86a56485de9447323c")) // 2NB21FD11Mv21waXcRJ6Mdn7g2E18HRwZhS
	priv := cpriv.(*btcec.PrivateKey)
	pub := cpub.(*btcec.PublicKey)
	a, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(btcutil.Hash160(pub.SerializeCompressed())).Script()
	fmt.Println(helper.BytesToHex(a))
	log.Println(helper.BytesToHex(priv.PubKey().SerializeCompressed()))

	sig, err := txscript.RawTxInSignature(&tx, 0, v.SignatureScript[1:], txscript.SigHashAll, priv)
	log.Println(helper.BytesToHex(sig))
	sig, err = txscript.RawTxInWitnessSignature(&tx, txscript.NewTxSigHashes(&tx), 0, 1999990040, v.SignatureScript[1:], txscript.SigHashAll, priv)
	log.Println(helper.BytesToHex(sig))
}
