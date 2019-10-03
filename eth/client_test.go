package eth

import (
	"crypto"
	concept "github.com/galaxym31/swan-concept"
	helper "github.com/galaxym31/swan-helper"
	"github.com/galaxym31/swan-helper/decimal"
	"log"
	"testing"
)

func TestClient_GetTransactionsOfBlock(t *testing.T) {
	var client = NewEthClient(ChainConfigEthTestnet)
	client.Connect(TestEthConnectEndPoint)
	blockEvent, _ := client.GetEventsOfBlock(
		6468076)
	for _, e := range blockEvent.Events {
		transferEvent := e.(*concept.TransferEvent)
		log.Println(transferEvent)
	}
}

func TestGenerateAndSignTransferTransaction(t *testing.T) {
	var client = NewEthClient(ChainConfigEthTestnet)
	client.Connect(TestEthConnectEndPoint)

	priv, pub := KeysFromBytes(helper.HexToBytes("08f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))

	from := PublicKeyToAddress(pub)
	to := "0x3d9ce8f7ea47573f7be534733fcb08b8d55c898e" // 08f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f310
	amount := decimal.New(2, -4)

	asset := client.chainConfig.GetAssetByCode(ASSET_TESTETH_ETH)
	transferCtx, err := client.PrepareTransferContext(asset, from, to, amount, "", nil)
	if err != nil {
		t.Errorf("prepare data fail")
		return
	}
	hash, hexStr, err := client.ExecuteTransferTransaction(map[string]crypto.PrivateKey{from: priv}, transferCtx)
	log.Println(hash)
	log.Println(hexStr)
	log.Println(err)
	if err != nil {
		t.Errorf("execute transfer transaction")
		return
	}
	hash, err = client.BroadcastTransaction(hexStr)
	log.Println(err)
	log.Println(hash)
}
