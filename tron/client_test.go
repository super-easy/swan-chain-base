package tron

import (
	"crypto"
	concept "github.com/galaxym31/swan-concept"
	helper "github.com/galaxym31/swan-helper"
	"github.com/galaxym31/swan-helper/decimal"
	"log"
	"testing"
)

// https://developers.tron.network/docs/official-public-node
func TestNormal(t *testing.T) {
	client := NewTronClient(ChainConfigTestTron)
	client.Connect(TestTronConnectEndPoint)
	h, _ := client.GetCurrentHeight()
	t.Log(h)
	blockEvent, _ := client.GetEventsOfBlock(2933262)
	for _, e := range blockEvent.Events {
		transferEvent := e.(*concept.TransferEvent)
		log.Println(transferEvent)
	}
}

func TestClient_PublicKeyToAddress(t *testing.T) {
	client := NewTronClient(ChainConfigTestTron)
	_, pub := client.KeysFromBytes(helper.HexToBytes("08f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))
	a := client.PublicKeyToAddress(pub)
	log.Println(a)
	if a != "TEp3CmkVPNnQo5nJ7yFiMSzYMYpcBiKBDP" {
		t.Errorf("fail")
	}
	_, pub = client.KeysFromBytes(helper.HexToBytes("88f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))
	b := client.PublicKeyToAddress(pub)
	log.Println(b)
	if b != "TH91Ro9kA1B2FgcAWBrQh3sPvNyeTtPS7H" {
		t.Errorf("fail")
	}
}

func TestClient_PrepareTransferContext(t *testing.T) {
	client := NewTronClient(ChainConfigTestTron)
	client.Connect(TestTronConnectEndPoint)
	priv, pub := client.KeysFromBytes(helper.HexToBytes("08f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"))
	fromAddr := client.PublicKeyToAddress(pub)

	ctx, _ := client.PrepareTransferContext(client.chainConfig.GetAssetByCode(client.chainConfig.ChainAssetCode), fromAddr, "TH91Ro9kA1B2FgcAWBrQh3sPvNyeTtPS7H", decimal.New(2, 0), "")
	h, hexStr, _ := client.ExecuteTransferTransaction(map[string]crypto.PrivateKey{fromAddr: priv}, ctx)
	log.Println(h)
	t.Log(hexStr)
	client.BroadcastTransaction(hexStr)
}
