package tron

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/galaxym31/swan-chain-base/tron/pb/core"
	concept "github.com/galaxym31/swan-concept"
	helper "github.com/galaxym31/swan-helper"
	"github.com/galaxym31/swan-helper/decimal"
	"github.com/galaxym31/swan-helper/httputil"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"time"
)

type Client struct {
	chainConfig *concept.ChainConfig
	url         string
}

// https://github.com/tronprotocol/documentation/blob/master/TRX/Tron-http.md
// https://github.com/tronprotocol/tron-demo/blob/115d03055eff421d2d3fa11b86876e5159ea7c02/demo/go-client-api/service/client.go
// https://github.com/tronprotocol/documentation/blob/master/TRX/Tron-overview.md
// TRC20:
/*
       data = (
           TronClient.TRC20_TRANSFER_ABI_PREFIX
           + encode_abi(
               ["address", "uint256"], [to_addr_hex, outbound.value]
           ).hex()
       )

	eg: 5832760cafd482686bb8c4e386a6a8ad425790ae697dca0562834c7caa7ea04a
*/

func NewTronClient(config *concept.ChainConfig) *Client {
	return &Client{
		chainConfig: config,
	}
}

func (c *Client) GetChainConfig() *concept.ChainConfig {
	return c.chainConfig
}

func (c *Client) Connect(point concept.ConnectEndPoint) error {
	c.url = point.GetUrl()
	return nil
}

type balanceResponse struct {
	Balance int64 `json:"balance"`
}

func (c *Client) GetBalance(address string, asset string) (balance decimal.Decimal, err error) {
	data := map[string]interface{}{
		"address": tronAddressToHex(address),
	}
	fmt.Println(data)
	var balanceResp balanceResponse
	err = httputil.RequestJson(c.url+"/walletsolidity/getaccount", data, &balanceResp)
	if err != nil {
		return
	}
	balance = decimal.New(balanceResp.Balance, -tronDecimalPoint)
	fmt.Println(balance)
	return
}

type blockHeader struct {
	RawData struct {
		Number     uint64 `json:"number"`
		ParentHash string `json:"parentHash"`
	} `json:"raw_data"`
}

type simpleBlock struct {
	BlockID string      `json:"blockId"`
	Header  blockHeader `json:"block_header"`
}

func (c *Client) GetCurrentHeight() (uint64, error) {
	var block simpleBlock
	err := httputil.RequestJson(c.url+"/wallet/getnowblock", nil, &block)
	if err != nil {
		return 0, nil
	}
	return block.Header.RawData.Number, nil
}

type broadcastResp struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) BroadcastTransaction(hexStr string) (hash string, err error) {
	var resp map[string]interface{}
	err = httputil.RequestJson(c.url+"/wallet/broadcasttransaction", json.RawMessage([]byte(hexStr)), &resp)
	if err != nil {
		return
	}
	fmt.Println(resp)
	v, ok := resp["result"]
	if ok && v.(bool) {
		return "", nil
	}
	errCode := resp["code"]
	return "", errors.New(fmt.Sprintf("%s", errCode))
}

type txResp struct {
	TxID string `json:"txID"`
	Ret  []struct {
		ContractRet string `json:"contractRet"`
	}
	RawData struct {
		Contract []struct {
			Parameter struct {
				Value map[string]interface{}
			} `json:"parameter"`
			Type string `json:"type"`
		} `json:"contract"`
	} `json:"raw_data"`
}

type blocksResp struct {
	Block []struct {
		BlockID      string      `json:"blockID"`
		Header       blockHeader `json:"block_header"`
		Transactions []*txResp   `json:"transactions"`
	} `json:"block"`
}

func (c *Client) GetEventsOfBlock(blockNumber uint64) (*concept.BlockEventPackage, error) {
	data := map[string]interface{}{
		"startNum": blockNumber, "endNum": blockNumber + 1,
	}
	var resp blocksResp
	err := httputil.RequestJson(c.url+"/wallet/getblockbylimitnext", data, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Block) == 0 {
		return nil, errors.New("fetch block fail")
	}

	block := resp.Block[0]
	if block.Header.RawData.Number != blockNumber {
		return nil, errors.New("fetch block fail, number mismatch")
	}

	events := make([]concept.Event, 0)
	for _, tx := range block.Transactions {
		for idx, contract := range tx.RawData.Contract {
			if contract.Type == "TransferContract" {
				ret := tx.Ret[idx]
				if ret.ContractRet != "SUCCESS" {
					continue
				}
				value := contract.Parameter.Value
				fromAddr := helper.HashedBase58(helper.HexToBytes(value["owner_address"].(string)))
				toAddr := helper.HashedBase58(helper.HexToBytes(value["to_address"].(string)))
				amount := decimal.NewFromFloatWithExponent(value["amount"].(float64), 0).DivRound(tronDecimal, tronDecimalPoint)
				event := concept.GenSimpleTransferEvent(
					c.chainConfig.GetAssetByCode(c.chainConfig.ChainAssetCode),
					fromAddr, toAddr, amount, decimal.Zero, blockNumber, tx.TxID, true,
				)
				events = append(events, event)
			} else if contract.Type == "TransferAssetContract" {
				// TODO asset transfer
				ret := tx.Ret[idx]
				if ret.ContractRet != "SUCCESS" {
					continue
				}
				//value := contract.Parameter.Value
				//assetName := value["asset_name"].(string)
				//fromAddr := helper.HashedBase58(helper.HexToBytes(value["owner_address"].(string)))
				//toAddr := helper.HashedBase58(helper.HexToBytes(value["to_address"].(string)))
				//amount := decimal.NewFromFloatWithExponent(value["amount"].(float64), 0).DivRound(tronDecimal, tronDecimalPoint)
			}
		}
	}

	return &concept.BlockEventPackage{
		ChainAssetCode:  c.chainConfig.ChainAssetCode,
		BlockNumber:     blockNumber,
		BlockHash:       block.BlockID,
		Events:          events,
		NextBlockNumber: blockNumber + 1,
	}, nil
}

func signTransaction(raw *core.TransactionRaw, key *ecdsa.PrivateKey) ([]byte, []byte, error) {
	rawData, err := proto.Marshal(raw)

	if err != nil {
		return nil, nil, err
	}

	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)

	v, err := ethCrypto.Sign(hash, key)
	if err != nil {
		return nil, nil, err
	}
	return hash, v, nil
}

type tronTransferContext struct {
	AssetCode    string          `json:"asset_code"`
	FromAddr     string          `json:"from_addr"`
	ToAddr       string          `json:"to_addr"`
	Amount       decimal.Decimal `json:"amount"`
	Memo         string          `json:"memo"`
	RefHeight    uint64          `json:"ref_height"`
	RefBlockHash string          `json:"ref_block_hash"`
	FeeCode      string          `json:"fee_code"`
}

func (t *tronTransferContext) GetFeeInfo() (string, decimal.Decimal) {
	return t.FeeCode, decimal.Zero
}

func (c *Client) PrepareTransferContext(asset *concept.AssetInfo, from, to string, amount decimal.Decimal, memo string, extra map[string]interface{}) (concept.TransferContext, error) {
	var block simpleBlock
	err := httputil.RequestJson(c.url+"/wallet/getnowblock", nil, &block)
	if err != nil {
		return nil, err
	}

	return &tronTransferContext{
		AssetCode:    asset.Code,
		FromAddr:     from,
		ToAddr:       to,
		Amount:       amount,
		Memo:         memo,
		RefHeight:    block.Header.RawData.Number,
		RefBlockHash: block.BlockID,
		FeeCode:      asset.FeeCode,
	}, nil
}

func (c *Client) ParseCtxFromString(cpreparedCtx string) (concept.TransferContext, []string, error) {
	var preparedCtx tronTransferContext
	err := json.Unmarshal([]byte(cpreparedCtx), &preparedCtx)
	if err != nil {
		return nil, nil, err
	}
	return &preparedCtx, []string{preparedCtx.FromAddr}, nil
}

func (c *Client) ExecuteTransferTransaction(cprivateKeys map[string]crypto.PrivateKey, cpreparedCtx concept.TransferContext) (string, string, error) {
	preparedCtx := cpreparedCtx.(*tronTransferContext)

	contract := &core.TransferContract{
		OwnerAddress: tronAddressToBytes(preparedCtx.FromAddr),
		ToAddress:    tronAddressToBytes(preparedCtx.ToAddr),
		Amount:       preparedCtx.Amount.Mul(tronDecimal).IntPart(),
	}
	contractBytes, _ := proto.Marshal(contract)
	anyVal := any.Any{
		TypeUrl: "type.googleapis.com/protocol.TransferContract",
		Value:   contractBytes,
	}
	txContract := new(core.Transaction_Contract)
	txContract.Type = core.Transaction_Contract_TransferContract
	txContract.Parameter = &anyVal

	txRaw := new(core.TransactionRaw)
	txRaw.Contract = []*core.Transaction_Contract{txContract}

	var numBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(numBytes, preparedCtx.RefHeight)

	txRaw.RefBlockBytes = numBytes[6:8]
	txRaw.RefBlockHash = helper.HexToBytes(preparedCtx.RefBlockHash[16:32])

	now := time.Now().UnixNano() / 1000000
	txRaw.Timestamp = now
	txRaw.Expiration = now + 5*60*1000

	cprivateKey, ok := cprivateKeys[preparedCtx.FromAddr]
	if !ok {
		return "", "", errors.New("key miss")
	}
	privateKey := cprivateKey.(*ecdsa.PrivateKey)

	hash, signature, err := signTransaction(txRaw, privateKey)
	if err != nil {
		return "", "", errors.New("sign tx fail")
	}
	data := map[string]interface{}{
		"signature": []string{helper.BytesToHex(signature)},
		"txID":      helper.BytesToHex(hash),
		"raw_data": map[string]interface{}{
			"ref_block_bytes": helper.BytesToHex(txRaw.RefBlockBytes),
			"ref_block_hash":  helper.BytesToHex(txRaw.RefBlockHash),
			"timestamp":       txRaw.Timestamp,
			"expiration":      txRaw.Expiration,
			"contract": []map[string]interface{}{
				map[string]interface{}{
					"type": "TransferContract",
					"parameter": map[string]interface{}{
						"value": map[string]interface{}{
							"owner_address": tronAddressToHex(preparedCtx.FromAddr),
							"to_address":    tronAddressToHex(preparedCtx.ToAddr),
							"amount":        preparedCtx.Amount.Mul(tronDecimal).IntPart(),
						},
						"type_url": "type.googleapis.com/protocol.TransferContract",
					},
				},
			},
		},
	}
	x, _ := json.Marshal(data)
	return helper.BytesToHex(hash), string(x), nil
}

func (c *Client) KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	return KeysFromBytes(pk)
}

func (c *Client) PublicKeyToAddress(ckey crypto.PublicKey) string {
	return PublicKeyToAddress(ckey)
}
