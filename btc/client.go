package btc

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	concept "github.com/galaxym31/swan-concept"
	helper "github.com/galaxym31/swan-helper"
	"github.com/galaxym31/swan-helper/decimal"
	"github.com/pkg/errors"
)

type Client struct {
	chainConfig *concept.ChainConfig
	client      *rpcclient.Client
	chainParams *chaincfg.Params
}

// For btc: https://btc.com/api-doc#Unspent
// For altcoin: https://github.com/richardkiss/pycoin/blob/5f7490fe4a/pycoin/symbols/doge.py

func NewBtcClient(config *concept.ChainConfig) *Client {
	var params *chaincfg.Params
	if config.ChainAssetCode == ASSET_BTC {
		params = &chaincfg.MainNetParams
	} else if config.ChainAssetCode == ASSET_TESTBTC {
		params = &chaincfg.TestNet3Params
	} else if config.ChainAssetCode == ASSET_REGBTC {
		params = &chaincfg.RegressionNetParams
	} else {
		panic("not supported chain code " + config.ChainAssetCode)
	}
	return &Client{
		chainConfig: config,
		client:      nil,
		chainParams: params,
	}
}

func (c *Client) GetChainConfig() *concept.ChainConfig {
	return c.chainConfig
}

func (c *Client) Connect(point concept.ConnectEndPoint) error {
	connCfg := &rpcclient.ConnConfig{
		Host:         point.GetUrl(),
		User:         point.GetUsername(),
		Pass:         point.GetPassword(),
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *Client) GetBalance(address string, asset string) (balance decimal.Decimal, err error) {
	// not support for utxo
	return decimal.Zero, nil
}

func (c *Client) GetCurrentHeight() (uint64, error) {
	info, err := c.client.GetBlockCount()
	if err != nil {
		return 0, err
	}
	return uint64(info), nil
}
func (c *Client) BroadcastTransaction(hexStr string) (hash string, err error) {
	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewReader(helper.HexToBytes(hexStr)))
	if err != nil {
		return "", err
	}
	h, err := c.client.SendRawTransaction(&tx, false)
	if err != nil {
		return "", err
	}
	return h.String(), nil
}
func (c *Client) GetEventsOfBlock(blockNumber uint64) (*concept.BlockEventPackage, error) {
	h, err := c.client.GetBlockHash(int64(blockNumber))
	if err != nil {
		return nil, err
	}
	result, err := c.client.GetBlockVerboseTx(h)
	if err != nil {
		return nil, err
	}
	events := make([]concept.Event, 0)
	for _, tx := range result.RawTx {
		vin := make(map[string]decimal.Decimal)
		vout := make(map[string]decimal.Decimal)
		for _, x := range tx.Vin {
			addr := fmt.Sprintf("%s,%d", x.Txid, x.Vout)
			vin[addr] = decimal.Zero
		}
		for _, x := range tx.Vout {
			addr := x.ScriptPubKey.Addresses[0]
			vout[addr] = decimal.NewFromFloat(x.Value)
		}
		event := &concept.TransferEvent{
			EventType:   concept.EventTypeTransfer,
			BlockNumber: blockNumber,
			Txid:        tx.Txid,
			Success:     true,
			Asset:       c.chainConfig.GetMainAsset(),
			Vins:        vin,
			Vouts:       vout,
			FeeConsumed: decimal.Zero,
		}
		events = append(events, event)
	}
	return &concept.BlockEventPackage{
		ChainAssetCode:  c.chainConfig.ChainAssetCode,
		BlockNumber:     blockNumber,
		BlockHash:       h.String(),
		Events:          events,
		NextBlockNumber: blockNumber + 1,
	}, nil
}

type Vinput struct {
	Txid    string          `json:"txid"`
	Vout    uint32          `json:"vout"`
	Address string          `json:"address"`
	Amount  decimal.Decimal `json:"amount"`
}

type Voutput struct {
	Address string          `json:"address"`
	Amount  decimal.Decimal `json:"amount"`
}

type btcTransferContext struct {
	AssetCode string          `json:"asset_code"`
	FromAddr  string          `json:"from_addr"`
	ToAddr    string          `json:"to_addr"`
	Amount    decimal.Decimal `json:"amount"`
	Memo      string          `json:"memo"`
	FeeCode   string          `json:"fee_code"`
	Fee       decimal.Decimal `json:"fee"`
}

func (t *btcTransferContext) GetFeeInfo() (string, decimal.Decimal) {
	return t.AssetCode, t.Fee
}

// txscript/sign_test.go
func (c *Client) PrepareTransferContext(asset *concept.AssetInfo, from, to string, amount decimal.Decimal, memo string, extra map[string]interface{}) (concept.TransferContext, error) {
	var blockNum int64 = 2
	if extra != nil {
		v, ok := extra["block"]
		if ok {
			blockNum = v.(int64)
		}
	}
	feePerKB, err := c.client.EstimateFee(blockNum)
	if err != nil {
		return nil, err
	}
	fee := decimal.NewFromFloat(feePerKB)
	// TODO cal tx size
	return &btcTransferContext{
		AssetCode: asset.Code,
		FromAddr:  from,
		ToAddr:    to,
		Amount:    amount,
		Memo:      memo,
		FeeCode:   asset.FeeCode,
		Fee:       fee,
	}, nil
}

func (c *Client) ParseCtxFromString(cpreparedCtx string) (concept.TransferContext, []string, error) {
	var preparedCtx btcTransferContext
	err := json.Unmarshal([]byte(cpreparedCtx), &preparedCtx)
	if err != nil {
		return nil, nil, err
	}
	var inputs []Vinput
	err = json.Unmarshal([]byte(preparedCtx.FromAddr), &inputs)
	if err != nil {
		return nil, nil, err
	}
	addresses := make([]string, 0, len(inputs))
	for _, input := range inputs {
		addresses = append(addresses, input.Address)
	}
	return &preparedCtx, addresses, nil
}

// decode tool: https://live.blockcypher.com/btc/decodetx/
// TODO zz only support P2SH(P2WPKH), should support more address type
func (c *Client) ExecuteTransferTransaction(cprivateKeys map[string]crypto.PrivateKey, cpreparedCtx concept.TransferContext) (string, string, error) {
	preparedCtx := cpreparedCtx.(*btcTransferContext)

	if !preparedCtx.Amount.Equal(decimal.Zero) {
		return "", "", errors.New("param amount should be zero")
	}
	var inputs []Vinput
	err := json.Unmarshal([]byte(preparedCtx.FromAddr), &inputs)
	if err != nil {
		return "", "", errors.Wrap(err, "parse from error")
	}
	var outs []Voutput
	err = json.Unmarshal([]byte(preparedCtx.ToAddr), &outs)
	if err != nil {
		return "", "", errors.Wrap(err, "parse to error")
	}

	mtx := wire.NewMsgTx(2)
	for _, out := range outs {
		amount := out.Amount.Mul(BtcDecimal)
		// Ensure amount is in the valid range for monetary amounts.
		if amount.LessThan(decimal.Zero) || amount.GreaterThan(decimal.New(btcutil.MaxSatoshi, 0)) {
			return "", "", fmt.Errorf("invalid amount %s", amount)
		}

		// Decode the provided address.
		addr, err := btcutil.DecodeAddress(out.Address, c.chainParams)
		if err != nil {
			return "", "", fmt.Errorf("invalid address format: %s", out.Address)
		}

		// Ensure the address is one of the supported types and that
		// the network encoded with the address matches the network the
		// server is currently on.
		switch addr.(type) {
		case *btcutil.AddressPubKeyHash:
		case *btcutil.AddressScriptHash:
		default:
			return "", "", &btcjson.RPCError{
				Code:    btcjson.ErrRPCInvalidAddressOrKey,
				Message: "Invalid address or key",
			}
		}
		if !addr.IsForNet(c.chainParams) {
			return "", "", &btcjson.RPCError{
				Code: btcjson.ErrRPCInvalidAddressOrKey,
				Message: "Invalid address: " + out.Address +
					" is for the wrong network",
			}
		}

		// Create a new script which pays to the provided address.
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", "", errors.Wrap(err, "Failed to generate pay-to-address script")
		}

		txOut := wire.NewTxOut(amount.IntPart(), pkScript)
		mtx.AddTxOut(txOut)
	}

	for idx, input := range inputs {
		_ = idx

		fmt.Println(input.Txid, len(input.Txid))
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return "", "", errors.Wrap(err, "parse previous txid error")
		}

		prevOut := wire.NewOutPoint(txHash, input.Vout)

		txIn := wire.NewTxIn(prevOut, nil, nil)
		mtx.AddTxIn(txIn)
	}

	for idx, txIn := range mtx.TxIn {
		input := inputs[idx]
		cprivateKey, ok := cprivateKeys[input.Address]
		if !ok {
			return "", "", errors.New("key miss")
		}

		privateKey := cprivateKey.(*btcec.PrivateKey)

		redeemScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(btcutil.Hash160(privateKey.PubKey().SerializeCompressed())).Script()
		if err != nil {
			return "", "", err
		}

		witness, err := txscript.WitnessSignature(
			mtx, txscript.NewTxSigHashes(mtx),
			idx, input.Amount.Mul(BtcDecimal).IntPart(),
			redeemScript, txscript.SigHashAll, privateKey, true)

		if err != nil {
			return "", "", err
		}

		txIn.Witness = witness
		txIn.SignatureScript = helper.HexToBytes("16" + helper.BytesToHex(redeemScript))
	}

	return mtx.TxHash().String(), txHexString(mtx), nil
}

func txHexString(tx *wire.MsgTx) string {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	// Ignore Serialize's error, as writing to a bytes.buffer cannot fail.
	tx.Serialize(buf)
	return hex.EncodeToString(buf.Bytes())
}

func (c *Client) KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	return KeysFromBytes(pk)
}

func (c *Client) PublicKeyToAddress(ckey crypto.PublicKey) string {
	return PublicKeyToSegwitAddress(ckey, c.chainParams)
}
