package eth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	concept "github.com/galaxym31/swan-concept"
	helper "github.com/galaxym31/swan-helper"
	"github.com/galaxym31/swan-helper/decimal"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strings"
)

/*
Public Nodes:
https://medium.com/linkpool/release-of-public-ethereum-rpcs-f5dd57455d2e

Doc:
https://goethereumbook.org/en/transfer-tokens/
*/

var Erc20ABI, _ = abi.JSON(strings.NewReader(erc20AbiJson))
var EmptyErc20Contract = bind.NewBoundContract(common.BigToAddress(big.NewInt(0)), Erc20ABI, nil, nil, nil)

type Client struct {
	ctx                 context.Context
	chainConfig         *concept.ChainConfig
	url                 string
	rawClient           *rpc.Client
	rpcClient           *ethclient.Client
	signerType          types.Signer
	erc20ContractMap    map[string]*bind.BoundContract
	erc20AddrToAssetMap map[string]*concept.AssetInfo
	erc20Addresses      []common.Address
}

func NewEthClient(config *concept.ChainConfig) *Client {
	var signer types.Signer = nil
	if config.ChainAssetCode == ASSET_ETH_ETH {
		signer = types.MakeSigner(params.MainnetChainConfig, nil)
	} else if config.ChainAssetCode == ASSET_TESTETH_ETH {
		signer = types.MakeSigner(params.TestnetChainConfig, nil)
	} else {
		panic(fmt.Errorf("not supported chain %s", config.ChainAssetCode))
	}
	addrToAssetMap := make(map[string]*concept.AssetInfo)
	erc20Addresses := make([]common.Address, 0)
	for _, asset := range config.Assets {
		if isErc20Asset(asset) {
			addrToAssetMap[asset.TokenAddress] = asset
			erc20Addresses = append(erc20Addresses, common.HexToAddress(asset.TokenAddress))
		}
	}
	return &Client{
		ctx:                 context.TODO(),
		chainConfig:         config,
		rawClient:           nil,
		rpcClient:           nil,
		signerType:          signer,
		erc20ContractMap:    make(map[string]*bind.BoundContract),
		erc20AddrToAssetMap: addrToAssetMap,
		erc20Addresses:      erc20Addresses,
	}
}

func (c *Client) Connect(point concept.ConnectEndPoint) error {
	rawClient, err := rpc.DialContext(context.Background(), point.GetUrl())
	if err != nil {
		return errors.Wrap(err, "connect eth fail")
	}
	client := ethclient.NewClient(rawClient)
	c.rawClient = rawClient
	c.rpcClient = client
	return nil
}

func (c *Client) GetChainConfig() *concept.ChainConfig {
	return c.chainConfig
}

func (c *Client) getErc20Contract(caddr string) *bind.BoundContract {
	v, ok := c.erc20ContractMap[caddr]
	if ok {
		return v
	}
	addr := common.HexToAddress(caddr)
	contract := bind.NewBoundContract(addr, Erc20ABI, c.rpcClient, nil, nil)
	c.erc20ContractMap[caddr] = contract
	return contract
}

type ethTransferContext struct {
	AssetCode string          `json:"asset_code"`
	FromAddr  string          `json:"from_addr"`
	ToAddr    string          `json:"to_addr"`
	Amount    decimal.Decimal `json:"amount"`
	Memo      string          `json:"memo"`
	GasLimit  decimal.Decimal `json:"gas_limit"`
	GasPrice  decimal.Decimal `json:"gas_price"`
	Nonce     uint64          `json:"nonce"`
	Data      string          `json:"data"`
	FeeCode   string          `json:"fee_code"`
}

func (t *ethTransferContext) GetFeeInfo() (string, decimal.Decimal) {
	return t.FeeCode, t.GasLimit.Mul(t.GasPrice).DivRound(ethDecimal, ethDecimalPoint)
}

func isMainAsset(asset *concept.AssetInfo) bool {
	return asset.Code == ChainConfigEth.ChainAssetCode || asset.Code == ChainConfigEthTestnet.ChainAssetCode
}

func isErc20Asset(asset *concept.AssetInfo) bool {
	return (asset.Chain.ChainAssetCode == ChainConfigEth.ChainAssetCode || asset.Chain.ChainAssetCode == ChainConfigEthTestnet.ChainAssetCode) && len(asset.TokenAddress) > 0
}

func (c *Client) PrepareTransferContext(asset *concept.AssetInfo, from, to string, amount decimal.Decimal, memo string, extra map[string]interface{}) (concept.TransferContext, error) {
	nonce, err := c.GetNonce(from)
	if err != nil {
		return nil, err
	}
	price, err := c.SuggestGasPrice()
	if err != nil {
		return nil, err
	}
	var fee decimal.Decimal
	var data []byte
	if isMainAsset(asset) {
		fee, err = c.EstimateFee(to, emptyData)
		if err != nil {
			return nil, err
		}
	} else if isErc20Asset(asset) {
		data = c.CalErc20TransactionData(to, amount)
		fee, err = c.EstimateFee(to, data)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("not supported asset %s in eth", asset.Code)
	}
	return &ethTransferContext{
		AssetCode: asset.Code,
		FromAddr:  from,
		ToAddr:    to,
		Amount:    amount,
		Memo:      memo,
		GasLimit:  fee,
		GasPrice:  price,
		Nonce:     nonce,
		Data:      helper.BytesToHex(data),
		FeeCode:   asset.FeeCode,
	}, nil
}

func (c *Client) ParseCtxFromString(cpreparedCtx string) (concept.TransferContext, []string, error) {
	var preparedCtx ethTransferContext
	err := json.Unmarshal([]byte(cpreparedCtx), &preparedCtx)
	if err != nil {
		return nil, nil, err
	}
	return &preparedCtx, []string{preparedCtx.FromAddr}, nil
}

func (c *Client) ExecuteTransferTransaction(cprivateKeys map[string]crypto.PrivateKey, cpreparedCtx concept.TransferContext) (string, string, error) {
	preparedCtx := cpreparedCtx.(*ethTransferContext)

	cprivateKey, ok := cprivateKeys[preparedCtx.FromAddr]
	if !ok {
		return "", "", errors.New("key miss")
	}

	asset := c.chainConfig.GetAssetByCode(preparedCtx.AssetCode)
	if isMainAsset(asset) {
		return c.GenerateAndSignTransferTransaction(cprivateKey, preparedCtx.ToAddr, preparedCtx.Nonce, preparedCtx.Amount, preparedCtx.GasLimit, preparedCtx.GasPrice)
	} else if isErc20Asset(asset) {
		return c.SignErc20Transaction(cprivateKey, asset.TokenAddress, preparedCtx.Nonce, helper.HexToBytes(preparedCtx.Data), preparedCtx.GasLimit, preparedCtx.GasPrice)
	} else {
		return "", "", fmt.Errorf("not supported asset %s in eth", asset.Code)
	}
}

func (c *Client) GenerateAndSignTransferTransaction(cprivateKey crypto.PrivateKey, to string, nonce uint64, amount decimal.Decimal, fee, gasprice decimal.Decimal) (string, string, error) {
	amount = amount.Mul(ethDecimal)

	privateKey := cprivateKey.(*ecdsa.PrivateKey)
	tx := types.NewTransaction(nonce, common.HexToAddress(to), amount.ToBigInt(), uint64(fee.IntPart()), gasprice.ToBigInt(), emptyData)
	signedTx, err := types.SignTx(tx, c.signerType, privateKey)
	if err != nil {
		return "", "", errors.Wrap(err, "sign tx fail")
	}
	v, _ := rlp.EncodeToBytes(signedTx)
	rawTx := helper.BytesToHex(v)
	return signedTx.Hash().Hex(), rawTx, nil
}

func (c *Client) CalErc20TransactionData(to string, amount decimal.Decimal) []byte {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println(hexutil.Encode(methodID)) // 0xa9059cbb

	paddedAddress := common.LeftPadBytes(common.HexToAddress(to).Bytes(), 32)
	fmt.Println(hexutil.Encode(paddedAddress)) // 0x0000000000000000000000004592d8f8d7b001e72cb26a73e4fa1806a51ac79d

	paddedAmount := common.LeftPadBytes(amount.ToBigInt().Bytes(), 32)
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	return data
}

func (c *Client) SignErc20Transaction(cprivateKey crypto.PrivateKey, contractAddress string, nonce uint64, data []byte, fee, gasprice decimal.Decimal) (string, string, error) {
	privateKey := cprivateKey.(*ecdsa.PrivateKey)

	tx := types.NewTransaction(nonce, common.HexToAddress(contractAddress), big.NewInt(0), uint64(fee.IntPart()), gasprice.ToBigInt(), data)
	signedTx, err := types.SignTx(tx, c.signerType, privateKey)
	if err != nil {
		return "", "", errors.Wrap(err, "sign tx fail")
	}
	v, _ := rlp.EncodeToBytes(signedTx)
	rawTx := helper.BytesToHex(v)
	return signedTx.Hash().Hex(), rawTx, nil
}

func (c *Client) GetBalance(address string, asset string) (balance decimal.Decimal, err error) {
	addr := common.HexToAddress(address)
	assetInfo := c.chainConfig.GetAssetByCode(asset)
	if isMainAsset(assetInfo) {
		ib, e := c.rpcClient.BalanceAt(c.ctx, addr, nil)
		if e != nil {
			err = e
			return
		}
		balance = decimal.NewFromBigInt(ib, 0).Div(ethDecimal)
	} else {
		var out interface{}
		err = c.getErc20Contract(assetInfo.TokenAddress).Call(nil, &out, "balanceOf", common.HexToAddress(address))
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(out)
	}
	return
}

func (c *Client) GetCurrentHeight() (uint64, error) {
	var num hexutil.Uint
	err := c.rawClient.Call(&num, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	return uint64(num), nil
}

func (c *Client) BroadcastTransaction(hexStr string) (hash string, err error) {
	err = c.rawClient.Call(&hash, "eth_sendRawTransaction", "0x"+hexStr)
	return
}

func (c *Client) GetNonce(addr string) (uint64, error) {
	return c.rpcClient.NonceAt(c.ctx, common.HexToAddress(addr), nil)
}

func (c *Client) EstimateFee(to string, data []byte) (decimal.Decimal, error) {
	toAddr := common.HexToAddress(to)
	msg := ethereum.CallMsg{To: &toAddr, Data: data}
	v, err := c.rpcClient.EstimateGas(c.ctx, msg)
	if err != nil {
		return decimal.Zero, err
	}
	return decimal.New(int64(v), 0), nil
}

func (c *Client) SuggestGasPrice() (decimal.Decimal, error) {
	v, err := c.rpcClient.SuggestGasPrice(c.ctx)
	if err != nil {
		return decimal.Zero, err
	}
	return decimal.NewFromBigInt(v, 0), nil
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

func (ec *Client) BlockByNumber(ctx context.Context, number *big.Int) (*rpcBlock, error) {
	return ec.getBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(number), true)
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (ec *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*rpcBlock, error) {
	var raw json.RawMessage
	err := ec.rawClient.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	return &body, nil
}

func (c *Client) GetEventsOfBlock(blockNumber uint64) (*concept.BlockEventPackage, error) {
	block, err := c.BlockByNumber(c.ctx, big.NewInt(int64(blockNumber)))
	if err != nil {
		return nil, errors.Wrapf(err, "fetch eth block fail %d", blockNumber)
	}
	events := make([]concept.Event, 0)
	for _, tx := range block.Transactions {
		if tx.From == nil || tx.tx.To() == nil {
			continue
		}
		fromAddr := strings.ToLower(tx.From.Hex())
		toAddr := strings.ToLower(tx.tx.To().Hex())
		if toAddr == "0x0000000000000000000000000000000000000000" {
			continue
		}
		amount := decimal.NewFromBigInt(tx.tx.Value(), 0).DivRound(ethDecimal, ethDecimalPoint)
		if amount.Equal(decimal.Zero) {
			continue
		}
		fee := decimal.NewFromBigInt(tx.tx.GasPrice(), 0).Mul(decimal.New(int64(tx.tx.Gas()), 0)).Div(ethDecimal)
		event := concept.GenSimpleTransferEvent(
			c.chainConfig.GetAssetByCode(c.chainConfig.ChainAssetCode), fromAddr, toAddr, amount, fee, blockNumber, tx.tx.Hash().Hex(), true,
		)
		events = append(events, event)
	}
	// TODO fetch receipts to get real consumed gas
	tokenEvents, err := c.getBlockReceipts(blockNumber)
	if err == nil && len(tokenEvents) > 0 {
		events = append(events, tokenEvents...)
	}
	return &concept.BlockEventPackage{
		ChainAssetCode:  c.chainConfig.ChainAssetCode,
		BlockNumber:     blockNumber,
		BlockHash:       block.Hash.String(),
		Events:          events,
		NextBlockNumber: blockNumber + 1,
	}, nil
}

func (c *Client) getBlockReceipts(blockNumber uint64) ([]concept.Event, error) {
	b := big.NewInt(int64(blockNumber))
	logs, err := c.rpcClient.FilterLogs(c.ctx, ethereum.FilterQuery{
		FromBlock: b,
		ToBlock:   b,
		Addresses: c.erc20Addresses,
	})
	if err != nil {
		return nil, err
	}
	events := make([]concept.Event, 0)
	for _, log := range logs {
		if log.Removed {
			continue
		}
		toAddr := strings.ToLower(log.Address.Hex())
		assetInfo, ok := c.erc20AddrToAssetMap[toAddr]
		if !ok {
			continue
		}
		ifc := make(map[string]interface{})
		err = EmptyErc20Contract.UnpackLogIntoMap(ifc, "Transfer", log)
		if err != nil {
			fmt.Println(err)
			continue
		}
		from := strings.ToLower(ifc["from"].(common.Address).Hex())
		to := strings.ToLower(ifc["to"].(common.Address).Hex())
		amount := decimal.NewFromBigInt(ifc["value"].(*big.Int), 0).DivRound(decimal.New(1, assetInfo.DecimalPoint), assetInfo.DecimalPoint)
		event := concept.GenSimpleTransferEvent(
			assetInfo, from, to, amount, decimal.Zero, blockNumber, strings.ToLower(log.TxHash.Hex()), true,
		)
		events = append(events, event)
	}
	return events, nil
}

type rpcReceipt struct {
	TransactionHash string       `json:"transactionHash"`
	Logs            []*types.Log `json:"logs"`
	Status          string       `json:"status"`
}

func (c *Client) GetTransactionReceipts(txid string, blockNumber uint64, assetInfo *concept.AssetInfo, fee decimal.Decimal) ([]concept.Event, error) {
	var r *rpcReceipt
	err := c.rawClient.CallContext(c.ctx, &r, "eth_getTransactionReceipt", txid)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}
	fmt.Println(txid)
	fmt.Println(r)
	fmt.Println(hexutil.DecodeUint64(r.Status))
	events := make([]concept.Event, 0)
	for _, log := range r.Logs {
		if log.Removed {
			continue
		}
		ifc := make(map[string]interface{})
		err = EmptyErc20Contract.UnpackLogIntoMap(ifc, "Transfer", *r.Logs[0])
		from := ifc["from"].(common.Address).Hex()
		to := ifc["to"].(common.Address).Hex()
		amount := decimal.NewFromBigInt(ifc["value"].(*big.Int), 0).Div(decimal.New(1, assetInfo.DecimalPoint))
		event := concept.GenSimpleTransferEvent(
			assetInfo, from, to, amount, fee, blockNumber, txid, true,
		)
		events = append(events, event)
	}

	return events, nil
}

func (c *Client) KeysFromBytes(pk []byte) (crypto.PrivateKey, crypto.PublicKey) {
	return KeysFromBytes(pk)
}

func (c *Client) PublicKeyToAddress(ckey crypto.PublicKey) string {
	return PublicKeyToAddress(ckey)
}
