package btc

import (
	concept "github.com/galaxym31/swan-concept"
	"github.com/galaxym31/swan-helper/decimal"
)

const (
	BtcDecimalPoint = 8
)

const (
	ASSET_BTC     = "BTC"
	ASSET_TESTBTC = "TESTBTC"
	ASSET_REGBTC  = "REGBTC_BTC"
)

var (
	BtcDecimal = decimal.New(1, BtcDecimalPoint)
)

var BtcConnectEndPoint = &concept.ConnectEndPointImpl{
	Url:      "",
	Username: "",
	Password: "",
}

var ChainConfigBtc = concept.NewChainConfig(ASSET_BTC).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_BTC,
		Type:         concept.AssetTypeUtxo,
		DeriveNumber: 1000,
		DecimalPoint: BtcDecimalPoint,
	},
)

var TestBtcConnectEndPoint = &concept.ConnectEndPointImpl{
	Url:      "",
	Username: "",
	Password: "",
}

var ChainConfigTestBtc = concept.NewChainConfig(ASSET_TESTBTC).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_TESTBTC,
		Type:         concept.AssetTypeUtxo,
		DeriveNumber: 1000,
		DecimalPoint: BtcDecimalPoint,
	},
)

// https://bitcoin.org/en/developer-examples#simple-raw-transaction
// https://bitcoin.org/en/developer-reference#gettransaction
var RegBtcConnectEndPoint = &concept.ConnectEndPointImpl{
	Url:      "127.0.0.1:18443",
	Username: "fyz",
	Password: "fyz",
}

var ChainConfigRegBtc = concept.NewChainConfig(ASSET_REGBTC).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_REGBTC,
		Type:         concept.AssetTypeUtxo,
		DeriveNumber: 1200,
		DecimalPoint: BtcDecimalPoint,
	},
)
