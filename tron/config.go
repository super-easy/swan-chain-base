package tron

import (
	concept "github.com/galaxym31/swan-concept"
	"github.com/galaxym31/swan-helper/decimal"
)

const (
	ASSET_TRON_TRON     = "TRON_TRON"
	ASSET_TESTTRON_TRON = "TESTTRON_TRON"
	tronDecimalPoint    = 6
)

var tronDecimal = decimal.New(1, tronDecimalPoint)

var TronConnectEndPoint = &concept.ConnectEndPointImpl{
	Url: "http://52.53.189.99:8090",
}

var ChainConfigTron = concept.NewChainConfig(ASSET_TRON_TRON).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_TRON_TRON,
		Type:         concept.AssetTypeAccount,
		DeriveNumber: 5000,
		DecimalPoint: tronDecimalPoint,
	},
)

var TestTronConnectEndPoint = &concept.ConnectEndPointImpl{
	Url: "https://api.shasta.trongrid.io",
}

var ChainConfigTestTron = concept.NewChainConfig(ASSET_TESTTRON_TRON).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_TESTTRON_TRON,
		Type:         concept.AssetTypeAccount,
		DeriveNumber: 5100,
		DecimalPoint: tronDecimalPoint,
	},
)
