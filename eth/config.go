package eth

import (
	concept "github.com/galaxym31/swan-concept"
	"github.com/galaxym31/swan-helper/decimal"
)

const (
	ASSET_ETH_ETH   = "ETH_ETH"
	ethDecimalPoint = 18
)

var ethDecimal = decimal.New(1, ethDecimalPoint)

const (
	ASSET_TESTETH_ETH = "TESTETH_ETH"
	ASSET_TESTETH_TRU = "TESTETH_TRU"
)

var EthConnectEndPoint = &concept.ConnectEndPointImpl{
	Url: "https://main-rpc.linkpool.io",
}

var ChainConfigEth = concept.NewChainConfig(ASSET_ETH_ETH).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_ETH_ETH,
		Type:         concept.AssetTypeAccount,
		DeriveNumber: 2000,
		DecimalPoint: ethDecimalPoint,
	},
)

var TestEthConnectEndPoint = &concept.ConnectEndPointImpl{
	Url: "http://52.208.46.161:8549",
}

var ChainConfigEthTestnet = concept.NewChainConfig(ASSET_TESTETH_ETH).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_TESTETH_ETH,
		DeriveNumber: 2100,
		Type:         concept.AssetTypeAccount,
		DecimalPoint: ethDecimalPoint,
	},
).RegisterAsset(
	&concept.AssetInfo{
		Code:         ASSET_TESTETH_TRU,
		Type:         concept.AssetTypeAccount,
		DecimalPoint: 2,
		TokenAddress: "0x30707240885fe83c86b3b943e6b479899168c647",
	},
)
