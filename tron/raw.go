package tron

import helper "github.com/galaxym31/swan-helper"

func hexToTronAddress(h string) string {
	return helper.HashedBase58(helper.HexToBytes(h))
}

func tronAddressToBytes(addr string) []byte {
	return helper.HashedBase58Decode(addr)
}

func tronAddressToHex(addr string) string {
	return helper.BytesToHex(tronAddressToBytes(addr))
}
