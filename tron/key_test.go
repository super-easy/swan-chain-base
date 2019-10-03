package tron

import (
	helper "github.com/galaxym31/swan-helper"
	"testing"
)

func TestPublicKeyToAddress(t *testing.T) {
	_, pub := KeysFromBytes(helper.HexToBytes("E02F410EB88994B680570C499C6F6F00E06DB151BB655513DCD6727AB03C1A0E"))
	addr := PublicKeyToAddress(pub)
	if addr != "TYRQiczoYUFXzyzSnP6gLviH8S3NVTJGUa" {
		t.Error("tron address fail")
	}
}
