package tpke

import (
	"crypto/rand"
	"github.com/bls"
	"testing"
)

func TestPublicKey_Serialize(t *testing.T) {
	g1, _ := bls.RandG1(rand.Reader)
	pubKey := &PublicKey {
		G1: g1,
	}

	bytes := pubKey.Serialize()

	pubKey2 := NewPublicKeyFromBytes(bytes)

	if !pubKey.Equals(pubKey2) {
		t.Fatalf("test failed.")
	}
}
