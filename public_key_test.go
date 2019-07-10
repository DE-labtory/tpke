package tpke

import (
	"crypto/rand"
	"github.com/DE-labtory/tpke/bls"
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

func TestPublicKeySet_Serialize(t *testing.T) {
	poly := randomPoly(10)
	commit := poly.commitment()
	pks := &PublicKeySet {
		commitment: commit,
	}
	serial := pks.Serialize()
	pks2, err := NewPublicKeySetFromBytes(serial)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !pks.Equals(pks2) {
		t.Fatalf("public key sets must be equal")
	}

	t.Logf("pks: %v", pks.commitment.coeff)
	t.Logf("pks2: %v", pks2.commitment.coeff)
}