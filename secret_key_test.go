package tpke

import (
	"github.com/DE-labtory/tpke/bls"
	"testing"
)

func TestSecretKeySet(t *testing.T) {
	fr1 := &bls.FRRepr{11461019170205349423, 12272630964495617950, 9149182916965293782, 6231711138846263786}
	fr2 := &bls.FRRepr{12852770524937451773, 15186792727181123651, 15751227662529177088, 7207065174582100258}
	skSet := &SecretKeySet {
		poly: Poly {
			coeff: []*bls.FR{
				bls.FRReprToFR(fr1),
				bls.FRReprToFR(fr2),
			},
		},
	}

	pkSet := skSet.PublicKeySet()
	t.Logf("%v", pkSet)
	// PASS

	ks0 := skSet.KeyShare(0)
	ks1 := skSet.KeyShare(1)
	ks2 := skSet.KeyShare(2)

	t.Logf("%v", ks0)
	t.Logf("%v", ks1)
	t.Logf("%v", ks2)
}

func TestSecretKey_Serialize(t *testing.T) {
	sk := randomSecretKey(100)
	t.Logf("%v", sk)
	t.Logf("%v", sk.Serialize())
	serial := sk.Serialize()

	sk2 := NewSecretKeyFromBytes(serial)

	if !sk.Equals(sk2) {
		t.Fatalf("test failed.")
	}
}