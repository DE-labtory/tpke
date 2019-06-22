package tpke

import (
	"github.com/bls"
)

type SecretKey struct {
	FR *bls.FR
}

func (s *SecretKey) PublicKey() *PublicKey {
	return &PublicKey {
		G1: bls.G1AffineOne.MulFR(s.FR.ToRepr()),
	}
}

func (s *SecretKey) Sign(msg []byte) *Signature {
	g2Hash := HashG2(msg).ToAffine()
	return &Signature {
		G2: g2Hash.MulFR(s.FR.ToRepr()),
	}
}

func (s *SecretKey) Decrypt(cipher *CipherText) []byte {
	if !cipher.Verify() {
		return nil
	}
	g := cipher.U.ToAffine().MulFR(s.FR.ToRepr())
	//d, _ := xorHash(*g, cipher.V)
	d := xorHash(*g, cipher.V)
	return d
}

type SecretKeySet struct {
	poly Poly
}

func RandomSecretKeySet(threshold int) *SecretKeySet {
	randomPoly := randomPoly(threshold + 1)
	return &SecretKeySet{
		poly: *randomPoly,
	}
}

func (sks *SecretKeySet) threshold() int {
	return sks.poly.degree()
}

func (sks *SecretKeySet) publicKeySet() *PublicKeySet {
	return &PublicKeySet{
		commitment: sks.poly.commitment(),
	}
}

func (sks *SecretKeySet) keyShare(i int) *SecretKeyShare {
	//fr := bls.FRReprToFR(bls.NewFRRepr(uint64(i + 1)))
	fr := bls.FRReprToFR(bls.NewFRRepr(uint64(1)))
	x := bls.FRReprToFR(bls.NewFRRepr(uint64(i)))
	fr.AddAssign(x)
	eval := sks.poly.evaluate(*fr)
	return &SecretKeyShare {
		sk: &SecretKey {
			FR: eval,
		},
	}
}

type SecretKeyShare struct {
	sk *SecretKey
}

func (sks *SecretKeyShare) DecryptShare(ct *CipherText) *DecryptionShare {
	// TODO : verify
	return &DecryptionShare {
		G1: ct.U.ToAffine().MulFR(sks.sk.FR.ToRepr()).Copy(),
	}
}