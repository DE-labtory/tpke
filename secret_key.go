package tpke

import (
	"github.com/phoreproject/bls"
	"math/big"
)

type SecretKey struct {
	FQ bls.FQ
}

func (s *SecretKey) PublicKey() *PublicKey {
	return &PublicKey {
		G1: bls.G1AffineOne.Mul(s.FQ.ToRepr()),
	}
}

func (s *SecretKey) Sign(msg []byte) *Signature {
	g2Hash := bls.HashG2(msg, 0)
	return &Signature {
		G2: g2Hash.Mul(s.FQ.ToRepr()),
	}
}

func (s *SecretKey) Decrypt(cipher *CipherText) []byte {
	if !cipher.Verify() {
		return nil
	}
	g := cipher.U.ToAffine().Mul(s.FQ.ToRepr())
	d, _ := xorHash(*g, cipher.V)
	return d
}

type SecretKeySet struct {
	poly Poly
}

func randomSecretKeySet(threshold int) *SecretKeySet {
	randomPoly := randomPoly(threshold)
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
	fqRepr, _ := bls.FQReprFromBigInt(big.NewInt(int64(i + 1)))
	fq := bls.FQReprToFQ(fqRepr)
	eval := sks.poly.evaluate(fq)
	return &SecretKeyShare {
		sk: &SecretKey {
			FQ: eval,
		},
	}
}

type SecretKeyShare struct {
	sk *SecretKey
}

func (sks *SecretKeyShare) DecryptShare(ct CipherText) *DecryptionShare {
	// TODO : verify
	return &DecryptionShare {
		G1: ct.U.ToAffine().Mul(sks.sk.FQ.ToRepr()),
	}
}