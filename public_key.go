package tpke

import (
	"github.com/phoreproject/bls"
	"math/big"
	"math/rand"
	"time"
)

type PublicKey struct {
	G1 *bls.G1Projective
}

func (p *PublicKey) Hash(msg []byte) *bls.G2Projective {
	return bls.HashG2(msg, 0)
}

func (p *PublicKey) Verify(sig *Signature, msg []byte) bool {
	hashG2 := bls.HashG2(msg, 0)
	return bls.Pairing(p.G1, hashG2).Equals(bls.Pairing(bls.G1ProjectiveOne, sig.G2))
}

func (p *PublicKey) Encrypt(msg []byte) (*CipherText, error) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	r, err := bls.RandFR(r1)
	if err != nil {
		return nil, err
	}
	u := bls.G1AffineOne.MulFR(r.ToRepr())

	g := p.G1.ToAffine().MulFR(r.ToRepr())
	v, err := xorHash(*g, msg)
	if err != nil {
		return nil, err
	}

	w := hashH(*u, v).ToAffine().MulFR(r.ToRepr())
	return &CipherText{
		U : *u,
		V : v,
		W : *w,
	}, nil
}

func (p *PublicKey) FromBytes(bytes []byte) {

}

type PublicKeySet struct {
	commitment *Commitment
}

func (pks *PublicKeySet) Hash() {
	// TODO
}

func (pks *PublicKeySet) Threshold() int {
	return pks.commitment.degree()
}

func (pks *PublicKeySet) PublicKey() *PublicKey {
	return &PublicKey {
		G1: pks.commitment.coeff[0],
	}
}

func (pks *PublicKeySet) KeyShare(i int) *PublicKeyShare {
	fqRepr, _ := bls.FQReprFromBigInt(big.NewInt(int64(i + 1)))
	fq := bls.FQReprToFQ(fqRepr)
	eval := pks.commitment.evaluate(fq)
	return &PublicKeyShare {
		pk: &PublicKey {
			G1: eval,
		},
	}
}

type PublicKeyShare struct {
	pk *PublicKey
}