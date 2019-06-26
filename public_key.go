package tpke

import (
	"crypto/rand"
	"fmt"
	"github.com/bls"
)

type PublicKey struct {
	G1 *bls.G1Projective
}

func (p *PublicKey) Hash(msg [32]byte) *bls.G2Projective {
	return bls.HashG2WithDomain(msg, 0)
}

func (p *PublicKey) Verify(sig *Signature, msg []byte) bool {
	hashG2 := bls.HashG2(msg)
	one := bls.G1ProjectiveOne
	left := bls.Pairing(p.G1.Copy(), hashG2.ToProjective().Copy())
	right := bls.Pairing(one, sig.G2)
	return left.Equals(right)
}

func (p *PublicKey) Encrypt(msg []byte) (*CipherText, error) {

	if len(msg) > 32 {
		return nil, nil
	}

	r, err := bls.RandFR(rand.Reader)
	if err != nil {
		return nil, err
	}
	u := bls.G1AffineOne.MulFR(r.ToRepr())

	g := p.G1.ToAffine().MulFR(r.ToRepr())

	v := xorHash(*g, msg)
	if err != nil {
		return nil, err
	}
	hashed := hashG1G2(*u, v)
	affine := hashed
	w := affine.MulFR(r.ToRepr())
	return &CipherText{
		U : *u,
		V : v,
		W : *w,
	}, nil
}

func (p *PublicKey) FromBytes(bytes []byte) {

}

func (p *PublicKey) Serialize() [96]byte {
	return p.G1.ToAffine().SerializeBytes()
}

type PublicKeySet struct {
	commitment *Commitment
}

func (pks *PublicKeySet) Clone() *PublicKeySet {
	return &PublicKeySet {
		commitment: pks.commitment.Clone(),
	}
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
	fr := bls.FRReprToFR(bls.NewFRRepr(uint64(i + 1)))
	eval := pks.commitment.evaluate(*fr)
	return &PublicKeyShare {
		pk: &PublicKey {
			G1: eval,
		},
	}
}

func (pks *PublicKeySet) Decrypt(ds map[int]*DecryptionShare, ct *CipherText) ([]byte, error) {
	samples := make([]*Sample, 0)
	i := 0
	for id, d := range ds {
		samples = append(samples, &Sample {
			fr: bls.FRReprToFR(bls.NewFRRepr(uint64(id + 1))),
			g1: d.G1.Copy(),
		})
		i++
	}
	g, err := Interpolate(pks.commitment.degree(), samples)
	fmt.Printf("g: %v\n", g)
	if err != nil {
		return nil, err
	}

	return xorHash(*g, ct.V), nil
}

func (pks *PublicKeySet) Equals(other *PublicKeySet) bool {
	if len(pks.commitment.coeff) != len(other.commitment.coeff) {
		return false
	}

	for i := range pks.commitment.coeff {
		if !pks.commitment.coeff[i].Equal(other.commitment.coeff[i]) {
			return false
		}
	}
	return true
}

func (pks *PublicKeySet) Serialize() []byte {
	bytes := make([]byte, 0)
	for i := range pks.commitment.coeff {
		g := pks.commitment.coeff[i]
		affine := g.ToAffine()
		serial := affine.SerializeBytes()
		for j := range serial {
			bytes = append(bytes, serial[j])
		}
	}
	return bytes
}

type PublicKeyShare struct {
	pk *PublicKey
}