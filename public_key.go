package tpke

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/DE-labtory/tpke/bls"
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

	//if len(msg) > 32 {
	//	return nil, nil
	//}

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

func (p *PublicKey) Equals(other *PublicKey) bool {
	return p.G1.Equal(other.G1)
}

func NewPublicKeyFromBytes(bytes [96]byte) *PublicKey {
	var b [48]byte
	for i := range b {
		b[i] = bytes[i]
	}
	x := bls.FQReprFromBytes(b)

	for i := range b {
		b[i] = bytes[i + 48]
	}
	y := bls.FQReprFromBytes(b)

	g1Affine := bls.NewG1Affine(bls.FQReprToFQ(x), bls.FQReprToFQ(y))
	return &PublicKey {
		G1: g1Affine.ToProjective(),
	}
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

func (pks *PublicKeySet) DecryptUsingStringMap(ds map[string]*DecryptionShare, ct *CipherText) ([]byte, error) {
	samples := make([]*Sample, 0)
	i := 0
	for id, d := range ds {
		fr, err := bls.FRReprFromString(id, 10)
		if err != nil {
			return nil, err
		}
		samples = append(samples, &Sample {
			fr: bls.FRReprToFR(fr),
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

func NewPublicKeySetFromBytes(bytes []byte) (*PublicKeySet, error) {
	l := len(bytes)
	if l % 96 != 0 {
		return nil, errors.New("the length of input must be a multiple of 96")
	}
	g1Arr := make([]*bls.G1Projective, 0)
	idx := 0
	for i := 0; i < l / 96; i++ {
		var xArr [48]byte
		var yArr [48]byte
		for j := 0; j < 48; j++ {
			xArr[j] = bytes[idx]
			idx++
		}
		for j := 0; j < 48; j++ {
			yArr[j] = bytes[idx]
			idx++
		}
		fqXrepr := bls.FQReprFromBytes(xArr)
		fqYrepr := bls.FQReprFromBytes(yArr)
		fqX := bls.FQReprToFQ(fqXrepr)
		fqY := bls.FQReprToFQ(fqYrepr)

		g1 := bls.NewG1Affine(fqX, fqY).ToProjective()
		g1Arr = append(g1Arr, g1)
	}
	return &PublicKeySet {
		commitment: &Commitment {
			coeff: g1Arr,
		},
	}, nil
}

type PublicKeyShare struct {
	pk *PublicKey
}