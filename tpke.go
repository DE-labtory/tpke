package tpke

import (
	"github.com/bls"
)

type CipherText struct {
	U bls.G1Projective
	V []byte
	W bls.G2Projective
}

func (c *CipherText) Verify() bool {
	hash := hashG1G2(c.U, c.V)
	right := bls.Pairing(c.U.Copy(), hash.ToProjective())
	left := bls.Pairing(bls.G1ProjectiveOne, &c.W)

	return left.Equals(right)
}

func (c *CipherText) Hash() {

}

func (c *CipherText) Clone() *CipherText {
	cloneV := make([]byte, len(c.V))
	for i := range cloneV {
		cloneV[i] = c.V[i]
	}

	return &CipherText {
		U: *c.U.Copy(),
		V: cloneV,
		W: *c.W.Copy(),
	}
}

type DecryptionShare struct {
	G1 *bls.G1Projective
}

func SetUp(t, p int) {

}