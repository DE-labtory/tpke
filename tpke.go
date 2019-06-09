package tpke

import (
	"github.com/phoreproject/bls"
)

type CipherText struct {
	U bls.G1Projective
	V []uint8
	W bls.G2Projective
}

func (c *CipherText) Verify() bool {
	hash := hashG1G2(c.U, c.V)
	return bls.Pairing(bls.G1ProjectiveOne, &c.W).Equals(bls.Pairing(&c.U, &hash))
}

func (c *CipherText) Hash() {

}

func (c *CipherText) Clone() *CipherText {
	cloneV := make([]uint8, len(c.V))
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