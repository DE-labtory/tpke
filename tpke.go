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

func (c *CipherText) Serialize() []byte {
	ret := make([]byte, 0)
	uSerial := c.U.ToAffine().SerializeBytes()
	wSerial := c.W.ToAffine().SerializeBytes()
	for i:=0; i<len(uSerial); i++ {
		ret = append(ret, uSerial[i])
	}
	for i:=0; i<len(wSerial); i++ {
		ret = append(ret, wSerial[i])
	}
	for i:=0; i<len(c.V); i++ {
		ret = append(ret, c.V[i])
	}
	return ret
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

func (c *CipherText) Equals(other *CipherText) bool {
	if !c.U.Equal(&other.U) {
		return false
	}

	if !c.W.Equals(&other.W) {
		return false
	}

	if len(c.V) != len(other.V) {
		return false
	}

	for i := range c.V {
		if c.V[i] != other.V[i] {
			return false
		}
	}
	return true
}

type DecryptionShare struct {
	G1 *bls.G1Projective
}

func SetUp(t, p int) {

}