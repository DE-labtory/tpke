package tpke

import (
	"fmt"
	"github.com/DE-labtory/tpke/bls"
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

func NewCipherTextFromBytes(bytes []byte) *CipherText {
	uSerial := bytes[0:96]
	wSerial := bytes[96:288]
	vSerial := bytes[288:]

	var uX [48]byte
	var uY [48]byte
	for i:=0; i<48; i++ {
		uX[i] = uSerial[i]
	}
	for i:=0; i<48; i++ {
		uY[i] = uSerial[i + 48]
	}
	uXfq := bls.FQReprToFQ(bls.FQReprFromBytes(uX))
	uYfq := bls.FQReprToFQ(bls.FQReprFromBytes(uY))
	u := bls.NewG1Affine(uXfq, uYfq).ToProjective()

	var wXc0 [48]byte
	var wXc1 [48]byte
	var wYc0 [48]byte
	var wYc1 [48]byte
	for i:=0; i<48; i++ {
		wXc0[i] = wSerial[i]
	}
	for i:=0; i<48; i++ {
		wXc1[i] = wSerial[i+48]
	}
	for i:=0; i<48; i++ {
		wYc0[i] = wSerial[i+96]
	}
	for i:=0; i<48; i++ {
		wYc1[i] = wSerial[i+144]
	}
	wXc0fq := bls.FQReprToFQ(bls.FQReprFromBytes(wXc0))
	wXc1fq := bls.FQReprToFQ(bls.FQReprFromBytes(wXc1))
	wYc0fq := bls.FQReprToFQ(bls.FQReprFromBytes(wYc0))
	wYc1fq := bls.FQReprToFQ(bls.FQReprFromBytes(wYc1))

	wXfq2 := bls.NewFQ2(wXc0fq, wXc1fq)
	wYfq2 := bls.NewFQ2(wYc0fq, wYc1fq)

	w := bls.NewG2Affine(wXfq2, wYfq2).ToProjective()

	return &CipherText {
		U: *u,
		V: vSerial,
		W: *w,
	}
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

func (c *CipherText) String() string {
	return fmt.Sprintf("U : %v, V : %v, W : %v", c.U, c.V, c.W)
}

type DecryptionShare struct {
	G1 *bls.G1Projective
}

func (ds *DecryptionShare) Serialize() [96]byte {
	return ds.G1.ToAffine().SerializeBytes()
}

func NewDecryptionShareFromBytes(bytes [96]byte) *DecryptionShare {
	var x, y [48]byte
	for i :=0; i<48; i++ {
		x[i] = bytes[i]
		y[i] = bytes[i+48]
	}
	fqX := bls.FQReprToFQ(bls.FQReprFromBytes(x))
	fqY := bls.FQReprToFQ(bls.FQReprFromBytes(y))

	g1 := bls.NewG1Affine(fqX, fqY).ToProjective()
	return &DecryptionShare{
		G1: g1,
	}
}