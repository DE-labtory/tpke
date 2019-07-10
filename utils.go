package tpke

import (
	"encoding/binary"
	"errors"
	"github.com/DE-labtory/tpke/bls"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

func hashG1G2(g1 bls.G1Projective, msg []byte) *bls.G2Affine {

	k := make([]byte, 0)

	compress := bls.CompressG1(g1.ToAffine())
	for _, b := range compress {
		k = append(k, b)
	}

	for _, b := range msg {
		k = append(k, b)
	}

	return bls.HashG2(k)
}

func HashG2(msg []byte) *bls.G2Projective {
	/*//bls.HashG1
	hasher0 := sha3.New256()
	//hasher0.Write([]byte("G2_0"))
	hasher0.Write(msg)
	//hasher1 := sha3.New256()
	//hasher1.Write([]byte("G2_1"))
	//hasher1.Write(msg)


	t0 := bls.HashFQ2(hasher0)
	t0Affine := bls.SWEncodeG2(t0)
	//t1 := bls.HashFQ2(hasher1)
	//t1Affine := bls.SWEncodeG2(t1)
	res := t0Affine.ScaleByCofactor()
	//res = res.AddAffine(t1Affine)*/
	domainBytes := [8]byte{}
	binary.BigEndian.PutUint64(domainBytes[:], 0)

	hasher0, _ := blake2b.New(64, nil)
	hasher0.Write(domainBytes[:])
	hasher0.Write([]byte("G2_0"))
	hasher0.Write(msg)
	hasher1, _ := blake2b.New(64, nil)
	hasher1.Write(domainBytes[:])
	hasher1.Write([]byte("G2_1"))
	hasher1.Write(msg)

	t0 := bls.HashFQ2(hasher0)
	t0Affine := bls.SWEncodeG2(t0)
	t1 := bls.HashFQ2(hasher1)
	t1Affine := bls.SWEncodeG2(t1)

	res := t0Affine.ToProjective()
	res = res.AddAffine(t1Affine)
	return res.ToAffine().ScaleByCofactor()
}

//func xorHash(g1 bls.G1Projective, msg [32]byte) ([]byte, error) {
//
//	for i, _ := range msg {
//
//	}
//}

func xorHash(g1 bls.G1Projective, msg []byte) []byte {
	slice := bls.CompressG1(g1.ToAffine())
	hash := sha3.New256()
	hash.Write(slice[:])
	hashedG1 := hash.Sum(nil)
	output := make([]byte, len(msg))
	for i := range output {
		output[i] = msg[i] ^ hashedG1[i % 32]
	}
	return output
}

type Sample struct {
	fr *bls.FR
	g1 *bls.G1Projective
}

func Interpolate(t int, inputs []*Sample) (*bls.G1Projective, error) {
	i := 0

	if len(inputs) <= t {
		return nil, errors.New("Not enough share")
	}

	if t == 0 {
		return inputs[0].g1.Copy(), nil
	}

	samples := make([]*Sample, 0)
	for i < t+1 {
		samples = append(samples, &Sample{
			fr: inputs[i].fr.Copy(),
			g1: inputs[i].g1.Copy(),
		})
		i++
	}

	tmp := bls.FRReprToFR(bls.NewFRRepr(1))
	//x_prod := make([]*bls.FR, t + 1)
	x_prod := make([]*bls.FR, 0)
	x_prod = append(x_prod, tmp.Copy())
	i = 1
	for i <= t {
		tmp.MulAssign(samples[i - 1].fr.Copy())
		//x_prod[i] = tmp.Copy()
		x_prod = append(x_prod, tmp.Copy())
		i++
	}

	tmp = bls.FRReprToFR(bls.NewFRRepr(1))
	i = len(samples) - 2
	j := len(samples) - 1
	for i >= 0 {
		tmp.MulAssign(samples[j].fr.Copy())
		x_prod[i].MulAssign(tmp.Copy())
		i--
		j--
	}

	result := bls.G1ProjectiveZero
	i = 0
	for i < len(x_prod) {
		denom := bls.FRReprToFR(bls.NewFRRepr(1))
		j := 0
		x := samples[i].fr.Copy()
		for j < len(samples) {
			x0 := samples[j].fr
			if !x.Equals(x0) {
				diff := x0.Copy()
				diff.SubAssign(x.Copy())
				denom.MulAssign(diff.Copy())
			}
			j++
		}
		l0 := x_prod[i].Copy()
		inv := denom.Inverse()
		l0.MulAssign(inv)
		adder := samples[i].g1.ToAffine().MulFR(l0.ToRepr())
		result = result.Add(adder)
		i++
	}
	return result, nil
}
