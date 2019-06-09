package tpke

import (
	"github.com/DE-labtory/koa/crpyto"
	"github.com/phoreproject/bls"
	"github.com/tendermint/tendermint/crypto/xchacha20poly1305"
)

func hashG1G2(g1 bls.G1Projective, msg []byte) bls.G2Projective {
	k := msg
	if len(msg) > 64 {
		k = crpyto.Keccak256(msg)
	}
	compress := bls.CompressG1(g1.ToAffine())
	for _, b := range compress {
		k = append(k, b)
	}
	return *bls.HashG2(k, 0)
}

func xorHash(g1 bls.G1Projective, msg []byte) ([]byte, error) {
	var slice []byte
	for _, b := range bls.CompressG1(g1.ToAffine()) {
		slice = append(slice, b)
	}

	var digest32 [32]byte
	digest := crpyto.Keccak256(slice)

	for i := range digest32 {
		digest32[i] = digest[i]
	}

	var out [32]byte
	result := make([]byte, len(msg))
	nonce := [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	xchacha20poly1305.HChaCha20(&out, &nonce, &digest32)
	idx := 0
	for i := range msg {
		result[i] = msg[i] ^ out[idx % 32]
		idx++
	}

	return result, nil
}

type Sample struct {
	fr *bls.FR
	g1 *bls.G1Projective
}

func Interpolate(t int, samples []*Sample) (*bls.G1Projective, error) {
	i := 0

	if t == 0 {
		return samples[0].g1, nil
	}

	//for i < t + 1 {
	//	samples[i].fr = bls.FRReprToFR(bls.NewFRRepr(uint64(i + 1)))
	//	samples[i].g1 = items[i]
	//	i++
	//}

	tmp := bls.FRReprToFR(bls.NewFRRepr(1))
	x_prod := make([]*bls.FR, t + 1)
	x_prod[0] = tmp.Copy()
	i = 1
	for i <= t {
		tmp.MulAssign(samples[i - 1].fr.Copy())
		x_prod[i] = tmp.Copy()
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
		inv := denom.Copy().Inverse()
		l0.MulAssign(inv)
		adder := samples[i].g1.ToAffine().MulFR(l0.ToRepr())
		result = result.Add(adder)
		i++
	}
	return result, nil
}
