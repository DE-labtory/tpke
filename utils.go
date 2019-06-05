package tpke

import (
	"github.com/DE-labtory/koa/crpyto"
	"github.com/phoreproject/bls"
	"github.com/tendermint/tendermint/crypto/xchacha20poly1305"
	"math/big"
)

func hashH(g1 bls.G1Projective, msg []byte) bls.G2Projective {
	k := crpyto.Keccak256(msg)
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
	result := make([]byte, 32)
	nonce := [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	xchacha20poly1305.HChaCha20(&out, &nonce, &digest32)
	idx := 0
	for i := range msg {
		result[i] = msg[i] ^ out[idx % 32]
		idx++
	}

	return result, nil
}

func Interpolate(t int, items []*bls.G1Projective) *bls.G1Projective {
	fqs := make([]bls.FQRepr, t + 1)
	i := 0
	for i < t + 1 {
		fq, _ := bls.FQReprFromBigInt(big.NewInt(int64(i + 1)))
		fqs[i] = fq
		i++
	}
	if t == 0 {
		return items[0]
	}

	tmp := bls.FQOne
	x_prod := make([]bls.FQRepr, t)
	x_prod[0] = tmp.ToRepr()
	i = 1
	for i <= t {
		tmp.MulAssign(bls.FQReprToFQ(fqs[i - 1]))
		x_prod[i] = tmp.ToRepr()
		i++
	}

	tmp = bls.FQOne
	i = 1
	for i <= len(items) {
		tmp.MulAssign(bls.FQReprToFQ(fqs[i - 1]))

		x_prod_fq := bls.FQReprToFQ(x_prod[i])
		x_prod_fq.MulAssign(tmp)
		x_prod[i] = x_prod_fq.ToRepr()
		i++
	}

	result := bls.G1ProjectiveZero
	i = 0
	for i < len(x_prod) {
		denom := bls.FQOne
		j := 0
		x := fqs[i]
		for j < len(fqs) {
			x0 := fqs[j]
			if !x.Equals(x0) {
				diff := x0.Copy()
				diffFQ := bls.FQReprToFQ(diff)
				diffFQ.SubAssign(bls.FQReprToFQ(x))
				denom.MulAssign(diffFQ)
			}
			j++
		}
		x_prod_fq := bls.FQReprToFQ(x_prod[i])
		inversedDenom, _ := denom.Inverse()
		x_prod_fq.MulAssign(inversedDenom)
		result.Add(items[i].ToAffine().Mul(x_prod_fq.ToRepr()))
		i++
	}
	return result
}
