package tpke

import (
	"github.com/DE-labtory/koa/crpyto"
	"github.com/phoreproject/bls"
	"github.com/tendermint/tendermint/crypto/xchacha20poly1305"
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

func Interpolate() {

}
