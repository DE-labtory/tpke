package tpke

import (
	"github.com/phoreproject/bls"
	"testing"
)

func TestPoly_AddAssign(t *testing.T) {
	poly := &Poly {
		coeff: []bls.FQ {
			bls.FQOne,
			bls.FQOne,
			bls.FQOne,
		},
	}
	poly2 := &Poly {
		coeff: []bls.FQ {
			bls.FQOne,
			bls.FQOne,
			bls.FQOne,
			bls.FQOne,
			bls.FQOne,
		},
	}
	t.Logf("FQZero : %v", bls.FQZero)
	t.Logf("FQOne : %v", bls.FQOne)
	a := bls.FQOne
	a.AddAssign(bls.FQOne)
	t.Logf("FQOne + FQZero : %v", a)
	t.Logf("%v", poly.coeff)
	poly.AddAssign(poly2)
	t.Logf("%v", poly.coeff)
}
