package tpke

import (
	"github.com/phoreproject/bls"
	"testing"
)

func TestPoly_AddAssign(t *testing.T) {
	fr1 := bls.FRReprToFR(bls.NewFRRepr(1))
	poly := &Poly {
		coeff: []*bls.FR {
			fr1.Copy(),
			fr1.Copy(),
			fr1.Copy(),
		},
	}
	poly2 := &Poly {
		coeff: []*bls.FR {
			fr1.Copy(),
			fr1.Copy(),
			fr1.Copy(),
			fr1.Copy(),
			fr1.Copy(),
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
