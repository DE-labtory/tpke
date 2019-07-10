package tpke

import (
	"github.com/DE-labtory/tpke/bls"
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

func TestPoly_evaluate(t *testing.T) {
	expectedFrRepr := &bls.FRRepr{5181237716180834938, 12933092709012868809, 7449062242929247980, 4519714088997883368}
	frRepr1 := &bls.FRRepr{18254824737299055921, 12301176899088639156, 11044415995378916883, 357667238319585097}
	frRepr2 := &bls.FRRepr{12824654784770937420, 5378575280977611710, 2705578970549845177, 4801150429553808887}
	frRepr3 := &bls.FRRepr{4520685442247980328, 10536932062350377723, 4028339353248801528, 1646571793378913296}
	poly := &Poly {
		[]*bls.FR{
			bls.FRReprToFR(frRepr1),
			bls.FRReprToFR(frRepr2),
			bls.FRReprToFR(frRepr3),
		},
	}

	result := poly.evaluate(*bls.FRReprToFR(bls.NewFRRepr(3)))
	expected := bls.FRReprToFR(expectedFrRepr)
	if !result.Equals(expected) {
		t.Errorf("results are not equal.")
	}
	// PASS
}

func TestPoly_commitment(t *testing.T) {
	frRepr1 := &bls.FRRepr{3430707088094777087, 2455690239785479458, 5507155159914335843, 7341630481516121204}
	frRepr2 := &bls.FRRepr{360679164676216945, 589008160366285188, 18428004055273428688, 2723678784642027464}
	frRepr3 := &bls.FRRepr{5511946094596868462, 16040801034001542498, 9453513069589497919, 2081802114026746926}

	poly := &Poly{
		coeff: []*bls.FR{
			bls.FRReprToFR(frRepr1),
			bls.FRReprToFR(frRepr2),
			bls.FRReprToFR(frRepr3),
		},
	}

	com := poly.commitment()
	result := com.evaluate(*bls.FRReprToFR(bls.NewFRRepr(3)))
	t.Logf("%v", com)
	t.Logf("%v", result)
}