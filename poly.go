package tpke

import (
	"github.com/leesper/go_rng"
	"github.com/phoreproject/bls"
)

type Poly struct {
	coeff []bls.FQ
}

func randomPoly(degree int) *Poly {
	coeff := make([]bls.FQ, degree + 1)
	rng := rng.NewUniformGenerator(123123421)
	for i := range coeff {
		fq:= bls.NewFQRepr(uint64(rng.Int64()))
		coeff[i] = bls.FQReprToFQ(fq)
	}
	return &Poly {
		coeff: coeff,
	}
}

func (p *Poly) evaluate(x bls.FQ) bls.FQ {
	result := p.coeff[0]
	for i, c := range p.coeff {
		if i > 0 {
			result.MulAssign(x)
			result.AddAssign(c)
		}
	}
	return result
}

func (p *Poly) AddAssign(op *Poly) {
	pLen := len(p.coeff)
	opLen := len(op.coeff)
	for pLen < opLen {
		p.coeff = append(p.coeff, bls.FQZero)
		pLen++
	}
	for i := range p.coeff {
		p.coeff[i].AddAssign(op.coeff[i])
	}
}

func (p *Poly) MulAssign(x bls.FQ) {
	// TODO : check if op is zero
	for _, c := range p.coeff {
		c.MulAssign(x)
	}
}

func (p *Poly) degree() int {
	return len(p.coeff)
}

func (p *Poly) commitment() *Commitment {
	g1One := bls.G1AffineOne
	coeff := make([]*bls.G1Projective, len(p.coeff))
	for i := range coeff {
		coeff[i] = g1One.Mul(p.coeff[i].ToRepr())
	}
	return &Commitment {
		coeff: coeff,
	}
}

type Commitment struct {
	coeff []*bls.G1Projective
}

func (c *Commitment) degree() int {
	return len(c.coeff) - 1
}

func (c *Commitment) evaluate(x bls.FQ) *bls.G1Projective {
	result := c.coeff[0]
	for i := range c.coeff {
		if i > 0 {
			result.Mul(x.ToRepr())
			result.Add(c.coeff[i])
		}
	}
	return result
}

func (c *Commitment) AddAssign(op *Commitment) {
	pLen := len(c.coeff)
	opLen := len(op.coeff)
	for pLen < opLen {
		c.coeff = append(c.coeff, bls.G1ProjectiveZero)
		pLen++
	}
	for i := range c.coeff {
		c.coeff[i].Add(op.coeff[i])
	}
}

func (c *Commitment) MulAssign() {

}