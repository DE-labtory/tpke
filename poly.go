package tpke

import (
	"github.com/leesper/go_rng"
	"github.com/bls"
)

type Poly struct {
	coeff []*bls.FR
}

func randomPoly(degree int) *Poly {
	coeff := make([]*bls.FR, degree)
	rng := rng.NewUniformGenerator(int64(degree * 123123421))
	for i := range coeff {
		fr:= bls.NewFRRepr(uint64(rng.Int64()))
		coeff[i] = bls.FRReprToFR(fr)
	}
	return &Poly {
		coeff: coeff,
	}
}

func (p *Poly) evaluate(x bls.FR) *bls.FR {
	i := len(p.coeff) - 1
	result := p.coeff[i].Copy()
	for i >= 0 {
		if i != len(p.coeff) - 1 {
			result.MulAssign(&x)
			result.AddAssign(p.coeff[i])
		}
		i--
	}
	return result
}

func (p *Poly) AddAssign(op *Poly) {
	pLen := len(p.coeff)
	opLen := len(op.coeff)
	FRZero := bls.FRReprToFR(bls.NewFRRepr(0))
	for pLen < opLen {
		p.coeff = append(p.coeff, FRZero)
		pLen++
	}
	for i := range p.coeff {
		p.coeff[i].AddAssign(op.coeff[i])
	}
}

func (p *Poly) MulAssign(x bls.FR) {
	// TODO : check if op is zero
	for _, c := range p.coeff {
		c.MulAssign(&x)
	}
}

func (p *Poly) degree() int {
	return len(p.coeff)
}

func (p *Poly) commitment() *Commitment {
	g1One := bls.G1AffineOne
	coeff := make([]*bls.G1Projective, len(p.coeff))
	for i := range coeff {
		coeff[i] = g1One.MulFR(p.coeff[i].ToRepr())
	}
	return &Commitment {
		coeff: coeff,
	}
}

type Commitment struct {
	coeff []*bls.G1Projective
}

func (c *Commitment) Clone() *Commitment {
	coeff := make([]*bls.G1Projective, len(c.coeff))
	for i := range coeff {
		coeff[i] = c.coeff[i].Copy()
	}
	return &Commitment {
		coeff: coeff,
	}
}

func (c *Commitment) degree() int {
	return len(c.coeff) - 1
}

func (c *Commitment) evaluate(x bls.FR) *bls.G1Projective {
	if len(c.coeff) == 0 {
		return bls.G1ProjectiveZero
	}
	i := len(c.coeff) - 1
	result := c.coeff[i]
	for i >= 0 {
		if i != len(c.coeff) - 1{
			result = result.MulFR(x.ToRepr())
			result = result.Add(c.coeff[i])
		}
		i--
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