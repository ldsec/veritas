package vche_2

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
)

type Plaintext struct {
	Plaintexts []*bfv.Plaintext
}

type PlaintextMul struct {
	Plaintexts []*bfv.PlaintextMul
}

func (p Plaintext) Operands() []bfv.Operand {
	operands := make([]bfv.Operand, len(p.Plaintexts))
	for i, ctxt := range p.Plaintexts {
		operands[i] = ctxt
	}
	return operands
}

func (p Plaintext) Len() int {
	return len(p.Plaintexts)
}

func (p Plaintext) BfvDegree() int {
	deg := 0
	for _, ptxt := range p.Plaintexts {
		deg = utils.MaxInt(deg, ptxt.Degree())
	}
	return deg
}

func (p PlaintextMul) Operands() []bfv.Operand {
	operands := make([]bfv.Operand, len(p.Plaintexts))
	for i, ctxt := range p.Plaintexts {
		operands[i] = ctxt
	}
	return operands
}

func (p PlaintextMul) Len() int {
	return len(p.Plaintexts)
}

func (p PlaintextMul) BfvDegree() int {
	deg := 0
	for _, ptxt := range p.Plaintexts {
		deg = utils.MaxInt(deg, ptxt.Degree())
	}
	return deg
}

func NewPlaintext(params Parameters) *Plaintext {
	plaintexts := make([]*bfv.Plaintext, 2)
	for i := range plaintexts {
		plaintexts[i] = bfv.NewPlaintext(params.Parameters)
	}
	return &Plaintext{plaintexts}
}

func NewPlaintextMul(params Parameters) *PlaintextMul {
	plaintexts := make([]*bfv.PlaintextMul, 2)
	for i := range plaintexts {
		plaintexts[i] = bfv.NewPlaintextMul(params.Parameters)
	}
	return &PlaintextMul{plaintexts}
}

type Poly struct {
	*ring.Poly
	Shift *ring.Poly
}

func NewPoly(params Parameters) *Poly {
	return &Poly{params.RingT().NewPoly(), params.RingT().NewPoly()}
}
