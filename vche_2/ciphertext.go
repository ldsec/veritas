package vche_2

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/utils"
)

// Ciphertext wraps a vector of HE ciphertexts
type Ciphertext struct {
	Ciphertexts []*bfv.Ciphertext
}

func (c Ciphertext) Operands() []bfv.Operand {
	operands := make([]bfv.Operand, len(c.Ciphertexts))
	for i, ptxt := range c.Ciphertexts {
		operands[i] = ptxt
	}
	return operands
}

func (c Ciphertext) Len() int {
	return len(c.Ciphertexts)
}

func (c Ciphertext) BfvDegree() int {
	deg := 0
	for _, ctxt := range c.Ciphertexts {
		deg = utils.MaxInt(deg, ctxt.Degree())
	}
	return deg
}

func (c *Ciphertext) CopyNew() *Ciphertext {
	copiedCtxts := make([]*bfv.Ciphertext, len(c.Ciphertexts))
	for i := range copiedCtxts {
		copiedCtxts[i] = c.Ciphertexts[i].CopyNew()
	}
	return &Ciphertext{copiedCtxts}
}

func NewCiphertext(params Parameters, degree int) (ciphertext *Ciphertext) {
	ciphertexts := make([]*bfv.Ciphertext, 2)
	for i := range ciphertexts {
		ciphertexts[i] = bfv.NewCiphertext(params.Parameters, degree)
	}
	return &Ciphertext{ciphertexts}
}

func NewCiphertextRandom(prng utils.PRNG, params Parameters, degree int) (ciphertext *Ciphertext) {
	ciphertexts := make([]*bfv.Ciphertext, 2)
	for i := range ciphertexts {
		ciphertexts[i] = bfv.NewCiphertextRandom(prng, params.Parameters, degree)
	}
	return &Ciphertext{ciphertexts}
}
