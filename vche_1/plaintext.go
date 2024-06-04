package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
)

type Plaintext struct {
	*bfv.Plaintext
	tags [][]byte
}
type PlaintextMul struct {
	*bfv.PlaintextMul
	tags [][]byte
}

type TaggedPoly struct {
	*ring.Poly
	tags [][]byte
}

func (plaintext Plaintext) Tags() [][]byte {
	return plaintext.tags
}

func (plaintext PlaintextMul) Tags() [][]byte {
	return plaintext.tags
}

func NewPlaintext(params Parameters) *Plaintext {
	return &Plaintext{bfv.NewPlaintext(params.Parameters), make([][]byte, params.NSlots)}
}

func NewPlaintextMul(params Parameters) *PlaintextMul {
	return &PlaintextMul{bfv.NewPlaintextMul(params.Parameters), make([][]byte, params.NSlots)}
}

func (plaintext *Plaintext) Copy(other *Plaintext) {
	if other != nil && other.Value != nil {
		plaintext.Plaintext.Plaintext.Copy(other.Plaintext.Plaintext)
		plaintext.tags = other.tags
	}
}

func (plaintext *PlaintextMul) Copy(other *PlaintextMul) {
	if other != nil && other.Value != nil {
		plaintext.PlaintextMul.Plaintext.Copy(other.PlaintextMul.Plaintext)
		plaintext.tags = other.tags
	}
}

func NewTaggedPoly(params Parameters) *TaggedPoly {
	return &TaggedPoly{params.RingT().NewPoly(), make([][]byte, params.NSlots)}
}
