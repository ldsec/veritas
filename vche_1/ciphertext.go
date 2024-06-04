package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/utils"
)

type Ciphertext struct {
	*bfv.Ciphertext
	tags [][]byte
}

func (ciphertext Ciphertext) Tags() [][]byte {
	return ciphertext.tags
}

func (ciphertext Ciphertext) CopyNew() *Ciphertext {
	res := &Ciphertext{ciphertext.Ciphertext.CopyNew(), make([][]byte, len(ciphertext.tags))}
	copy(res.tags, ciphertext.tags)
	return res
}

func NewCiphertext(params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{bfv.NewCiphertext(params.Parameters, degree), make([][]byte, params.NSlots)}
}

func NewCiphertextRandom(prng utils.PRNG, params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{bfv.NewCiphertextRandom(prng, params.Parameters, degree), make([][]byte, params.NSlots)}
}
