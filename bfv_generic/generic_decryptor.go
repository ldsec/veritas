package bfv_generic

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
)

type decryptor struct {
	bfv.Decryptor
}

var _ vche.GenericDecryptor = decryptor{}

func NewGenericDecryptor(params bfv.Parameters, sk *rlwe.SecretKey) vche.GenericDecryptor {
	return decryptor{bfv.NewDecryptor(params, sk)}
}

func (d decryptor) Decrypt(ciphertext interface{}, plaintext interface{}) {
	d.Decryptor.Decrypt(ctxt(ciphertext), ptxt(plaintext))
}

func (d decryptor) DecryptNew(ciphertext interface{}) (plaintext interface{}) {
	return d.Decryptor.DecryptNew(ctxt(ciphertext))
}
