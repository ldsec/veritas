package bfv_generic

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
)

type encryptor struct {
	bfv.Encryptor
}

var _ vche.GenericEncryptor = encryptor{}

func NewGenericEncryptor(params bfv.Parameters, key interface{}) vche.GenericEncryptor {
	return &encryptor{bfv.NewEncryptor(params, key)}
}

func (e encryptor) Encrypt(plaintext interface{}, ciphertext interface{}) {
	e.Encryptor.Encrypt(ptxt(plaintext), ctxt(ciphertext))
}

func (e encryptor) EncryptNew(plaintext interface{}) interface{} {
	return e.Encryptor.EncryptNew(ptxt(plaintext))
}
