package vche_2

import (
	"veritas/vche/vche"
)

type genericEncryptor struct {
	Encryptor
}

func NewGenericEncryptor(params Parameters, key interface{}) vche.GenericEncryptor {
	return &genericEncryptor{NewEncryptor(params, key)}
}

func (enc *genericEncryptor) Encrypt(plaintext interface{}, ciphertext interface{}) {
	enc.Encryptor.Encrypt(ptxt(plaintext), ctxt(ciphertext))
}

func (enc *genericEncryptor) EncryptNew(plaintext interface{}) interface{} {
	return enc.Encryptor.EncryptNew(ptxt(plaintext))
}
