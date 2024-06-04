package vche_2

import (
	"veritas/vche/vche"
)

type genericDecryptor struct {
	Decryptor
}

func NewGenericDecryptor(params Parameters, sk *SecretKey) vche.GenericDecryptor {
	return &genericDecryptor{NewDecryptor(params, sk)}
}

func (dec *genericDecryptor) Decrypt(ciphertext interface{}, plaintext interface{}) {
	dec.Decryptor.Decrypt(ctxt(ciphertext), ptxt(plaintext))
}

func (dec *genericDecryptor) DecryptNew(ciphertext interface{}) (plaintext interface{}) {
	return dec.Decryptor.DecryptNew(ctxt(ciphertext))
}
