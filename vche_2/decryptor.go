package vche_2

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

type Decryptor interface {
	InternalDecryptor() bfv.Decryptor
	DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext)
	Decrypt(ciphertext *Ciphertext, plaintext *Plaintext)
}

type decryptor struct {
	bfv.Decryptor
	params Parameters
	sk     *SecretKey
}

func NewDecryptor(params Parameters, sk *SecretKey) Decryptor {
	return &decryptor{bfv.NewDecryptor(params.Parameters, sk.SecretKey), params, sk}
}

func (dec *decryptor) InternalDecryptor() bfv.Decryptor {
	return dec.Decryptor
}

func (dec *decryptor) Decrypt(ciphertext *Ciphertext, plaintext *Plaintext) {
	plaintext.Plaintexts = make([]*bfv.Plaintext, len(ciphertext.Ciphertexts))
	for i := range ciphertext.Ciphertexts {
		plaintext.Plaintexts[i] = dec.Decryptor.DecryptNew(ciphertext.Ciphertexts[i])
	}
}

func (dec *decryptor) DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext) {
	plaintext = NewPlaintext(dec.params)
	dec.Decrypt(ciphertext, plaintext)
	return plaintext
}
