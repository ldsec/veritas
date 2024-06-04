package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

type Decryptor interface {
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

func (dec *decryptor) Decrypt(ciphertext *Ciphertext, plaintext *Plaintext) {
	dec.Decryptor.Decrypt(ciphertext.Ciphertext, plaintext.Plaintext)
	copy(plaintext.tags, ciphertext.tags)
}

func (dec *decryptor) DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext) {
	plaintext = NewPlaintext(dec.params)
	dec.Decrypt(ciphertext, plaintext)
	return plaintext
}
