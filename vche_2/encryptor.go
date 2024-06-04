package vche_2

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

type Encryptor interface {
	Encrypt(plaintext *Plaintext, ciphertext *Ciphertext)
	EncryptNew(plaintext *Plaintext) *Ciphertext
}

type encryptor struct {
	bfv.Encryptor
	params Parameters
}

func NewEncryptor(params Parameters, key interface{}) Encryptor {
	switch key := key.(type) {
	case *SecretKey:
		return &encryptor{bfv.NewEncryptor(params.Parameters, key.SecretKey), params}
	case *PublicKey:
		return &encryptor{bfv.NewEncryptor(params.Parameters, key), params}
	default:
		panic("key must be either PublicKey or SecretKey")
	}
}

func (enc *encryptor) Encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {
	ciphertext.Ciphertexts = make([]*bfv.Ciphertext, len(plaintext.Plaintexts))
	for i := range plaintext.Plaintexts {
		ciphertext.Ciphertexts[i] = enc.Encryptor.EncryptNew(plaintext.Plaintexts[i])
	}
}

func (enc *encryptor) EncryptNew(plaintext *Plaintext) *Ciphertext {
	ciphertext := &Ciphertext{}
	enc.Encrypt(plaintext, ciphertext)
	return ciphertext
}
