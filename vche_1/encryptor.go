package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

type Encryptor interface {
	Encrypt(plaintext *Plaintext, ciphertext *Ciphertext)
	EncryptNew(plaintext *Plaintext) *Ciphertext
}

type encryptor struct {
	bfv.Encryptor
}

func NewEncryptor(params Parameters, key interface{}) Encryptor {
	switch key := key.(type) {
	case *SecretKey:
		return &encryptor{bfv.NewEncryptor(params.Parameters, key.SecretKey)}
	case *PublicKey:
		return &encryptor{bfv.NewEncryptor(params.Parameters, key.PublicKey)}
	default:
		panic("key must be either PublicKey or SecretKey")
	}
}

func (enc *encryptor) Encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {
	enc.Encryptor.Encrypt(plaintext.Plaintext, ciphertext.Ciphertext)
	ciphertext.tags = plaintext.tags
}

func (enc *encryptor) EncryptNew(plaintext *Plaintext) *Ciphertext {
	return &Ciphertext{enc.Encryptor.EncryptNew(plaintext.Plaintext), plaintext.tags}
}
