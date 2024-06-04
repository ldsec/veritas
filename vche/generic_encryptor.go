package vche

type GenericEncryptor interface {
	Encrypt(plaintext interface{}, ciphertext interface{})
	EncryptNew(plaintext interface{}) interface{}
}
