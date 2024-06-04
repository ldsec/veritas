package vche

type GenericDecryptor interface {
	DecryptNew(ciphertext interface{}) (plaintext interface{})
	Decrypt(ciphertext interface{}, plaintext interface{})
}
