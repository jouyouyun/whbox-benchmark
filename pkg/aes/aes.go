package aes

import (
	aes0 "crypto/aes"
	"crypto/cipher"
)

type Encryptor struct {
	key []byte

	cryptor cipher.Block
}

func Encrypt(key, clearText []byte) ([]byte, error) {
	c, err := aes0.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, 16)
	c.Encrypt(cipherText, clearText)
	return cipherText, nil
}

func Decrypt(key, cipherText []byte) ([]byte, error) {
	c, err := aes0.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText := make([]byte, 16)
	c.Decrypt(clearText, cipherText)
	return clearText, nil
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	cryptor, err := aes0.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Encryptor{
		key:     key,
		cryptor: cryptor,
	}, nil
}

func (enc *Encryptor) Encrypt(clearText []byte) []byte {
	cipherText := make([]byte, 16)
	enc.cryptor.Encrypt(cipherText, clearText)
	return cipherText
}

func (enc *Encryptor) Decrypt(cipherText []byte) []byte {
	clearText := make([]byte, 16)
	enc.cryptor.Decrypt(clearText, cipherText)
	return cipherText
}
