package chow

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"path/filepath"

	whchow "github.com/OpenWhiteBox/AES/constructions/chow"
	whcommon "github.com/OpenWhiteBox/AES/constructions/common"
)

type Encryptor struct {
	encKey string
	decKey string

	constrEnc *whchow.Construction
	constrDec *whchow.Construction
}

func GenerateKey(key []byte, dir string) error {
	if len(key) != 16 {
		return fmt.Errorf("key must be 128 bits")
	}

	seed := make([]byte, 16)
	_, err := rand.Read(seed)
	if err != nil {
		return err
	}

	constr, _, _ := whchow.GenerateEncryptionKeys(key, seed, whcommon.SameMasks(whcommon.IdentityMask))
	//whcommon.IndependentMasks{Input: whcommon.RandomMask, Output: whcommon.RandomMask})
	err = ioutil.WriteFile(filepath.Join(dir, "encryption.key"), constr.Serialize(), 0600)
	if err != nil {
		return err
	}

	constr, _, _ = whchow.GenerateDecryptionKeys(key, seed, whcommon.SameMasks(whcommon.IdentityMask))
	//whcommon.IndependentMasks{Input: whcommon.RandomMask, Output: whcommon.RandomMask})
	return ioutil.WriteFile(filepath.Join(dir, "decryption.key"), constr.Serialize(), 0600)
}

func NewEncryptor(encKey, decKey string) (*Encryptor, error) {
	data, err := ioutil.ReadFile(encKey)
	if err != nil {
		return nil, err
	}
	constrEnc, err := whchow.Parse(data)
	if err != nil {
		return nil, err
	}

	data, err = ioutil.ReadFile(decKey)
	if err != nil {
		return nil, err
	}
	constrDec, err := whchow.Parse(data)
	if err != nil {
		return nil, err
	}
	return &Encryptor{
		encKey:    encKey,
		decKey:    decKey,
		constrEnc: &constrEnc,
		constrDec: &constrDec,
	}, nil
}

func (enc *Encryptor) Encrypt(clearText []byte) ([]byte, error) {
	cipherText := make([]byte, 16)
	enc.constrEnc.Encrypt(cipherText, clearText)
	return cipherText, nil
}

func (enc *Encryptor) Decrypt(cipherText []byte) ([]byte, error) {
	clearText := make([]byte, 16)
	enc.constrDec.Decrypt(clearText, cipherText)
	return clearText, nil
}
