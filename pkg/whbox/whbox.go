package whbox

import (
	"fmt"
	"whbox-bench/pkg/whbox/chow"
	"whbox-bench/pkg/whbox/xiao"
)

type Encryptor interface {
	Encrypt(clearText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
}

const (
	AlgTypeChow = "chow"
	AlgTypeXiao = "xiao"
)

// key and data range: [0-9a-f]+
func GenerateKey(key []byte, ty, dir string) error {
	switch ty {
	case AlgTypeChow:
		return chow.GenerateKey(key, dir)
	case AlgTypeXiao:
		return xiao.GenerateKey(key, dir)
	}

	return fmt.Errorf("unknown algorithm type: %s", ty)
}

func NewEncryptor(ty, encKey, decKey string) (Encryptor, error) {
	switch ty {
	case AlgTypeChow:
		return chow.NewEncryptor(encKey, decKey)
	case AlgTypeXiao:
		return xiao.NewEncryptor(encKey, decKey)
	}

	return nil, fmt.Errorf("unknown algorithm type: %s", ty)
}
