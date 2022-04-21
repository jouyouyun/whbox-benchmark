package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"path/filepath"
	"time"
	"whbox-bench/pkg/aes"
	"whbox-bench/pkg/whbox"
)

var (
	_action = flag.String("action", "", "available action: encrypt, decrypt, benchmark")
	_alg    = flag.String("alg", "", "the whbox algorithm")
	_dir    = flag.String("dir", "", "the dir of whbox key")
	_key    = flag.String("key", "", "the origin key, 128-bits")
	_block  = flag.String("block", "", "the data which encrypted or decrypted")
	_count  = flag.Int("count", 3, "the benchmark count")
)

func main() {
	flag.Parse()

	var (
		key        []byte
		block      []byte
		clearText  []byte
		cipherText []byte

		duration time.Duration
		start    time.Time

		err       error
		encryptor whbox.Encryptor
	)

	key, err = hex.DecodeString(*_key)
	if err != nil {
		goto failure
	}

	start = time.Now()
	err = whbox.GenerateKey(key, *_alg, *_dir)
	duration = time.Now().Sub(start)
	if err != nil {
		goto failure
	}
	fmt.Println("Generate key duration:", duration.String())

	block, err = hex.DecodeString(*_block)
	if err != nil {
		goto failure
	}

	encryptor, err = whbox.NewEncryptor(*_alg,
		filepath.Join(*_dir, "encryption.key"),
		filepath.Join(*_dir, "decryption.key"))
	if err != nil {
		goto failure
	}

	switch *_action {
	case "encrypt":
		start = time.Now()
		cipherText, err = encryptor.Encrypt(block)
		if err != nil {
			goto failure
		}
		duration = time.Now().Sub(start)
		fmt.Println("whbox encryption:", duration.String())
		fmt.Printf("\tKey: %x\n", key)
		fmt.Printf("\tBlock: %x\n", block)
		fmt.Printf("\tCipher: %x\n", cipherText)

		start = time.Now()
		cipherText, err = aes.Encrypt(key, block)
		duration = time.Now().Sub(start)
		fmt.Println("aes encryption:\t", duration.String())
		fmt.Printf("\tKey: %x\n", key)
		fmt.Printf("\tBlock: %x\n", block)
		fmt.Printf("\tCipher: %x\n", cipherText)
	case "decrypt":
		start = time.Now()
		clearText, err = encryptor.Decrypt(block)
		if err != nil {
			goto failure
		}
		duration = time.Now().Sub(start)
		fmt.Println("whbox decryption:\t", duration.String())
		fmt.Printf("\tKey: %x\n", key)
		fmt.Printf("\tBlock: %x\n", block)
		fmt.Printf("\tClear: %x\n", clearText)

		start = time.Now()
		clearText, err = aes.Decrypt(key, block)
		if err != nil {
			goto failure
		}
		duration = time.Now().Sub(start)
		fmt.Println("aes decryption:\t", duration.String())
		fmt.Printf("\tKey: %x\n", key)
		fmt.Printf("\tBlock: %x\n", block)
		fmt.Printf("\tClear: %x\n", clearText)
	case "benchmark":
		fmt.Printf("Benchmark: key(%x), block(%x)\n", key, block)
		fmt.Println("Encryption:")
		cipherText = encryptBenchmark(key, block, encryptor)
		fmt.Println("Decryption:")
		decryptBenchmark(key, cipherText, encryptor)
	default:
		fmt.Println("unknown action")
		return
	}

	return
failure:
	fmt.Println(err)
}

func encryptBenchmark(key, block []byte, encryptor whbox.Encryptor) []byte {
	var cipherText []byte
	var err error
	for i := 0; i < *_count; i++ {
		start := time.Now()
		cipherText, err = encryptor.Encrypt(block)
		duration := time.Now().Sub(start)
		if err != nil {
			fmt.Println("\t", err)
			continue
		}
		fmt.Printf("\t[%d]\n\t\t[WHBox] Duration: %s, \tCipher: %x\n", i, duration, cipherText)

		start = time.Now()
		cipherText, err = aes.Encrypt(key, block)
		duration = time.Now().Sub(start)
		if err != nil {
			fmt.Println("\t", err)
			continue
		}
		fmt.Printf("\t\t[AES] Duration: %s, \tCipher: %x\n", duration, cipherText)
	}
	return cipherText
}

func decryptBenchmark(key, block []byte, encryptor whbox.Encryptor) []byte {
	var clearText []byte
	var err error
	for i := 0; i < *_count; i++ {
		start := time.Now()
		clearText, err = encryptor.Decrypt(block)
		duration := time.Now().Sub(start)
		if err != nil {
			fmt.Println("\t", err)
			continue
		}
		fmt.Printf("\t[%d]\n\t\t[WHBox] Duration: %s, \tClear: %x\n", i, duration, clearText)

		start = time.Now()
		clearText, err = aes.Decrypt(key, block)
		duration = time.Now().Sub(start)
		if err != nil {
			fmt.Println("\t", err)
			continue
		}
		fmt.Printf("\t\t[AES] Duration: %s, \tClear: %x\n", duration, clearText)
	}
	return clearText
}
