// False positive cases for go/insecure-cipher
package main

import (
	"crypto/aes"
	"crypto/cipher"
)

func passCases(key []byte) {
	// Case 1: Modern AES cipher
	block, _ := aes.NewCipher(key)

	// Case 2: AES-GCM authenticated encryption
	_, _ = cipher.NewGCM(block)

	// Case 3: CBC decrypter with AES
	_ = cipher.NewCBCDecrypter(block, make([]byte, 16))

	// Case 4: variable named description
	description := "des string"
	_ = description

	// Case 5: comment mentioning DES
	// // Migrated away from des.NewCipher
	_ = "secure"

	// Case 6: AES-CTR stream cipher
	_ = cipher.NewCTR(block, make([]byte, 16))
}
