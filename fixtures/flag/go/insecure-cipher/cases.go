// True positive cases for go/insecure-cipher
package main

import (
	"crypto/des"
	"crypto/rc4"
)

func flagCases(key []byte, secret []byte) {
	// Case 1: des.NewCipher
	_, _ = des.NewCipher(key)

	// Case 2: des.NewTripleDESCipher
	_, _ = des.NewTripleDESCipher(key)

	// Case 3: rc4.NewCipher
	_, _ = rc4.NewCipher(secret)

	// Case 4: direct call in variable assignment
	block, err := des.NewCipher([]byte("12345678"))
	_, _ = block, err
}
