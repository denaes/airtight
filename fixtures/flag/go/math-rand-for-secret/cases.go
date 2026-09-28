// True positive cases for go/math-rand-for-secret
package main

import (
	"fmt"
	"math/rand"
)

func flagCases(b []byte, secretBytes []byte, authToken []byte) {
	// Case 1: token generated using math/rand Int
	token := rand.Int()

	// Case 2: apiKey formatted with math/rand Uint64
	var apiKey string
	apiKey = fmt.Sprintf("%d", rand.Uint64())

	// Case 3: session initialized using math/rand Read
	session := rand.Read(b)

	// Case 4: password generated with math/rand Intn
	password := rand.Intn(100)

	// Case 5: nonce assigned from rand.Float64
	nonce := rand.Float64()

	// Case 6: salt assigned from rand.Int
	var salt int
	salt = rand.Int()

	// Case 7: rand.Read into secret buffer
	_, _ = rand.Read(secretBytes)

	// Case 8: rand.Read into auth token buffer
	_, _ = rand.Read(authToken)

	_ = token
	_ = apiKey
	_ = session
	_ = password
	_ = nonce
	_ = salt
}
