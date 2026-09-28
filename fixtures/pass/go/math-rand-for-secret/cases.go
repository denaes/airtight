// False positive / near-miss cases for go/math-rand-for-secret
package main

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
)

func passCases(token []byte, cards []int) {
	// Case 1: crypto/rand.Read(token) - safe cryptographic generator
	_, _ = crypto/rand.Read(token)

	// Case 2: Non-sensitive variable with rand.Intn
	dice := mrand.Intn(6)

	// Case 3: Non-sensitive index with rand.Int
	index := mrand.Int()

	// Case 4: Non-sensitive jitter with rand.Float64
	jitter := mrand.Float64()

	// Case 5: Non-sensitive sample rate with rand.Uint64
	sampleRate := mrand.Uint64()

	// Case 6: Commented out pseudo-random token generation
	// token := mrand.Int()

	// Case 7: crypto/rand inline mention with math/rand read
	tokenBuf := make([]byte, 16)
	_, _ = mrand.Read(tokenBuf) // crypto/rand replacement pending

	// Case 8: Non-sensitive shuffle logic
	_ = cards[mrand.Intn(len(cards))]

	_ = dice
	_ = index
	_ = jitter
	_ = sampleRate
	_ = fmt.Sprintf("%d", index)
}
