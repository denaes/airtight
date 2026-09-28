package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	Username string
	jwt.RegisteredClaims
}

// Near-miss 1: Comment mentioning UnsafeAllowNoneSignatureType must not trigger
// UnsafeAllowNoneSignatureType is dangerous and should never be used in production.

// Near-miss 2: Comment mentioning jwt.Parse with jwt.None must not trigger
// jwt.Parse(token, jwt.None) is vulnerable to unauthenticated bypass.

// Near-miss 3: Standard HMAC validation with jwt.Parse
func parseHMAC(tokenStr string, hmacSecret []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return hmacSecret, nil
	})
}

// Near-miss 4: Standard RSA validation with jwt.ParseWithClaims
func parseRSA(tokenStr string, claims *CustomClaims, rsaKey *rsa.PublicKey) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaKey, nil
	})
}

// Near-miss 5: Explicitly checking against SigningMethodNone
func checkSigningMethod(token *jwt.Token, secret []byte) (interface{}, error) {
	if token.Method == jwt.SigningMethodNone {
		return nil, errors.New("none algorithm not permitted")
	}
	return secret, nil
}

// Near-miss 6: Secure parser with WithValidMethods
func parseWithValidMethods(tokenStr string, claims *CustomClaims, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "RS256"}))
	return parser.ParseWithClaims(tokenStr, claims, keyFunc)
}
