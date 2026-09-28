package main

import (
	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	Username string
	jwt.RegisteredClaims
}

func flagCases(tokenStr string, claims *CustomClaims, keyFunc jwt.Keyfunc) {
	// Case 1: Package variable or direct reference to UnsafeAllowNoneSignatureType
	_ = jwt.UnsafeAllowNoneSignatureType

	// Case 2: jwt.Parse with UnsafeAllowNoneSignatureType
	_, _ = jwt.Parse(tokenStr, keyFunc, jwt.UnsafeAllowNoneSignatureType)

	// Case 3: jwt.ParseWithClaims with UnsafeAllowNoneSignatureType
	_, _ = jwt.ParseWithClaims(tokenStr, claims, keyFunc, jwt.UnsafeAllowNoneSignatureType)

	// Case 4: jwt.Parse directly passing jwt.None
	_, _ = jwt.Parse(tokenStr, jwt.None)

	// Case 5: jwt.ParseWithClaims directly passing jwt.None
	_, _ = jwt.ParseWithClaims(tokenStr, claims, jwt.None)
}
