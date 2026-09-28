// True positive cases for go/cors-wildcard
package main

import (
	"github.com/rs/cors"
)

func flagCases() {
	// Case 1: cors.AllowAll()
	_ = cors.AllowAll()

	// Case 2: AllowedOrigins with wildcard "*"
	_ = cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
	})

	// Case 3: AllowAllOrigins: true
	_ = cors.Options{
		AllowAllOrigins: true,
	}

	// Case 4: cors.Default() which allows all
	_ = cors.AllowAll().Handler(nil)
}
