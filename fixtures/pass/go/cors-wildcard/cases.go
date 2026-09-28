// False positive cases for go/cors-wildcard
package main

import (
	"github.com/rs/cors"
)

func passCases() {
	// Case 1: Specific allowed domain
	_ = cors.New(cors.Options{
		AllowedOrigins: []string{"https://example.com"},
	})

	// Case 2: Subdomain specific allowlist
	_ = cors.New(cors.Options{
		AllowedOrigins: []string{"https://api.internal.net", "https://admin.internal.net"},
	})

	// Case 3: Wildcard in non-CORS context
	patterns := []string{"*"}
	_ = patterns

	// Case 4: AllowedMethods wildcard
	_ = cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
	})

	// Case 5: Custom validator function
	_ = cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://trusted.com"
		},
	})

	// Case 6: Comment mentioning cors.AllowAll
	// // Do not use cors.AllowAll()
	_ = cors.New(cors.Options{})
}
