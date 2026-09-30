// False positive / near-miss cases for go/ssrf-from-input
package main

import (
	"context"
	"io"
	"net/http"
)

type CustomClient struct{}

func (c *CustomClient) Get(url string) (*http.Response, error) {
	return nil, nil
}

func passCases(r *http.Request, b io.Reader, ctx context.Context) {
	// Case 1: Hardcoded static GET request
	http.Get("https://api.github.com/status")

	// Case 2: Hardcoded static POST request
	http.Post("https://example.com/api", "application/json", b)

	// Case 3: Vulnerable pattern inside a comment should not match
	// http.Get(r.URL.Query().Get("url"))

	// Case 4: Target URL passed through validation helper before request
	target := validateURL(r.URL.Query().Get("url"))
	http.Get(target)

	// Case 5: Query parameter read for non-HTTP operation
	query := r.URL.Query().Get("url")
	_ = query

	// Case 6: FormValue read with non-target parameter name
	http.Get(r.FormValue("username"))

	// Case 7: Static internal health check request
	http.NewRequest("GET", "http://localhost:8080/health", nil)

	// Case 8: Custom client wrapper method (not http standard library call)
	var myClient CustomClient
	myClient.Get(r.URL.Query().Get("url"))
}

func validateURL(raw string) string {
	return "https://example.com/safe"
}
