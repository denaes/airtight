// True positive cases for go/ssrf-from-input
package main

import (
	"context"
	"io"
	"net/http"
)

type GinContext interface {
	Query(key string) string
	Param(key string) string
}

func flagCases(w http.ResponseWriter, r *http.Request, req *http.Request, c GinContext, body io.Reader, ctx context.Context) {
	// Case 1: http.Get with query param "url"
	http.Get(r.URL.Query().Get("url"))

	// Case 2: http.Post with form value "target"
	http.Post(r.FormValue("target"), "application/json", body)

	// Case 3: http.NewRequest with gin query "webhook"
	http.NewRequest("GET", c.Query("webhook"), nil)

	// Case 4: http.Get with req query param "endpoint"
	http.Get(req.URL.Query().Get("endpoint"))

	// Case 5: http.Head with query param "link"
	http.Head(r.URL.Query().Get("link"))

	// Case 6: http.NewRequestWithContext with gin param "dest"
	http.NewRequestWithContext(ctx, "POST", c.Param("dest"), body)
}
