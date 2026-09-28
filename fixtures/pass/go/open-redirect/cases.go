// False positive cases for go/open-redirect
package main

import (
	"net/http"
)

func passCases(w http.ResponseWriter, r *http.Request) {
	// Case 1: Hardcoded relative redirect
	http.Redirect(w, r, "/login", http.StatusFound)

	// Case 2: Hardcoded dashboard route
	http.Redirect(w, r, "/dashboard/home", http.StatusSeeOther)

	// Case 3: Sanitized target URL
	target := sanitizeURL(r.URL.Query().Get("url"))
	http.Redirect(w, r, target, http.StatusFound)

	// Case 4: Query parameter read for searching, not redirecting
	query := r.URL.Query().Get("url")
	_ = query

	// Case 5: Redirecting to static internal error page
	http.Redirect(w, r, "/error?code=500", 302)

	// Case 6: FormValue read for ordinary form processing
	val := r.FormValue("next")
	_ = val
}

func sanitizeURL(raw string) string {
	return "/safe"
}
