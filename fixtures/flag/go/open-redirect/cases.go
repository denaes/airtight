// True positive cases for go/open-redirect
package main

import (
	"net/http"
)

func flagCases(w http.ResponseWriter, r *http.Request) {
	// Case 1: http.Redirect with URL.Query().Get("url")
	http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)

	// Case 2: http.Redirect with FormValue("redirect")
	http.Redirect(w, r, r.FormValue("redirect"), http.StatusSeeOther)

	// Case 3: http.Redirect with URL.Query().Get("next")
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)

	// Case 4: http.Redirect with FormValue("target")
	http.Redirect(w, r, r.FormValue("target"), http.StatusTemporaryRedirect)

	// Case 5: http.Redirect with URL.Query().Get("dest")
	http.Redirect(w, r, r.URL.Query().Get("dest"), http.StatusFound)
}
