package main

import (
	"net/http"
)

type Cookie = http.Cookie

func vulnerableCookies() {
	// Case 1: http.Cookie with HttpOnly set to false
	_ = &http.Cookie{Name: "session", Value: "token123", HttpOnly: false}

	// Case 2: http.Cookie with Secure set to false
	_ = http.Cookie{Name: "auth", Value: "val", Secure: false}

	// Case 3: http.Cookie variable with HttpOnly false and Secure true
	c := http.Cookie{Name: "sid", HttpOnly: false, Secure: true}
	_ = c

	// Case 4: pointer to http.Cookie with Secure false
	_ = &http.Cookie{Name: "jwt", Secure: false}

	// Case 5: unqualified Cookie struct with HttpOnly false
	_ = Cookie{Name: "refresh", Value: "token", HttpOnly: false, Secure: true}

	// Case 6: unqualified Cookie pointer with Secure false
	_ = &Cookie{Name: "pref", Secure: false}
}
