package main

import (
	"net/http"
)

type OtherStruct struct {
	HttpOnly bool
	Secure   bool
}

type Cookie = http.Cookie

func safeCookies() {
	// Near-miss 1: Cookie with both HttpOnly and Secure explicitly set to true
	_ = http.Cookie{Name: "session", Value: "token", HttpOnly: true, Secure: true}

	// Near-miss 2: Pointer to Cookie with HttpOnly true and Secure true
	_ = &http.Cookie{Name: "auth", Value: "token", Secure: true, HttpOnly: true}

	// Near-miss 3: Commented out insecure cookie (filtered by not_regex)
	// &http.Cookie{Name: "session", Value: "token", HttpOnly: false}

	// Near-miss 4: Non-cookie struct with HttpOnly set to false
	_ = OtherStruct{HttpOnly: false, Secure: false}

	// Near-miss 5: Unqualified Cookie with Secure true and HttpOnly true
	_ = Cookie{Name: "sid", Secure: true, HttpOnly: true}

	// Near-miss 6: Cookie initialized without literal false flags
	var cookie http.Cookie
	cookie.Name = "session"

	// Near-miss 7: Commented out insecure cookie with Secure false
	// http.Cookie{Name: "auth", Value: "val", Secure: false}
}
