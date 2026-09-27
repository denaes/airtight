package main

import (
	"crypto/tls"
	"net/http"
)

func insecureShapes() {
	// Shape 1: Inline struct literal
	_ = &tls.Config{InsecureSkipVerify: true}

	// Shape 2: Multi-line struct literal
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	_ = tlsConfig

	// Shape 3: Direct assignment on pointer
	cfg := &tls.Config{}
	cfg.InsecureSkipVerify = true

	// Shape 4: Nested in http.Transport struct literal
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = tr

	// Shape 5: Direct assignment on value struct
	var conf tls.Config
	conf.InsecureSkipVerify = true
	_ = conf
}
