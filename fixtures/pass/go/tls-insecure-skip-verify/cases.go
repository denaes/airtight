package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

// InsecureSkipVerify is disabled by default; never set InsecureSkipVerify to true in production.
func safeShapes(caCertPool *x509.CertPool) {
	// Near-miss 1: Explicitly set InsecureSkipVerify to false
	_ = &tls.Config{InsecureSkipVerify: false}

	// Near-miss 2: Modern TLS config with MinVersion and custom RootCAs
	_ = &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
	}

	// Near-miss 3: Direct assignment setting InsecureSkipVerify to false
	cfg := &tls.Config{}
	cfg.InsecureSkipVerify = false

	// Near-miss 4: Safe standard http.Client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	_ = client

	// Near-miss 5: Safe http.Transport with TLSClientConfig
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	_ = tr

	// Near-miss 6: Struct value assignment with false
	var conf tls.Config
	conf.InsecureSkipVerify = false
	_ = conf
}
