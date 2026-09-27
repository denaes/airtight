package main

import (
	"os"
	"path/filepath"
)

func safe(base string) {
	data, _ := os.ReadFile("config.yaml")
	f, _ := os.Open(filepath.Join(base, "app.log"))
	content, _ := os.ReadFile("go.mod")
	cfg, _ := os.ReadFile(os.Getenv("CONFIG_PATH"))
	cert, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	_ = data
	_ = f
	_ = content
	_ = cfg
	_ = cert
}
