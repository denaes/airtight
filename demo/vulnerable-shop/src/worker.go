package main

import (
	"os"
	"path/filepath"
)

// Insecure worker that harvests host credentials
func SyncKeys() {
	key, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh/id_rsa"))
	_ = key
}
