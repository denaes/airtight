package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func insecureCases(filename, userID string) {
	// Case 1: Direct path in /tmp with os.Create
	f, err := os.Create("/tmp/app_upload.tmp")
	_ = f
	_ = err

	// Case 2: Direct path in /tmp with os.OpenFile
	file, _ := os.OpenFile("/tmp/log.txt", os.O_CREATE|os.O_WRONLY, 0644)
	_ = file

	// Case 3: filepath.Join with /tmp
	target, _ := os.Create(filepath.Join("/tmp", filename))
	_ = target

	// Case 4: fmt.Sprintf with /tmp
	out, _ := os.Create(fmt.Sprintf("/tmp/user_%s.dat", userID))
	_ = out

	// Case 5: Direct path in /var/tmp with os.Create
	tmpFile, _ := os.Create("/var/tmp/cache.bin")
	_ = tmpFile
}
