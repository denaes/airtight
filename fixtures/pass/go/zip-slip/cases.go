package main

import (
	"archive/tar"
	"archive/zip"
	"path/filepath"
	"strings"
)

func safeCases(destDir, output, baseDir string, f *zip.File, header *tar.Header, tr *tar.Header, file *zip.File, hdr *tar.Header) {
	// Near-miss 1: filepath.Clean and strings.HasPrefix check on the joined path
	if strings.HasPrefix(filepath.Clean(filepath.Join(destDir, f.Name)), destDir) {
		_ = destDir
	}

	// Near-miss 2: Using filepath.Base to prevent path traversal
	safePath := filepath.Join(destDir, filepath.Base(header.Name))
	_ = safePath

	// Near-miss 3: Static paths without archive member name
	staticPath := filepath.Join(destDir, "extracted", "static.txt")
	_ = staticPath

	// Near-miss 4: Commented-out extraction pattern
	// target := filepath.Join(destDir, tr.Name)

	// Near-miss 5: filepath.Clean on the extraction path
	cleaned := filepath.Clean(filepath.Join(baseDir, file.Name))
	_ = cleaned

	// Near-miss 6: strings.HasPrefix guard condition
	if strings.HasPrefix(filepath.Join(output, hdr.Name), output) {
		_ = output
	}
}
