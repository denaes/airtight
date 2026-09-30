package main

import (
	"archive/tar"
	"archive/zip"
	"os"
	"path/filepath"
)

func extractCases(destDir, output, baseDir string, f *zip.File, header *tar.Header, tr *tar.Header, file *zip.File, hdr *tar.Header) {
	// Case 1: f.Name with filepath.Join and os.OpenFile
	target := filepath.Join(destDir, f.Name)
	_, _ = os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	// Case 2: header.Name with filepath.Join
	path := filepath.Join(output, header.Name)
	_ = path

	// Case 3: tr.Name with literal destination
	dest := filepath.Join("/tmp/extract", tr.Name)
	_ = dest

	// Case 4: file.Name with baseDir
	outPath := filepath.Join(baseDir, file.Name)
	_ = outPath

	// Case 5: hdr.Name with target directory
	targetFile := filepath.Join(destDir, hdr.Name)
	_ = targetFile
}
