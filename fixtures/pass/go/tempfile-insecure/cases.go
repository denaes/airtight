package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func safeCases(filename string) {
	// Near-miss 1: os.CreateTemp with default temp dir
	f1, err := os.CreateTemp("", "upload-*.tmp")
	_ = f1
	_ = err

	// Near-miss 2: os.CreateTemp with explicit /tmp dir
	f2, _ := os.CreateTemp("/tmp", "safe-*.dat")
	_ = f2

	// Near-miss 3: Commented-out insecure temporary file creation
	// f := os.Create("/tmp/app_upload.tmp")

	// Near-miss 4: os.Create with non-temporary system log path
	f3, _ := os.Create("/var/log/app/service.log")
	_ = f3

	// Near-miss 5: os.OpenFile with relative local file
	f4, _ := os.OpenFile("./local_file.txt", os.O_RDWR, 0600)
	_ = f4

	// Near-miss 6: ioutil.TempFile usage
	f5, _ := ioutil.TempFile("/tmp", "tempfile-*.tmp")
	_ = f5

	// Near-miss 7: filepath.Join with non-tmp directory
	f6, _ := os.Create(filepath.Join("/var/log", filename))
	_ = f6
}
