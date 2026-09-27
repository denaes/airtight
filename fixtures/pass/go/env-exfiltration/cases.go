package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

func normal() {
	port := os.Getenv("PORT")
	resp, _ := http.Get(os.Getenv("TARGET_URL"))
	data, _ := json.Marshal(map[string]string{"port": port})
	path := filepath.Join(os.Getenv("HOME"), "data")
	env := os.Getenv("APP_ENV")
	_ = resp
	_ = data
	_ = path
	_ = env
}
