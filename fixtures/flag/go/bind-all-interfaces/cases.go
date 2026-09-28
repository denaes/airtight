package main

import (
	"net"
	"net/http"
)

func runServers(handler http.Handler) {
	// Case 1: http.ListenAndServe with wildcard port
	_ = http.ListenAndServe(":8080", nil)

	// Case 2: http.ListenAndServe with 0.0.0.0
	_ = http.ListenAndServe("0.0.0.0:3000", handler)

	// Case 3: net.Listen tcp with wildcard port
	_, _ = net.Listen("tcp", ":9000")

	// Case 4: net.Listen tcp4 with 0.0.0.0
	_, _ = net.Listen("tcp4", "0.0.0.0:80")

	// Case 5: net.Listen tcp6 with wildcard port
	_, _ = net.Listen("tcp6", ":8000")

	// Case 6: net.Listen tcp with 0.0.0.0
	_, _ = net.Listen("tcp", "0.0.0.0:8080")
}
