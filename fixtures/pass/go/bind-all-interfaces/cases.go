package main

import (
	"net"
	"net/http"
)

// Safe server listening configurations binding only to localhost, private IP, or unix domain sockets.
func safeServers(handler http.Handler) {
	// Near-miss 1: Explicit loopback binding with http.ListenAndServe
	_ = http.ListenAndServe("127.0.0.1:8080", nil)

	// Near-miss 2: Explicit localhost binding with http.ListenAndServe
	_ = http.ListenAndServe("localhost:3000", handler)

	// Near-miss 3: Explicit private network IP binding
	_ = http.ListenAndServe("10.0.0.5:8080", handler)

	// Near-miss 4: net.Listen bound to loopback 127.0.0.1
	_, _ = net.Listen("tcp", "127.0.0.1:9000")

	// Near-miss 5: net.Listen bound to localhost
	_, _ = net.Listen("tcp", "localhost:8080")

	// Near-miss 6: net.Listen on unix domain socket
	_, _ = net.Listen("unix", "/tmp/app.sock")

	// Near-miss 7: Commented out bind-all listener
	// _ = http.ListenAndServe(":8080", nil)

	// Near-miss 8: Commented out net.Listen
	// _, _ = net.Listen("tcp", ":9000")
}
