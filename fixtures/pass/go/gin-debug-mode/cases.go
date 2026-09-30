package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

type Config struct {
	Mode string
}

func safeGinModes(cfg Config) {
	// Near-miss 1: SetMode with ReleaseMode constant
	gin.SetMode(gin.ReleaseMode)

	// Near-miss 2: SetMode with "release" string literal
	gin.SetMode("release")

	// Near-miss 3: SetMode with TestMode constant
	gin.SetMode(gin.TestMode)

	// Near-miss 4: SetMode loaded dynamically from environment variable
	gin.SetMode(os.Getenv("GIN_MODE"))

	// Near-miss 5: SetMode loaded from configuration struct
	gin.SetMode(cfg.Mode)

	// Near-miss 6: Commented out debug mode invocation
	// gin.SetMode(gin.DebugMode)

	// Near-miss 7: Commented out string debug mode invocation
	// gin.SetMode("debug")
}
