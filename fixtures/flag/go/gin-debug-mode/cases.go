package main

import (
	"github.com/gin-gonic/gin"
)

func vulnGinModes() {
	// Shape 1: gin.SetMode with gin.DebugMode constant
	gin.SetMode(gin.DebugMode)

	// Shape 2: gin.SetMode with "debug" string literal
	gin.SetMode("debug")

	// Shape 3: gin.SetMode with gin.DebugMode followed by router initialization
	gin.SetMode(gin.DebugMode); r := gin.Default()
	_ = r

	// Shape 4: gin.SetMode with "debug" followed by router initialization
	gin.SetMode("debug"); router := gin.New()
	_ = router

	// Shape 5: gin.SetMode with whitespace
	gin.SetMode( gin.DebugMode )

	// Shape 6: gin.SetMode with uppercase string literal
	gin.SetMode("DEBUG")
}
