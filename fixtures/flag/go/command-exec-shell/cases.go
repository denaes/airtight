package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
)

func vulnShapes(ctx context.Context, cmd, input, url, userInput string, req *http.Request) {
	// Shape 1: exec.Command with sh -c and dynamic command variable
	_ = exec.Command("sh", "-c", cmd)

	// Shape 2: exec.Command with bash -c and formatted dynamic string
	_ = exec.Command("bash", "-c", fmt.Sprintf("echo %s", input))

	// Shape 3: exec.CommandContext with /bin/sh -c and concatenated string
	_ = exec.CommandContext(ctx, "/bin/sh", "-c", "curl " + url)

	// Shape 4: exec.Command with zsh -c and user input
	_ = exec.Command("zsh", "-c", userInput)

	// Shape 5: exec.CommandContext with dash -c and concatenated string
	_ = exec.CommandContext(ctx, "dash", "-c", "echo " + input)

	// Shape 6: exec.Command with /bin/bash -c and HTTP request parameter
	_ = exec.Command("/bin/bash", "-c", req.FormValue("cmd"))
}
