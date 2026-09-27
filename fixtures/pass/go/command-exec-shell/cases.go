package main

import (
	"context"
	"os/exec"
)

// Safe execution patterns: invoke executables directly without shell interpreters,
// or provide purely static command strings.
func safeShapes(ctx context.Context, path string) {
	// Near-miss 1: Direct binary execution with no shell
	_ = exec.Command("git", "status")

	// Near-miss 2: Direct binary execution with argument slice
	_ = exec.Command("ls", "-la", path)

	// Near-miss 3: Context-aware direct binary execution
	_ = exec.CommandContext(ctx, "go", "build")

	// Near-miss 4: Shell execution with static literal command string only
	_ = exec.Command("sh", "-c", "echo static_literal")

	// Near-miss 5: Context-aware shell execution with static literal command string
	_ = exec.CommandContext(ctx, "/bin/sh", "-c", "uptime")

	// Near-miss 6: Bash with static literal argument
	_ = exec.Command("bash", "-c", "date")

	// Near-miss 7: Commented out execution pattern
	// exec.Command("sh", "-c", cmd)
}
