//go:build !windows

package app

import (
	"os/exec"
	"syscall"
)

func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
