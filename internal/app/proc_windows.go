//go:build windows

package app

import (
	"os/exec"
	"syscall"
)

func detach(c *exec.Cmd) {
	// CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200 | 0x00000008, HideWindow: true}
}
