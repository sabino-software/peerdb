//go:build windows

package pluginruntime

import (
	"os"
	"os/exec"
)

func configureProcess(_ *exec.Cmd) {}

func terminateProcessGroup(process *os.Process) error {
	return process.Kill()
}

func killProcessGroup(process *os.Process) error {
	return process.Kill()
}
