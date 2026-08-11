//go:build !windows

package pluginruntime

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func attachLaunchToken(cmd *exec.Cmd, token []byte) (func(), error) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create launch-token pipe: %w", err)
	}
	cleanup := func() {
		_ = readPipe.Close()
		_ = writePipe.Close()
	}
	if _, err := writePipe.Write(token); err != nil {
		cleanup()
		return nil, fmt.Errorf("write launch-token pipe: %w", err)
	}
	if err := writePipe.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("close launch-token pipe writer: %w", err)
	}

	fileDescriptor := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, readPipe)
	cmd.Env = append(cmd.Env, launchTokenFDEnvironment+"="+strconv.Itoa(fileDescriptor))
	return cleanup, nil
}
