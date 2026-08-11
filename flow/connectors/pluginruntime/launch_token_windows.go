//go:build windows

package pluginruntime

import (
	"errors"
	"os/exec"
)

// Windows has inheritable HANDLEs rather than Unix file descriptors. The
// protocol intentionally fails closed until the SDK defines an equivalent
// named-pipe/HANDLE contract; the package still cross-compiles on Windows.
func attachLaunchToken(_ *exec.Cmd, _ []byte) (func(), error) {
	return nil, errors.New("inherited launch-token descriptor is not implemented on windows")
}
