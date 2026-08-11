//go:build !windows

package pluginruntime

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyPrivateSocketRequiresExactMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on Unix socket: %v", err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod Unix socket: %v", err)
	}
	if err := verifyPrivateSocket(path); err != nil {
		t.Fatalf("verifyPrivateSocket rejected mode 0600 socket: %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatalf("chmod Unix socket to unsafe mode: %v", err)
	}
	if err := verifyPrivateSocket(path); err == nil {
		t.Fatal("verifyPrivateSocket accepted mode 0660 socket")
	}
}
