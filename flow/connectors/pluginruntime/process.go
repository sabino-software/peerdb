package pluginruntime

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	launchTokenFDEnvironment = "PEERDB_PLUGIN_LAUNCH_TOKEN_FD"
	socketEnvironment        = "PEERDB_PLUGIN_SOCKET"
)

type LaunchRequest struct {
	Executable  string
	RuntimeDir  string
	SocketPath  string
	Environment []string
	LaunchToken [LaunchTokenSize]byte
}

type Launcher interface {
	Start(context.Context, LaunchRequest) (Process, error)
}

type ProcessExit struct {
	ExitCode int
	Err      error
	At       time.Time
}

// Process operations apply to the child process group where the platform
// supports it. TerminateGroup is graceful; KillGroup is the final hard stop.
type Process interface {
	PID() int
	Done() <-chan struct{}
	Exit() ProcessExit
	TerminateGroup() error
	KillGroup() error
}

// FileVerifier hashes the exact executable immediately before launch. Artifact
// directories must additionally be mounted immutable to close path replacement
// races between verification and exec.
type FileVerifier struct{}

func (FileVerifier) Verify(ctx context.Context, path string, expected [32]byte) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open plugin executable: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat plugin executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin executable is not a regular file: %s", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("plugin artifact is not executable: %s", path)
	}

	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("hash plugin executable: %w", readErr)
		}
	}
	actual := hash.Sum(nil)
	if subtle.ConstantTimeCompare(actual, expected[:]) != 1 {
		return fmt.Errorf("plugin executable SHA-256 mismatch: got %x", actual)
	}
	return nil
}

// ExecLauncher invokes only the verified executable. It never invokes a shell,
// resolves PATH, or places the launch token in argv/environment.
type ExecLauncher struct{}

func (ExecLauncher) Start(ctx context.Context, request LaunchRequest) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(request.Executable) {
		return nil, fmt.Errorf("plugin executable must be absolute: %q", request.Executable)
	}
	if filepath.Dir(request.SocketPath) != request.RuntimeDir {
		return nil, errors.New("plugin socket must be directly inside its runtime directory")
	}

	cmd := exec.Command(request.Executable, "serve", "--socket", request.SocketPath)
	cmd.Dir = request.RuntimeDir
	cmd.Env = append([]string{}, request.Environment...)
	cmd.Env = append(cmd.Env, socketEnvironment+"="+request.SocketPath)
	configureProcess(cmd)

	cleanupToken, err := attachLaunchToken(cmd, request.LaunchToken[:])
	if err != nil {
		return nil, err
	}
	defer cleanupToken()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plugin executable: %w", err)
	}
	process := &execProcess{
		cmd:  cmd,
		done: make(chan struct{}),
	}
	go process.wait()
	return process, nil
}

type execProcess struct {
	cmd  *exec.Cmd
	done chan struct{}

	mu   sync.RWMutex
	exit ProcessExit
}

func (p *execProcess) wait() {
	err := p.cmd.Wait()
	exitCode := -1
	if p.cmd.ProcessState != nil {
		exitCode = p.cmd.ProcessState.ExitCode()
	}
	p.mu.Lock()
	p.exit = ProcessExit{ExitCode: exitCode, Err: err, At: time.Now()}
	p.mu.Unlock()
	close(p.done)
}

func (p *execProcess) PID() int {
	return p.cmd.Process.Pid
}

func (p *execProcess) Done() <-chan struct{} {
	return p.done
}

func (p *execProcess) Exit() ProcessExit {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.exit
}

func (p *execProcess) TerminateGroup() error {
	return terminateProcessGroup(p.cmd.Process)
}

func (p *execProcess) KillGroup() error {
	return killProcessGroup(p.cmd.Process)
}

var defaultEnvironmentAllowlist = []string{
	"COMSPEC",
	"LANG",
	"LC_ALL",
	"PATH",
	"PATHEXT",
	"SSL_CERT_DIR",
	"SSL_CERT_FILE",
	"SYSTEMROOT",
	"TEMP",
	"TMP",
	"TMPDIR",
	"TZ",
	"WINDIR",
}

// SanitizeEnvironment copies only explicitly allowed variables. Matching is
// case-insensitive on Windows, and output is deterministic for auditability.
func SanitizeEnvironment(environment, additionalAllowlist []string) []string {
	allowed := make(map[string]struct{}, len(defaultEnvironmentAllowlist)+len(additionalAllowlist))
	for _, name := range append(slicesClone(defaultEnvironmentAllowlist), additionalAllowlist...) {
		allowed[environmentKey(name)] = struct{}{}
	}

	values := make(map[string]string)
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			continue
		}
		key := environmentKey(name)
		if _, ok := allowed[key]; !ok {
			continue
		}
		if key == environmentKey(socketEnvironment) || key == environmentKey(launchTokenFDEnvironment) {
			continue
		}
		values[key] = entry
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result
}

func environmentKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

func slicesClone[T any](input []T) []T {
	result := make([]T, len(input))
	copy(result, input)
	return result
}
