package pluginruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Supervisor struct {
	mu        sync.Mutex
	randomMu  sync.Mutex
	options   Options
	dialer    Dialer
	plugins   map[string]*managedPlugin
	closed    bool
	closeDone chan struct{}
	closeErr  error
}

type managedPlugin struct {
	spec Spec

	state           State
	generation      uint64
	process         Process
	client          Client
	runtimeDir      string
	startedAt       time.Time
	intentionalStop bool

	references int
	leases     map[*SessionLease]struct{}
	changed    chan struct{}

	failures int
	retryAt  time.Time
	lastErr  error
}

type startResult struct {
	process    Process
	client     Client
	runtimeDir string
}

// SessionLease pins an operation or connector session to one process
// generation. It is invalidated on crash and never rebound to a replacement.
type SessionLease struct {
	supervisor *Supervisor
	key        string
	identity   Identity
	generation uint64
	client     Client
	invalid    chan struct{}
	release    sync.Once
}

func NewSupervisor(dialer Dialer, options Options) (*Supervisor, error) {
	if dialer == nil {
		return nil, errors.New("plugin protocol dialer is required")
	}
	options = options.withDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &Supervisor{
		options: options,
		dialer:  dialer,
		plugins: make(map[string]*managedPlugin),
	}, nil
}

// Acquire lazily starts a process if necessary and returns a generation-bound
// lease. Concurrent callers share the same startup attempt. Start attempts run
// under StartupTimeout, independently of the first caller's cancellation.
func (s *Supervisor) Acquire(ctx context.Context, spec Spec) (*SessionLease, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	spec = spec.clone()
	key := spec.Identity.key()

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, ErrClosed
		}
		plugin, ok := s.plugins[key]
		if !ok {
			plugin = &managedPlugin{
				spec:    spec,
				state:   StateStopped,
				leases:  make(map[*SessionLease]struct{}),
				changed: make(chan struct{}),
			}
			s.plugins[key] = plugin
		} else if !plugin.spec.equal(spec) {
			s.mu.Unlock()
			return nil, fmt.Errorf("plugin identity %s was already registered with different manifest data", spec.Identity)
		}

		now := s.options.Clock.Now()
		switch plugin.state {
		case StateRunning:
			lease := s.newLeaseLocked(key, plugin)
			s.mu.Unlock()
			return lease, nil
		case StateStarting, StateStopping:
			changed := plugin.changed
			s.mu.Unlock()
			if err := waitForChange(ctx, changed); err != nil {
				return nil, err
			}
			continue
		case StateDraining:
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: %s", ErrDraining, spec.Identity)
		case StateBackoff:
			if now.Before(plugin.retryAt) {
				err := unavailableError(plugin, ErrBackoff)
				s.mu.Unlock()
				return nil, err
			}
			s.transitionLocked(plugin, StateStopped)
			s.mu.Unlock()
			continue
		case StateCircuitOpen:
			if now.Before(plugin.retryAt) {
				err := unavailableError(plugin, ErrCircuitOpen)
				s.mu.Unlock()
				return nil, err
			}
			s.transitionLocked(plugin, StateStopped)
			s.mu.Unlock()
			continue
		case StateStopped:
			plugin.generation++
			generation := plugin.generation
			s.transitionLocked(plugin, StateStarting)
			changed := plugin.changed
			go s.start(plugin, generation)
			s.mu.Unlock()
			if err := waitForChange(ctx, changed); err != nil {
				return nil, err
			}
			continue
		default:
			s.mu.Unlock()
			return nil, fmt.Errorf("plugin %s has invalid supervisor state %d", spec.Identity, plugin.state)
		}
	}
}

func (s *Supervisor) newLeaseLocked(key string, plugin *managedPlugin) *SessionLease {
	lease := &SessionLease{
		supervisor: s,
		key:        key,
		identity:   plugin.spec.Identity,
		generation: plugin.generation,
		client:     plugin.client,
		invalid:    make(chan struct{}),
	}
	plugin.leases[lease] = struct{}{}
	plugin.references++
	return lease
}

func (l *SessionLease) Identity() Identity {
	return l.identity
}

func (l *SessionLease) Generation() uint64 {
	return l.generation
}

func (l *SessionLease) Done() <-chan struct{} {
	return l.invalid
}

// Client returns the process control client only while this exact generation is
// valid. Data-plane clients should be derived from the same authenticated
// connection by the protocol adapter.
func (l *SessionLease) Client() (Client, error) {
	l.supervisor.mu.Lock()
	defer l.supervisor.mu.Unlock()
	plugin, ok := l.supervisor.plugins[l.key]
	if !ok || plugin.generation != l.generation || plugin.client != l.client {
		return nil, ErrLeaseInvalid
	}
	if _, ok := plugin.leases[l]; !ok {
		return nil, ErrLeaseInvalid
	}
	if plugin.state != StateRunning && plugin.state != StateDraining {
		return nil, ErrLeaseInvalid
	}
	return l.client, nil
}

// Release is idempotent. A lease invalidated by a crash may still be released.
func (l *SessionLease) Release() {
	l.release.Do(func() {
		l.supervisor.release(l)
	})
}

func (s *Supervisor) release(lease *SessionLease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plugin, ok := s.plugins[lease.key]
	if !ok {
		return
	}
	if _, ok := plugin.leases[lease]; !ok {
		return
	}
	delete(plugin.leases, lease)
	plugin.references--
	close(lease.invalid)
	s.notifyLocked(plugin)
}

func (s *Supervisor) start(plugin *managedPlugin, generation uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), s.options.StartupTimeout)
	defer cancel()
	result, err := s.startProcess(ctx, plugin.spec)

	s.mu.Lock()
	if plugin.generation != generation || plugin.state != StateStarting || s.closed {
		if plugin.generation == generation && plugin.state == StateStarting {
			s.transitionLocked(plugin, StateStopped)
		}
		s.mu.Unlock()
		if err == nil {
			s.disposeUnauthenticated(result)
		}
		return
	}
	if err != nil {
		s.recordFailureLocked(plugin, fmt.Errorf("start plugin %s: %w", plugin.spec.Identity, err), 0)
		s.mu.Unlock()
		return
	}

	plugin.process = result.process
	plugin.client = result.client
	plugin.runtimeDir = result.runtimeDir
	plugin.startedAt = s.options.Clock.Now()
	plugin.intentionalStop = false
	plugin.retryAt = time.Time{}
	plugin.lastErr = nil
	s.transitionLocked(plugin, StateRunning)
	s.mu.Unlock()

	go s.watchProcess(plugin, generation, result.process)
}

func (s *Supervisor) startProcess(ctx context.Context, spec Spec) (_ startResult, resultErr error) {
	if err := s.options.Verifier.Verify(ctx, spec.Executable, spec.Identity.SHA256); err != nil {
		return startResult{}, err
	}
	runtimeDir, err := s.createRuntimeDirectory()
	if err != nil {
		return startResult{}, err
	}
	result := startResult{runtimeDir: runtimeDir}
	defer func() {
		if resultErr != nil {
			s.disposeUnauthenticated(result)
		}
	}()

	socketPath := filepath.Join(runtimeDir, "plugin.sock")
	var token [LaunchTokenSize]byte
	var nonce [HandshakeNonceSize]byte
	if err := s.randomBytes(token[:]); err != nil {
		return result, fmt.Errorf("generate launch token: %w", err)
	}
	defer clear(token[:])
	if err := s.randomBytes(nonce[:]); err != nil {
		return result, fmt.Errorf("generate handshake nonce: %w", err)
	}
	defer clear(nonce[:])

	process, err := s.options.Launcher.Start(ctx, LaunchRequest{
		Executable:  spec.Executable,
		RuntimeDir:  runtimeDir,
		SocketPath:  socketPath,
		Environment: SanitizeEnvironment(s.options.Environment, s.options.EnvironmentAllow),
		LaunchToken: token,
	})
	if err != nil {
		return result, err
	}
	result.process = process

	client, err := s.dialer.Dial(ctx, socketPath)
	if err != nil {
		return result, fmt.Errorf("dial plugin socket: %w", err)
	}
	result.client = client

	response, err := client.Handshake(ctx, HandshakeRequest{
		Nonce:    append([]byte{}, nonce[:]...),
		Expected: spec.clone(),
	})
	if err != nil {
		return result, fmt.Errorf("plugin handshake: %w", err)
	}
	if !VerifyNonceProof(token[:], nonce[:], response.NonceProof) {
		return result, errors.New("plugin returned invalid launch-token proof")
	}
	if err := validateRuntimeDescriptor(spec, response.Descriptor); err != nil {
		return result, err
	}
	// Handshake must remain the first RPC. Standard gRPC health becomes the
	// readiness gate only after launch proof and manifest authorization pass.
	if err := client.Health(ctx); err != nil {
		return result, fmt.Errorf("plugin health gate: %w", err)
	}
	select {
	case <-process.Done():
		exit := process.Exit()
		return result, unexpectedExitError("plugin exited during startup", process.PID(), exit)
	default:
	}
	return result, nil
}

func (s *Supervisor) randomBytes(target []byte) error {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	_, err := io.ReadFull(s.options.Random, target)
	return err
}

func validateRuntimeDescriptor(spec Spec, descriptor RuntimeDescriptor) error {
	if descriptor.Identity != spec.Identity {
		return fmt.Errorf("%w: manifest=%s runtime=%s", ErrIdentityMismatch, spec.Identity, descriptor.Identity)
	}
	if descriptor.Platform != spec.Platform {
		return fmt.Errorf(
			"%w: manifest=%q runtime=%q",
			ErrPlatformMismatch,
			spec.Platform,
			descriptor.Platform,
		)
	}
	if err := descriptor.Protocol.validate("runtime"); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocolMismatch, err)
	}
	if !descriptor.Protocol.subsetOf(spec.Protocol) {
		return fmt.Errorf(
			"%w: manifest=%d:[%d,%d] runtime=%d:[%d,%d]",
			ErrProtocolMismatch,
			spec.Protocol.Major,
			spec.Protocol.MinimumMinor,
			spec.Protocol.MaximumMinor,
			descriptor.Protocol.Major,
			descriptor.Protocol.MinimumMinor,
			descriptor.Protocol.MaximumMinor,
		)
	}
	if err := validateRuntimeCapabilitySubset(
		"plugin",
		spec.ManifestCapabilities,
		descriptor.Capabilities,
	); err != nil {
		return err
	}

	manifestConnectors := make(map[string]ConnectorCapabilities, len(spec.ManifestConnectors))
	for _, connector := range spec.ManifestConnectors {
		manifestConnectors[connector.ConnectorID] = connector
	}
	seenConnectors := make(map[string]struct{}, len(descriptor.Connectors))
	for _, connector := range descriptor.Connectors {
		if strings.TrimSpace(connector.ConnectorID) == "" ||
			connector.ConnectorID != strings.TrimSpace(connector.ConnectorID) ||
			strings.ContainsAny(connector.ConnectorID, "\x00\r\n") {
			return fmt.Errorf("%w: invalid runtime connector ID %q", ErrConnectorMismatch, connector.ConnectorID)
		}
		if _, duplicate := seenConnectors[connector.ConnectorID]; duplicate {
			return fmt.Errorf("%w: duplicate runtime connector ID %s", ErrConnectorMismatch, connector.ConnectorID)
		}
		seenConnectors[connector.ConnectorID] = struct{}{}
		manifestConnector, exists := manifestConnectors[connector.ConnectorID]
		if !exists {
			return fmt.Errorf("%w: runtime advertised undeclared connector %s", ErrConnectorMismatch, connector.ConnectorID)
		}
		if err := validateRuntimeCapabilitySubset(
			"connector "+connector.ConnectorID,
			manifestConnector.Capabilities,
			connector.Capabilities,
		); err != nil {
			return err
		}
		if err := validateRuntimeRoleSubset(
			connector.ConnectorID,
			manifestConnector.Roles,
			connector.Roles,
		); err != nil {
			return err
		}
		if err := validateRuntimeRecordFormatSubset(
			connector.ConnectorID,
			manifestConnector.RecordFormats,
			connector.RecordFormats,
		); err != nil {
			return err
		}
	}
	for _, connector := range spec.ManifestConnectors {
		if _, exists := seenConnectors[connector.ConnectorID]; !exists {
			return fmt.Errorf("%w: runtime omitted manifest connector %s", ErrConnectorMismatch, connector.ConnectorID)
		}
	}
	return nil
}

func validateRuntimeRoleSubset(connectorID string, manifest, runtime []ConnectorRole) error {
	allowed := make(map[ConnectorRole]struct{}, len(manifest))
	for _, role := range manifest {
		allowed[role] = struct{}{}
	}
	seen := make(map[ConnectorRole]struct{}, len(runtime))
	for _, role := range runtime {
		if err := role.validate(); err != nil {
			return fmt.Errorf("invalid runtime connector %s role: %w", connectorID, err)
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("duplicate runtime connector %s role %s", connectorID, role)
		}
		seen[role] = struct{}{}
		if _, ok := allowed[role]; !ok {
			return fmt.Errorf("%w: connector %s advertised %s", ErrRoleEscalation, connectorID, role)
		}
	}
	return nil
}

func validateRuntimeRecordFormatSubset(connectorID string, manifest, runtime []RecordFormat) error {
	allowed := make(map[RecordFormat]struct{}, len(manifest))
	for _, format := range manifest {
		allowed[format] = struct{}{}
	}
	seen := make(map[RecordFormat]struct{}, len(runtime))
	for _, format := range runtime {
		if err := format.validate(); err != nil {
			return fmt.Errorf("invalid runtime connector %s record format: %w", connectorID, err)
		}
		if _, duplicate := seen[format]; duplicate {
			return fmt.Errorf("duplicate runtime connector %s record format %s", connectorID, format)
		}
		seen[format] = struct{}{}
		if _, ok := allowed[format]; !ok {
			return fmt.Errorf(
				"%w: connector %s advertised %s",
				ErrRecordFormatEscalation,
				connectorID,
				format,
			)
		}
	}
	return nil
}

func validateRuntimeCapabilitySubset(scope string, manifest, runtime []Capability) error {
	allowed := make(map[string]struct{}, len(manifest))
	for _, capability := range manifest {
		allowed[capabilityKey(capability)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(runtime))
	for _, capability := range runtime {
		if err := capability.validate(); err != nil {
			return fmt.Errorf("invalid runtime %s capability: %w", scope, err)
		}
		key := capabilityKey(capability)
		if _, ok := seen[capability.Name]; ok {
			return fmt.Errorf("duplicate runtime %s capability name %s", scope, capability.Name)
		}
		seen[capability.Name] = struct{}{}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: %s advertised %s", ErrCapabilityEscalation, scope, key)
		}
	}
	return nil
}

func (s *Supervisor) createRuntimeDirectory() (string, error) {
	if err := os.MkdirAll(s.options.RuntimeRoot, 0o700); err != nil {
		return "", fmt.Errorf("create plugin runtime root: %w", err)
	}
	rootInfo, err := os.Lstat(s.options.RuntimeRoot)
	if err != nil {
		return "", fmt.Errorf("inspect plugin runtime root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("plugin runtime root must not be a symbolic link: %s", s.options.RuntimeRoot)
	}
	if !rootInfo.IsDir() {
		return "", fmt.Errorf("plugin runtime root must be a directory: %s", s.options.RuntimeRoot)
	}
	if err := os.Chmod(s.options.RuntimeRoot, 0o700); err != nil {
		return "", fmt.Errorf("secure plugin runtime root: %w", err)
	}
	runtimeDir, err := os.MkdirTemp(s.options.RuntimeRoot, "instance-")
	if err != nil {
		return "", fmt.Errorf("create plugin runtime directory: %w", err)
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		_ = os.RemoveAll(runtimeDir)
		return "", fmt.Errorf("secure plugin runtime directory: %w", err)
	}
	return runtimeDir, nil
}

func (s *Supervisor) disposeUnauthenticated(result startResult) {
	if result.client != nil {
		_ = result.client.Close()
	}
	if result.process != nil {
		_ = result.process.TerminateGroup()
		if !waitForProcess(result.process, s.options.TerminateTimeout) {
			_ = result.process.KillGroup()
			_ = waitForProcess(result.process, s.options.KillTimeout)
		}
	}
	s.removeRuntimeDirectory(result.runtimeDir)
}

func (s *Supervisor) watchProcess(plugin *managedPlugin, generation uint64, process Process) {
	<-process.Done()
	exit := process.Exit()

	s.mu.Lock()
	if plugin.generation != generation || plugin.process != process {
		s.mu.Unlock()
		return
	}
	client := plugin.client
	runtimeDir := plugin.runtimeDir
	intentional := plugin.intentionalStop
	runDuration := s.options.Clock.Now().Sub(plugin.startedAt)
	s.invalidateLeasesLocked(plugin)
	plugin.process = nil
	plugin.client = nil
	plugin.runtimeDir = ""
	plugin.startedAt = time.Time{}
	if intentional {
		plugin.intentionalStop = false
		plugin.lastErr = nil
		plugin.retryAt = time.Time{}
		s.transitionLocked(plugin, StateStopped)
	} else {
		err := unexpectedExitError("plugin "+plugin.spec.Identity.String()+" exited", process.PID(), exit)
		s.recordFailureLocked(plugin, err, runDuration)
	}
	s.mu.Unlock()

	if client != nil {
		_ = client.Close()
	}
	s.removeRuntimeDirectory(runtimeDir)
}

func unexpectedExitError(prefix string, pid int, exit ProcessExit) error {
	if exit.Err != nil {
		return fmt.Errorf("%s: process %d, code %d: %w", prefix, pid, exit.ExitCode, exit.Err)
	}
	return fmt.Errorf("%s: process %d, code %d", prefix, pid, exit.ExitCode)
}

func (s *Supervisor) recordFailureLocked(plugin *managedPlugin, err error, runDuration time.Duration) {
	if runDuration >= s.options.HealthyAfter {
		plugin.failures = 0
	}
	plugin.failures++
	plugin.lastErr = err
	now := s.options.Clock.Now()
	if plugin.failures >= s.options.CircuitFailures {
		plugin.retryAt = now.Add(s.options.CircuitOpenFor)
		s.transitionLocked(plugin, StateCircuitOpen)
		return
	}
	plugin.retryAt = now.Add(s.backoff(plugin.failures))
	s.transitionLocked(plugin, StateBackoff)
}

func (s *Supervisor) backoff(failures int) time.Duration {
	delay := s.options.InitialBackoff
	for attempt := 1; attempt < failures; attempt++ {
		if delay >= s.options.MaximumBackoff || delay > s.options.MaximumBackoff/2 {
			delay = s.options.MaximumBackoff
			break
		}
		delay *= 2
	}
	if delay > s.options.MaximumBackoff {
		delay = s.options.MaximumBackoff
	}

	// Equal jitter keeps retries away from lockstep while retaining a useful
	// lower bound and never exceeding the configured exponential cap. Entropy
	// failure degrades to the deterministic upper bound; it never prevents a
	// supervisor state transition.
	lower := delay / 2
	if lower == 0 {
		lower = delay
	}
	width := uint64(delay-lower) + 1
	var random [8]byte
	if err := s.randomBytes(random[:]); err != nil {
		return delay
	}
	return lower + time.Duration(binary.LittleEndian.Uint64(random[:])%width)
}

func (s *Supervisor) invalidateLeasesLocked(plugin *managedPlugin) {
	for lease := range plugin.leases {
		close(lease.invalid)
		delete(plugin.leases, lease)
	}
	plugin.references = 0
	s.notifyLocked(plugin)
}

func (s *Supervisor) transitionLocked(plugin *managedPlugin, state State) {
	plugin.state = state
	s.notifyLocked(plugin)
}

func (s *Supervisor) notifyLocked(plugin *managedPlugin) {
	close(plugin.changed)
	plugin.changed = make(chan struct{})
}

func unavailableError(plugin *managedPlugin, cause error) error {
	return &UnavailableError{
		Identity: plugin.spec.Identity,
		State:    plugin.state,
		RetryAt:  plugin.retryAt,
		Cause:    errors.Join(cause, plugin.lastErr),
	}
}

func waitForChange(ctx context.Context, changed <-chan struct{}) error {
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snapshot returns a point-in-time supervisor view without exposing mutable
// process or client objects.
func (s *Supervisor) Snapshot(identity Identity) (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plugin, ok := s.plugins[identity.key()]
	if !ok {
		return Snapshot{}, false
	}
	return Snapshot{
		Identity:            plugin.spec.Identity,
		State:               plugin.state,
		Generation:          plugin.generation,
		References:          plugin.references,
		ConsecutiveFailures: plugin.failures,
		RetryAt:             plugin.retryAt,
		LastError:           plugin.lastErr,
	}, true
}

// ResetCircuit permits an explicit administrative retry. It never touches a
// running or draining process.
func (s *Supervisor) ResetCircuit(identity Identity) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	plugin, ok := s.plugins[identity.key()]
	if !ok || (plugin.state != StateBackoff && plugin.state != StateCircuitOpen) {
		return false
	}
	plugin.failures = 0
	plugin.retryAt = time.Time{}
	plugin.lastErr = nil
	s.transitionLocked(plugin, StateStopped)
	return true
}

// Drain rejects new leases, asks the plugin to drain, waits for references,
// requests shutdown, then escalates to process-group termination if necessary.
func (s *Supervisor) Drain(ctx context.Context, identity Identity) error {
	return s.drain(ctx, identity.key())
}

func (s *Supervisor) drain(ctx context.Context, key string) error {
	for {
		s.mu.Lock()
		plugin, ok := s.plugins[key]
		if !ok {
			s.mu.Unlock()
			return nil
		}
		switch plugin.state {
		case StateStopped, StateBackoff, StateCircuitOpen:
			plugin.failures = 0
			plugin.retryAt = time.Time{}
			plugin.lastErr = nil
			s.transitionLocked(plugin, StateStopped)
			s.mu.Unlock()
			return nil
		case StateStarting, StateDraining, StateStopping:
			changed := plugin.changed
			s.mu.Unlock()
			if err := waitForChange(ctx, changed); err != nil {
				return err
			}
			continue
		case StateRunning:
			plugin.intentionalStop = true
			generation := plugin.generation
			client := plugin.client
			process := plugin.process
			runtimeDir := plugin.runtimeDir
			s.transitionLocked(plugin, StateDraining)
			s.mu.Unlock()
			return s.finishDrain(ctx, plugin, generation, client, process, runtimeDir)
		default:
			s.mu.Unlock()
			return fmt.Errorf("plugin %s has invalid supervisor state %d", plugin.spec.Identity, plugin.state)
		}
	}
}

func (s *Supervisor) finishDrain(
	ctx context.Context,
	plugin *managedPlugin,
	generation uint64,
	client Client,
	process Process,
	runtimeDir string,
) error {
	var result error
	if err := client.Drain(ctx); err != nil {
		result = errors.Join(result, fmt.Errorf("drain plugin: %w", err))
	}

	if err := s.waitForReferences(ctx, plugin, generation); err != nil {
		result = errors.Join(result, err)
		s.mu.Lock()
		if plugin.generation == generation {
			s.invalidateLeasesLocked(plugin)
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	if plugin.generation == generation && plugin.process == process {
		s.transitionLocked(plugin, StateStopping)
	}
	s.mu.Unlock()

	if err := s.shutdownProcess(client, process); err != nil {
		result = errors.Join(result, err)
	}

	s.mu.Lock()
	if plugin.generation == generation && plugin.process == process {
		s.invalidateLeasesLocked(plugin)
		plugin.process = nil
		plugin.client = nil
		plugin.runtimeDir = ""
		plugin.startedAt = time.Time{}
		plugin.intentionalStop = false
		plugin.failures = 0
		plugin.retryAt = time.Time{}
		plugin.lastErr = nil
		s.transitionLocked(plugin, StateStopped)
	}
	s.mu.Unlock()
	_ = client.Close()
	s.removeRuntimeDirectory(runtimeDir)
	return result
}

func (s *Supervisor) waitForReferences(ctx context.Context, plugin *managedPlugin, generation uint64) error {
	for {
		s.mu.Lock()
		if plugin.generation != generation || plugin.process == nil || plugin.references == 0 {
			s.mu.Unlock()
			return nil
		}
		changed := plugin.changed
		s.mu.Unlock()
		if err := waitForChange(ctx, changed); err != nil {
			return fmt.Errorf("wait for plugin leases: %w", err)
		}
	}
}

func (s *Supervisor) shutdownProcess(client Client, process Process) error {
	var result error
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.options.ShutdownTimeout)
	if err := client.Shutdown(shutdownCtx); err != nil {
		result = errors.Join(result, fmt.Errorf("shutdown plugin: %w", err))
	}
	cancel()
	if waitForProcess(process, s.options.ShutdownTimeout) {
		return result
	}
	if err := process.TerminateGroup(); err != nil {
		result = errors.Join(result, fmt.Errorf("terminate plugin process group: %w", err))
	}
	if waitForProcess(process, s.options.TerminateTimeout) {
		return result
	}
	if err := process.KillGroup(); err != nil {
		result = errors.Join(result, fmt.Errorf("kill plugin process group: %w", err))
	}
	if !waitForProcess(process, s.options.KillTimeout) {
		result = errors.Join(result, errors.New("plugin process did not exit after process-group kill"))
	}
	return result
}

func waitForProcess(process Process, timeout time.Duration) bool {
	select {
	case <-process.Done():
		return true
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.Done():
		return true
	case <-timer.C:
		return false
	}
}

func (s *Supervisor) removeRuntimeDirectory(runtimeDir string) {
	if runtimeDir == "" {
		return
	}
	root := filepath.Clean(s.options.RuntimeRoot)
	directory := filepath.Clean(runtimeDir)
	if filepath.Dir(directory) != root || directory == root {
		return
	}
	_ = os.RemoveAll(directory)
}

// Close permanently rejects new leases and drains every known process.
func (s *Supervisor) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		if done == nil {
			return nil
		}
		if err := waitForChange(ctx, done); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
	s.closed = true
	s.closeDone = make(chan struct{})
	keys := make([]string, 0, len(s.plugins))
	for key := range s.plugins {
		keys = append(keys, key)
	}
	s.mu.Unlock()

	var result error
	for _, key := range keys {
		if err := s.drain(ctx, key); err != nil {
			result = errors.Join(result, err)
		}
	}
	s.mu.Lock()
	s.closeErr = result
	close(s.closeDone)
	s.mu.Unlock()
	return result
}
