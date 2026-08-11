package pluginruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAcquireDeduplicatesStartAndCreatesPrivateRuntime(t *testing.T) {
	identity := testIdentity(1)
	spec := testSpec(identity)
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	supervisor, err := NewSupervisor(harness, testOptions(t, harness))
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}

	const callers = 32
	leases := make(chan *SessionLease, callers)
	errorsChannel := make(chan error, callers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			lease, acquireErr := supervisor.Acquire(context.Background(), spec)
			if acquireErr != nil {
				errorsChannel <- acquireErr
				return
			}
			leases <- lease
		}()
	}
	close(start)
	group.Wait()
	close(errorsChannel)
	close(leases)
	for acquireErr := range errorsChannel {
		t.Errorf("Acquire returned an error: %v", acquireErr)
	}

	if starts := harness.startCount(); starts != 1 {
		t.Fatalf("launcher starts = %d, want 1", starts)
	}
	request := harness.lastRequest()
	info, err := os.Stat(request.RuntimeDir)
	if err != nil {
		t.Fatalf("stat runtime directory: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("runtime directory permissions = %o, want 700", permissions)
	}
	if filepath.Dir(request.SocketPath) != request.RuntimeDir {
		t.Fatalf("socket %q is outside runtime directory %q", request.SocketPath, request.RuntimeDir)
	}
	if !slices.Contains(request.Environment, "PATH=/safe/bin") {
		t.Fatalf("sanitized environment omitted PATH: %v", request.Environment)
	}
	for _, entry := range request.Environment {
		if strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY=") || strings.HasPrefix(entry, "UNRELATED=") {
			t.Fatalf("secret/unapproved environment variable leaked: %q", entry)
		}
	}

	leaseCount := 0
	for lease := range leases {
		leaseCount++
		lease.Release()
	}
	if leaseCount != callers {
		t.Fatalf("leases = %d, want %d", leaseCount, callers)
	}
	snapshot, ok := supervisor.Snapshot(identity)
	if !ok || snapshot.State != StateRunning || snapshot.References != 0 {
		t.Fatalf("unexpected snapshot after releases: %+v, found=%v", snapshot, ok)
	}
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if _, err := os.Stat(request.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime directory still exists after close: %v", err)
	}
}

func TestRuntimeDescriptorMustMatchManifestAndCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		descriptor func(Spec) RuntimeDescriptor
		want       error
	}{
		{
			name: "identity mismatch",
			descriptor: func(spec Spec) RuntimeDescriptor {
				descriptor := runtimeDescriptorForSpec(spec)
				descriptor.Identity.Version = "different"
				return descriptor
			},
			want: ErrIdentityMismatch,
		},
		{
			name: "capability escalation",
			descriptor: func(spec Spec) RuntimeDescriptor {
				descriptor := runtimeDescriptorForSpec(spec)
				descriptor.Connectors[0].Capabilities = append(
					descriptor.Connectors[0].Capabilities,
					Capability{Name: "query", Version: 1},
				)
				return descriptor
			},
			want: ErrCapabilityEscalation,
		},
		{
			name: "connector identity mismatch",
			descriptor: func(spec Spec) RuntimeDescriptor {
				descriptor := runtimeDescriptorForSpec(spec)
				descriptor.Connectors[0].ConnectorID = "mysql"
				return descriptor
			},
			want: ErrConnectorMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(2)
			spec := testSpec(identity)
			harness := newFakeHarness(test.descriptor(spec))
			supervisor, err := NewSupervisor(harness, testOptions(t, harness))
			if err != nil {
				t.Fatalf("NewSupervisor returned an error: %v", err)
			}
			_, err = supervisor.Acquire(context.Background(), spec)
			if !errors.Is(err, test.want) {
				t.Fatalf("Acquire error = %v, want errors.Is(%v)", err, test.want)
			}
			instance := harness.lastInstance()
			if instance.process.terminateCalls() != 1 {
				t.Fatalf("unauthenticated process terminate calls = %d, want 1", instance.process.terminateCalls())
			}
		})
	}
}

func TestRuntimeRolesAndRecordFormatsRemainManifestScoped(t *testing.T) {
	identity := testIdentity(11)
	spec := testSpec(identity)
	tests := []struct {
		name   string
		mutate func(*RuntimeDescriptor)
		want   error
	}{
		{
			name: "role escalation",
			mutate: func(descriptor *RuntimeDescriptor) {
				descriptor.Connectors[0].Roles = append(
					descriptor.Connectors[0].Roles,
					ConnectorRoleDestination,
				)
			},
			want: ErrRoleEscalation,
		},
		{
			name: "record format escalation",
			mutate: func(descriptor *RuntimeDescriptor) {
				descriptor.Connectors[0].RecordFormats = append(
					descriptor.Connectors[0].RecordFormats,
					RecordFormatArrowIPCV1,
				)
			},
			want: ErrRecordFormatEscalation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := runtimeDescriptorForSpec(spec)
			test.mutate(&descriptor)
			if err := validateRuntimeDescriptor(spec, descriptor); !errors.Is(err, test.want) {
				t.Fatalf("validateRuntimeDescriptor error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRuntimeCapabilitiesRemainScopedToTheirManifestConnector(t *testing.T) {
	identity := testIdentity(9)
	spec := testSpec(identity)
	spec.ManifestConnectors = append(spec.ManifestConnectors, ConnectorCapabilities{
		ConnectorID: "query-engine",
		Capabilities: []Capability{
			{Name: "query", Version: 1},
		},
	})
	// The runtime advertises the same artifact-wide union as the manifest, but
	// moves query authority onto postgresql. A flat union check would accept it.
	descriptor := runtimeDescriptorForSpec(spec)
	descriptor.Connectors[0].Capabilities = append(
		descriptor.Connectors[0].Capabilities,
		Capability{Name: "query", Version: 1},
	)
	descriptor.Connectors[1].Capabilities = nil

	harness := newFakeHarness(descriptor)
	supervisor, err := NewSupervisor(harness, testOptions(t, harness))
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	_, err = supervisor.Acquire(context.Background(), spec)
	if !errors.Is(err, ErrCapabilityEscalation) {
		t.Fatalf("Acquire error = %v, want ErrCapabilityEscalation", err)
	}
}

func TestRuntimeMayAdvertisePerConnectorCapabilitySubset(t *testing.T) {
	identity := testIdentity(10)
	spec := testSpec(identity)
	spec.ManifestConnectors[0].Capabilities = append(
		spec.ManifestConnectors[0].Capabilities,
		Capability{Name: "cdc.snapshot", Version: 1},
	)
	descriptor := runtimeDescriptorForSpec(spec)
	descriptor.Connectors[0].Capabilities = descriptor.Connectors[0].Capabilities[:1]

	harness := newFakeHarness(descriptor)
	supervisor, err := NewSupervisor(harness, testOptions(t, harness))
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	lease, err := supervisor.Acquire(context.Background(), spec)
	if err != nil {
		t.Fatalf("Acquire rejected a valid capability subset: %v", err)
	}
	lease.Release()
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
}

func TestInvalidNonceProofFailsClosed(t *testing.T) {
	identity := testIdentity(3)
	spec := testSpec(identity)
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	harness.invalidProof = true
	supervisor, err := NewSupervisor(harness, testOptions(t, harness))
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	_, err = supervisor.Acquire(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "invalid launch-token proof") {
		t.Fatalf("Acquire error = %v, want invalid proof", err)
	}
	if instance := harness.lastInstance(); instance.process.terminateCalls() != 1 {
		t.Fatalf("invalid-proof process terminate calls = %d, want 1", instance.process.terminateCalls())
	}
}

func TestStartupTimeoutTerminatesUnauthenticatedProcess(t *testing.T) {
	identity := testIdentity(8)
	spec := testSpec(identity)
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	harness.blockDial = true
	options := testOptions(t, harness)
	options.StartupTimeout = 20 * time.Millisecond
	supervisor, err := NewSupervisor(harness, options)
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	_, err = supervisor.Acquire(context.Background(), spec)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire error = %v, want context deadline exceeded", err)
	}
	instance := harness.lastInstance()
	if instance.process.terminateCalls() != 1 {
		t.Fatalf("timed-out process terminate calls = %d, want 1", instance.process.terminateCalls())
	}
}

func TestCrashInvalidatesLeaseAndDoesNotReplayIt(t *testing.T) {
	identity := testIdentity(4)
	spec := testSpec(identity)
	clock := &fakeClock{now: time.Unix(100, 0)}
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	options := testOptions(t, harness)
	options.Clock = clock
	options.InitialBackoff = time.Second
	options.MaximumBackoff = time.Second
	supervisor, err := NewSupervisor(harness, options)
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}

	lease, err := supervisor.Acquire(context.Background(), spec)
	if err != nil {
		t.Fatalf("Acquire returned an error: %v", err)
	}
	firstGeneration := lease.Generation()
	harness.lastInstance().process.exit(ProcessExit{ExitCode: 17, Err: errors.New("crash")})
	select {
	case <-lease.Done():
	case <-time.After(time.Second):
		t.Fatal("crash did not invalidate lease")
	}
	if _, err := lease.Client(); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("Client error after crash = %v, want ErrLeaseInvalid", err)
	}
	if _, err := supervisor.Acquire(context.Background(), spec); !errors.Is(err, ErrBackoff) {
		t.Fatalf("Acquire during backoff error = %v, want ErrBackoff", err)
	}

	clock.Advance(time.Second)
	replacement, err := supervisor.Acquire(context.Background(), spec)
	if err != nil {
		t.Fatalf("Acquire after backoff returned an error: %v", err)
	}
	if replacement.Generation() == firstGeneration {
		t.Fatalf("replacement reused generation %d", firstGeneration)
	}
	if harness.startCount() != 2 {
		t.Fatalf("launcher starts = %d, want 2", harness.startCount())
	}
	if _, err := lease.Client(); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("old lease rebound after restart: %v", err)
	}
	replacement.Release()
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
}

func TestCircuitBreakerOpensAfterBoundedFailures(t *testing.T) {
	identity := testIdentity(5)
	spec := testSpec(identity)
	clock := &fakeClock{now: time.Unix(200, 0)}
	harness := newFakeHarness(RuntimeDescriptor{Identity: identity})
	verifier := &fakeVerifier{err: errors.New("digest unavailable")}
	options := testOptions(t, harness)
	options.Clock = clock
	options.Verifier = verifier
	options.InitialBackoff = time.Second
	options.MaximumBackoff = 2 * time.Second
	options.CircuitFailures = 2
	options.CircuitOpenFor = time.Minute
	supervisor, err := NewSupervisor(harness, options)
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}

	if _, err := supervisor.Acquire(context.Background(), spec); !errors.Is(err, ErrBackoff) {
		t.Fatalf("first failure = %v, want ErrBackoff", err)
	}
	clock.Advance(time.Second)
	if _, err := supervisor.Acquire(context.Background(), spec); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("second failure = %v, want ErrCircuitOpen", err)
	}
	snapshot, _ := supervisor.Snapshot(identity)
	if snapshot.State != StateCircuitOpen || snapshot.ConsecutiveFailures != 2 {
		t.Fatalf("unexpected circuit snapshot: %+v", snapshot)
	}
	if !supervisor.ResetCircuit(identity) {
		t.Fatal("ResetCircuit returned false")
	}
	snapshot, _ = supervisor.Snapshot(identity)
	if snapshot.State != StateStopped || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("unexpected snapshot after reset: %+v", snapshot)
	}
}

func TestDrainWaitsForLeasesThenShutsDown(t *testing.T) {
	identity := testIdentity(6)
	spec := testSpec(identity)
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	supervisor, err := NewSupervisor(harness, testOptions(t, harness))
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	lease, err := supervisor.Acquire(context.Background(), spec)
	if err != nil {
		t.Fatalf("Acquire returned an error: %v", err)
	}
	instance := harness.lastInstance()
	drained := make(chan error, 1)
	go func() {
		drained <- supervisor.Drain(context.Background(), identity)
	}()
	select {
	case <-instance.drainCalled:
	case <-time.After(time.Second):
		t.Fatal("Drain RPC was not called")
	}
	select {
	case <-instance.shutdownCalled:
		t.Fatal("Shutdown ran while a lease was still held")
	default:
	}

	lease.Release()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("Drain returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain did not finish")
	}
	if got := instance.eventsSnapshot(); !orderedEvents(got, "drain", "shutdown") {
		t.Fatalf("events %v do not contain drain before shutdown", got)
	}
	if instance.process.terminateCalls() != 0 || instance.process.killCalls() != 0 {
		t.Fatalf("graceful shutdown escalated: terminate=%d kill=%d",
			instance.process.terminateCalls(), instance.process.killCalls())
	}
	snapshot, _ := supervisor.Snapshot(identity)
	if snapshot.State != StateStopped || snapshot.References != 0 {
		t.Fatalf("unexpected drained snapshot: %+v", snapshot)
	}
}

func TestDrainEscalatesToProcessGroupTermination(t *testing.T) {
	identity := testIdentity(7)
	spec := testSpec(identity)
	harness := newFakeHarness(runtimeDescriptorForSpec(spec))
	harness.shutdownExits = false
	harness.terminateExits = true
	options := testOptions(t, harness)
	options.ShutdownTimeout = time.Millisecond
	options.TerminateTimeout = time.Second
	supervisor, err := NewSupervisor(harness, options)
	if err != nil {
		t.Fatalf("NewSupervisor returned an error: %v", err)
	}
	lease, err := supervisor.Acquire(context.Background(), spec)
	if err != nil {
		t.Fatalf("Acquire returned an error: %v", err)
	}
	instance := harness.lastInstance()
	lease.Release()
	if err := supervisor.Drain(context.Background(), identity); err != nil {
		t.Fatalf("Drain returned an error: %v", err)
	}
	if instance.process.terminateCalls() != 1 || instance.process.killCalls() != 0 {
		t.Fatalf("escalation calls: terminate=%d kill=%d, want 1/0",
			instance.process.terminateCalls(), instance.process.killCalls())
	}
	if got := instance.eventsSnapshot(); !orderedEvents(got, "drain", "shutdown", "terminate") {
		t.Fatalf("events %v are out of order", got)
	}
}

func TestSanitizeEnvironmentRequiresExplicitAllowlist(t *testing.T) {
	got := SanitizeEnvironment([]string{
		"PATH=/bin",
		"AWS_SECRET_ACCESS_KEY=secret",
		"PLUGIN_SAFE=value",
		"PEERDB_PLUGIN_SOCKET=/attacker/socket",
		"PEERDB_PLUGIN_LAUNCH_TOKEN_FD=99",
		"MALFORMED",
	}, []string{"PLUGIN_SAFE", "PEERDB_PLUGIN_SOCKET", "PEERDB_PLUGIN_LAUNCH_TOKEN_FD"})
	if !slices.Contains(got, "PATH=/bin") || !slices.Contains(got, "PLUGIN_SAFE=value") {
		t.Fatalf("allowed values missing from %v", got)
	}
	for _, entry := range got {
		if strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY=") || strings.HasPrefix(entry, "PEERDB_PLUGIN_") {
			t.Fatalf("secret or reserved protocol variable leaked in %v", got)
		}
	}
}

func TestFileVerifierChecksDigestAndExecutableMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin")
	contents := []byte("test plugin artifact")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatalf("write plugin artifact: %v", err)
	}
	digest := sha256.Sum256(contents)
	if err := (FileVerifier{}).Verify(context.Background(), path, digest); err != nil {
		t.Fatalf("Verify rejected matching artifact: %v", err)
	}
	digest[0] ^= 0xff
	if err := (FileVerifier{}).Verify(context.Background(), path, digest); err == nil {
		t.Fatal("Verify accepted the wrong digest")
	}
}

func TestRuntimeRootRejectsSymlinkAndEnforcesPrivateMode(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "runtime")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	supervisor := &Supervisor{options: Options{RuntimeRoot: root}}
	runtimeDir, err := supervisor.createRuntimeDirectory()
	if err != nil {
		t.Fatalf("createRuntimeDirectory: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(root)
		if statErr != nil {
			t.Fatalf("stat runtime root: %v", statErr)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("runtime root mode = %o, want 700", got)
		}
	}
	if err := os.RemoveAll(runtimeDir); err != nil {
		t.Fatalf("remove runtime directory: %v", err)
	}

	realRoot := filepath.Join(parent, "real-runtime")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatalf("create real runtime root: %v", err)
	}
	symlinkRoot := filepath.Join(parent, "runtime-link")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	supervisor.options.RuntimeRoot = symlinkRoot
	if _, err := supervisor.createRuntimeDirectory(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink runtime root error = %v, want symbolic-link rejection", err)
	}
}

func TestSupervisorRejectsSharedOrFilesystemRuntimeRoot(t *testing.T) {
	harness := newFakeHarness(RuntimeDescriptor{})
	for _, root := range []string{
		filepath.Clean(os.TempDir()),
		filepath.VolumeName(os.TempDir()) + string(os.PathSeparator),
	} {
		if _, err := NewSupervisor(harness, Options{RuntimeRoot: root}); err == nil {
			t.Fatalf("NewSupervisor accepted unsafe runtime root %q", root)
		}
	}
}

func testIdentity(seed byte) Identity {
	var digest [32]byte
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return Identity{ID: "io.peerdb.test", Version: "1.0.0", SHA256: digest}
}

func testSpec(identity Identity) Spec {
	return Spec{
		Identity:             identity,
		Executable:           filepath.Join(os.TempDir(), "plugins", identity.ID),
		Platform:             "test/architecture",
		Protocol:             ProtocolRange{Major: 1, MinimumMinor: 0, MaximumMinor: 4},
		ManifestCapabilities: []Capability{{Name: "control", Version: 1}},
		ManifestConnectors: []ConnectorCapabilities{
			{
				ConnectorID: "postgresql",
				Roles:       []ConnectorRole{ConnectorRoleSource},
				Capabilities: []Capability{
					{Name: "cdc.source", Version: 1},
				},
				RecordFormats: []RecordFormat{RecordFormatQValueProtoV1},
			},
		},
	}
}

func runtimeDescriptorForSpec(spec Spec) RuntimeDescriptor {
	return RuntimeDescriptor{
		Identity:     spec.Identity,
		Platform:     spec.Platform,
		Protocol:     spec.Protocol,
		Capabilities: slices.Clone(spec.ManifestCapabilities),
		Connectors:   cloneConnectorCapabilities(spec.ManifestConnectors),
	}
}

func testOptions(t *testing.T, launcher Launcher) Options {
	t.Helper()
	return Options{
		RuntimeRoot:      t.TempDir(),
		StartupTimeout:   time.Second,
		ShutdownTimeout:  10 * time.Millisecond,
		TerminateTimeout: 10 * time.Millisecond,
		KillTimeout:      10 * time.Millisecond,
		InitialBackoff:   time.Second,
		MaximumBackoff:   time.Minute,
		CircuitFailures:  5,
		CircuitOpenFor:   time.Minute,
		HealthyAfter:     time.Minute,
		Environment: []string{
			"PATH=/safe/bin",
			"AWS_SECRET_ACCESS_KEY=secret",
			"UNRELATED=value",
		},
		Random:   &deterministicReader{},
		Verifier: &fakeVerifier{},
		Launcher: launcher,
	}
}

type fakeVerifier struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (v *fakeVerifier) Verify(context.Context, string, [32]byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	return v.err
}

type deterministicReader struct {
	mu   sync.Mutex
	next byte
}

func (r *deterministicReader) Read(target []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range target {
		r.next++
		target[index] = r.next
	}
	return len(target), nil
}

var _ io.Reader = (*deterministicReader)(nil)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type fakeHarness struct {
	mu sync.Mutex

	descriptor     RuntimeDescriptor
	invalidProof   bool
	blockDial      bool
	shutdownExits  bool
	terminateExits bool
	nextPID        int
	requests       []LaunchRequest
	instances      map[string]*fakeInstance
}

func newFakeHarness(descriptor RuntimeDescriptor) *fakeHarness {
	return &fakeHarness{
		descriptor:     descriptor,
		shutdownExits:  true,
		terminateExits: true,
		nextPID:        1000,
		instances:      make(map[string]*fakeInstance),
	}
}

func (h *fakeHarness) Start(_ context.Context, request LaunchRequest) (Process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextPID++
	instance := &fakeInstance{
		harness:        h,
		request:        request,
		drainCalled:    make(chan struct{}),
		shutdownCalled: make(chan struct{}),
	}
	instance.process = &fakeProcess{
		harness:  h,
		instance: instance,
		pid:      h.nextPID,
		done:     make(chan struct{}),
	}
	h.requests = append(h.requests, request)
	h.instances[request.SocketPath] = instance
	return instance.process, nil
}

func (h *fakeHarness) Dial(ctx context.Context, socketPath string) (Client, error) {
	h.mu.Lock()
	instance, ok := h.instances[socketPath]
	block := h.blockDial
	h.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown fake socket")
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &fakeClient{instance: instance}, nil
}

func (h *fakeHarness) startCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

func (h *fakeHarness) lastRequest() LaunchRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests[len(h.requests)-1]
}

func (h *fakeHarness) lastInstance() *fakeInstance {
	h.mu.Lock()
	defer h.mu.Unlock()
	request := h.requests[len(h.requests)-1]
	return h.instances[request.SocketPath]
}

type fakeInstance struct {
	harness *fakeHarness
	request LaunchRequest
	process *fakeProcess

	drainOnce      sync.Once
	shutdownOnce   sync.Once
	drainCalled    chan struct{}
	shutdownCalled chan struct{}
	eventsMu       sync.Mutex
	events         []string
}

func (i *fakeInstance) record(event string) {
	i.eventsMu.Lock()
	i.events = append(i.events, event)
	i.eventsMu.Unlock()
}

func (i *fakeInstance) eventsSnapshot() []string {
	i.eventsMu.Lock()
	defer i.eventsMu.Unlock()
	return slices.Clone(i.events)
}

type fakeClient struct {
	instance *fakeInstance
}

func (c *fakeClient) Handshake(_ context.Context, request HandshakeRequest) (HandshakeResponse, error) {
	proof, err := ComputeNonceProof(c.instance.request.LaunchToken[:], request.Nonce)
	if err != nil {
		return HandshakeResponse{}, err
	}
	if c.instance.harness.invalidProof {
		proof[0] ^= 0xff
	}
	return HandshakeResponse{
		Descriptor: c.instance.harness.descriptor,
		NonceProof: proof,
	}, nil
}

func (c *fakeClient) Health(context.Context) error {
	c.instance.record("health")
	return nil
}

func (c *fakeClient) Drain(context.Context) error {
	c.instance.record("drain")
	c.instance.drainOnce.Do(func() { close(c.instance.drainCalled) })
	return nil
}

func (c *fakeClient) Shutdown(context.Context) error {
	c.instance.record("shutdown")
	c.instance.shutdownOnce.Do(func() { close(c.instance.shutdownCalled) })
	if c.instance.harness.shutdownExits {
		c.instance.process.exit(ProcessExit{ExitCode: 0})
	}
	return nil
}

func (c *fakeClient) Close() error {
	c.instance.record("close")
	return nil
}

type fakeProcess struct {
	harness  *fakeHarness
	instance *fakeInstance
	pid      int
	done     chan struct{}
	exitOnce sync.Once

	mu             sync.Mutex
	exitResult     ProcessExit
	terminateCount int
	killCount      int
}

func (p *fakeProcess) PID() int {
	return p.pid
}

func (p *fakeProcess) Done() <-chan struct{} {
	return p.done
}

func (p *fakeProcess) Exit() ProcessExit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitResult
}

func (p *fakeProcess) TerminateGroup() error {
	p.mu.Lock()
	p.terminateCount++
	p.mu.Unlock()
	p.instance.record("terminate")
	if p.harness.terminateExits {
		p.exit(ProcessExit{ExitCode: 143})
	}
	return nil
}

func (p *fakeProcess) KillGroup() error {
	p.mu.Lock()
	p.killCount++
	p.mu.Unlock()
	p.instance.record("kill")
	p.exit(ProcessExit{ExitCode: 137})
	return nil
}

func (p *fakeProcess) exit(result ProcessExit) {
	p.exitOnce.Do(func() {
		p.mu.Lock()
		p.exitResult = result
		p.mu.Unlock()
		close(p.done)
	})
}

func (p *fakeProcess) terminateCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.terminateCount
}

func (p *fakeProcess) killCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killCount
}

func orderedEvents(events []string, wanted ...string) bool {
	position := 0
	for _, event := range events {
		if position < len(wanted) && event == wanted[position] {
			position++
		}
	}
	return position == len(wanted)
}
