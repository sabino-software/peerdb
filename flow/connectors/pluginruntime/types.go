// Package pluginruntime supervises out-of-process PeerDB connector plugins.
//
// The package deliberately depends on small protocol and process interfaces.
// Generated RPC clients can implement Client and Dialer without making the
// supervisor depend on a particular protocol revision.
package pluginruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	// LaunchTokenSize is 256 bits. Tokens are delivered through an inherited
	// anonymous pipe and must never be put in argv or the environment.
	LaunchTokenSize = 32
	// HandshakeNonceSize matches the launch token size and prevents proof replay.
	HandshakeNonceSize = 32
)

var (
	ErrClosed                 = errors.New("plugin supervisor is closed")
	ErrDraining               = errors.New("plugin is draining")
	ErrLeaseInvalid           = errors.New("plugin session lease is invalid")
	ErrBackoff                = errors.New("plugin restart is in backoff")
	ErrCircuitOpen            = errors.New("plugin restart circuit is open")
	ErrIdentityMismatch       = errors.New("plugin runtime identity does not match manifest")
	ErrPlatformMismatch       = errors.New("plugin runtime platform does not match manifest")
	ErrProtocolMismatch       = errors.New("plugin runtime protocol does not match manifest")
	ErrConnectorMismatch      = errors.New("plugin runtime connector identities do not match manifest")
	ErrCapabilityEscalation   = errors.New("plugin runtime advertised a capability absent from its manifest")
	ErrRoleEscalation         = errors.New("plugin runtime advertised a role absent from its manifest")
	ErrRecordFormatEscalation = errors.New("plugin runtime advertised a record format absent from its manifest")
)

// Identity is an immutable plugin artifact identity. A version without its
// digest is never sufficient to select executable bytes.
type Identity struct {
	ID      string
	Version string
	SHA256  [32]byte
}

// ParseIdentity creates an immutable identity from a SHA-256 digest. It
// accepts the manifest's canonical "sha256:<hex>" representation and the raw
// hexadecimal form used by lower-level protocol adapters.
func ParseIdentity(id, version, digest string) (Identity, error) {
	var sum [32]byte
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	decoded, err := hex.DecodeString(hexDigest)
	if err != nil || len(decoded) != len(sum) {
		return Identity{}, fmt.Errorf("invalid SHA-256 digest %q", digest)
	}
	copy(sum[:], decoded)
	identity := Identity{ID: id, Version: version, SHA256: sum}
	if err := identity.Validate(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (i Identity) Validate() error {
	if strings.TrimSpace(i.ID) == "" || i.ID != strings.TrimSpace(i.ID) {
		return errors.New("plugin ID is required")
	}
	if strings.ContainsAny(i.ID, "\x00\r\n") {
		return errors.New("plugin ID contains a prohibited character")
	}
	if strings.TrimSpace(i.Version) == "" || i.Version != strings.TrimSpace(i.Version) {
		return errors.New("plugin version is required")
	}
	if strings.ContainsAny(i.Version, "\x00\r\n") {
		return errors.New("plugin version contains a prohibited character")
	}
	var zero [32]byte
	if i.SHA256 == zero {
		return errors.New("plugin SHA-256 digest is required")
	}
	return nil
}

func (i Identity) Digest() string {
	return "sha256:" + i.DigestHex()
}

// DigestHex returns the lower-case digest bytes without an algorithm prefix.
// Use Digest for manifest, lockfile, and diagnostic representations.
func (i Identity) DigestHex() string {
	return hex.EncodeToString(i.SHA256[:])
}

func (i Identity) key() string {
	return i.ID + "\x00" + i.Version + "\x00" + i.Digest()
}

func (i Identity) String() string {
	return fmt.Sprintf("%s@%s#%s", i.ID, i.Version, i.Digest())
}

type Capability struct {
	Name    string
	Version uint32
}

// ProtocolVersion is one negotiated wire-protocol revision.
type ProtocolVersion struct {
	Major uint32
	Minor uint32
}

// ProtocolRange is an inclusive range of compatible minor revisions within
// one protocol major. A signed manifest's single certified minor is expressed
// as [0, certifiedMinor] by the manifest adapter.
type ProtocolRange struct {
	Major        uint32
	MinimumMinor uint32
	MaximumMinor uint32
}

func (p ProtocolRange) validate(scope string) error {
	if p.Major == 0 {
		return fmt.Errorf("%s protocol major is required", scope)
	}
	if p.MinimumMinor > p.MaximumMinor {
		return fmt.Errorf(
			"%s protocol minor range [%d, %d] is invalid",
			scope,
			p.MinimumMinor,
			p.MaximumMinor,
		)
	}
	return nil
}

func (p ProtocolRange) contains(version ProtocolVersion) bool {
	return version.Major == p.Major &&
		version.Minor >= p.MinimumMinor &&
		version.Minor <= p.MaximumMinor
}

func (p ProtocolRange) subsetOf(allowed ProtocolRange) bool {
	return p.Major == allowed.Major &&
		p.MinimumMinor >= allowed.MinimumMinor &&
		p.MaximumMinor <= allowed.MaximumMinor
}

type ConnectorRole uint8

const (
	ConnectorRoleSource ConnectorRole = iota + 1
	ConnectorRoleDestination
	ConnectorRoleQuery
)

func (r ConnectorRole) String() string {
	switch r {
	case ConnectorRoleSource:
		return "source"
	case ConnectorRoleDestination:
		return "destination"
	case ConnectorRoleQuery:
		return "query"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

func (r ConnectorRole) validate() error {
	switch r {
	case ConnectorRoleSource, ConnectorRoleDestination, ConnectorRoleQuery:
		return nil
	default:
		return fmt.Errorf("unknown connector role %d", r)
	}
}

type RecordFormat uint8

const (
	RecordFormatQValueProtoV1 RecordFormat = iota + 1
	RecordFormatArrowIPCV1
	RecordFormatPGTextV1
	RecordFormatPGCopyV1
	RecordFormatObjectRefV1
)

func (f RecordFormat) String() string {
	switch f {
	case RecordFormatQValueProtoV1:
		return "qvalue-proto-v1"
	case RecordFormatArrowIPCV1:
		return "arrow-ipc-v1"
	case RecordFormatPGTextV1:
		return "pg-text-v1"
	case RecordFormatPGCopyV1:
		return "pg-copy-v1"
	case RecordFormatObjectRefV1:
		return "object-ref-v1"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}

func (f RecordFormat) validate() error {
	switch f {
	case RecordFormatQValueProtoV1,
		RecordFormatArrowIPCV1,
		RecordFormatPGTextV1,
		RecordFormatPGCopyV1,
		RecordFormatObjectRefV1:
		return nil
	default:
		return fmt.Errorf("unknown record format %d", f)
	}
}

type Compression uint8

const (
	CompressionNone Compression = iota + 1
	CompressionGZIP
	CompressionZSTD
)

func (c Compression) String() string {
	switch c {
	case CompressionNone:
		return "none"
	case CompressionGZIP:
		return "gzip"
	case CompressionZSTD:
		return "zstd"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

func (c Compression) validate() error {
	switch c {
	case CompressionNone, CompressionGZIP, CompressionZSTD:
		return nil
	default:
		return fmt.Errorf("unknown compression %d", c)
	}
}

func (c Capability) validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("capability name is required")
	}
	if c.Name != strings.TrimSpace(c.Name) || strings.ContainsAny(c.Name, "\x00\r\n") {
		return fmt.Errorf("capability name %q contains a prohibited character", c.Name)
	}
	if c.Version == 0 {
		return fmt.Errorf("capability %q has unspecified version", c.Name)
	}
	return nil
}

// ConnectorCapabilities keeps capability authorization scoped to one
// connector descriptor. Capabilities from another connector in the same
// executable never authorize this connector.
type ConnectorCapabilities struct {
	ConnectorID   string
	Roles         []ConnectorRole
	Capabilities  []Capability
	RecordFormats []RecordFormat
}

func (c ConnectorCapabilities) validate(scope string) error {
	if strings.TrimSpace(c.ConnectorID) == "" {
		return fmt.Errorf("%s connector ID is required", scope)
	}
	if c.ConnectorID != strings.TrimSpace(c.ConnectorID) || strings.ContainsAny(c.ConnectorID, "\x00\r\n") {
		return fmt.Errorf("%s connector ID %q contains a prohibited character", scope, c.ConnectorID)
	}
	connectorScope := scope + " connector " + c.ConnectorID
	if err := validateRoleSet(connectorScope, c.Roles); err != nil {
		return err
	}
	if err := validateCapabilitySet(connectorScope, c.Capabilities); err != nil {
		return err
	}
	return validateRecordFormatSet(connectorScope, c.RecordFormats)
}

func (c ConnectorCapabilities) clone() ConnectorCapabilities {
	c.Roles = slices.Clone(c.Roles)
	c.Capabilities = slices.Clone(c.Capabilities)
	c.RecordFormats = slices.Clone(c.RecordFormats)
	return c
}

func validateRoleSet(scope string, roles []ConnectorRole) error {
	seen := make(map[ConnectorRole]struct{}, len(roles))
	for _, role := range roles {
		if err := role.validate(); err != nil {
			return fmt.Errorf("%s: %w", scope, err)
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("%s has duplicate connector role %s", scope, role)
		}
		seen[role] = struct{}{}
	}
	return nil
}

func validateRecordFormatSet(scope string, formats []RecordFormat) error {
	seen := make(map[RecordFormat]struct{}, len(formats))
	for _, format := range formats {
		if err := format.validate(); err != nil {
			return fmt.Errorf("%s: %w", scope, err)
		}
		if _, duplicate := seen[format]; duplicate {
			return fmt.Errorf("%s has duplicate record format %s", scope, format)
		}
		seen[format] = struct{}{}
	}
	return nil
}

func validateCapabilitySet(scope string, capabilities []Capability) error {
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if err := capability.validate(); err != nil {
			return fmt.Errorf("%s: %w", scope, err)
		}
		if _, ok := seen[capability.Name]; ok {
			return fmt.Errorf("%s has duplicate capability name %s", scope, capability.Name)
		}
		seen[capability.Name] = struct{}{}
	}
	return nil
}

// Spec is the signed-manifest information needed to start one artifact.
// Executable must be an absolute path; the supervisor never searches PATH and
// never invokes a shell. ManifestCapabilities is reserved for capabilities
// that truly apply to the entire process; connector capabilities must remain
// in ManifestConnectors so one connector cannot borrow another's authority.
type Spec struct {
	Identity             Identity
	Executable           string
	Platform             string
	Protocol             ProtocolRange
	ManifestCapabilities []Capability
	ManifestConnectors   []ConnectorCapabilities
}

func (s Spec) validate() error {
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(s.Executable) {
		return fmt.Errorf("plugin executable must be an absolute path: %q", s.Executable)
	}
	if strings.TrimSpace(s.Platform) == "" || s.Platform != strings.TrimSpace(s.Platform) ||
		strings.ContainsAny(s.Platform, "\x00\r\n") {
		return fmt.Errorf("plugin platform is invalid: %q", s.Platform)
	}
	if err := s.Protocol.validate("manifest"); err != nil {
		return err
	}
	if err := validateCapabilitySet("manifest plugin", s.ManifestCapabilities); err != nil {
		return err
	}
	if len(s.ManifestConnectors) == 0 {
		return errors.New("manifest must declare at least one connector")
	}
	seenConnectors := make(map[string]struct{}, len(s.ManifestConnectors))
	for _, connector := range s.ManifestConnectors {
		if err := connector.validate("manifest"); err != nil {
			return err
		}
		if _, ok := seenConnectors[connector.ConnectorID]; ok {
			return fmt.Errorf("manifest has duplicate connector ID %s", connector.ConnectorID)
		}
		seenConnectors[connector.ConnectorID] = struct{}{}
	}
	return nil
}

func (s Spec) clone() Spec {
	s.ManifestCapabilities = slices.Clone(s.ManifestCapabilities)
	s.ManifestConnectors = cloneConnectorCapabilities(s.ManifestConnectors)
	return s
}

func (s Spec) equal(other Spec) bool {
	if s.Identity != other.Identity || s.Executable != other.Executable ||
		s.Platform != other.Platform || s.Protocol != other.Protocol {
		return false
	}
	if !equalCapabilitySets(s.ManifestCapabilities, other.ManifestCapabilities) {
		return false
	}
	left := normalizedConnectorCapabilities(s.ManifestConnectors)
	right := normalizedConnectorCapabilities(other.ManifestConnectors)
	return slices.EqualFunc(left, right, func(left, right ConnectorCapabilities) bool {
		return left.ConnectorID == right.ConnectorID &&
			slices.Equal(left.Roles, right.Roles) &&
			slices.Equal(left.Capabilities, right.Capabilities) &&
			slices.Equal(left.RecordFormats, right.RecordFormats)
	})
}

func cloneConnectorCapabilities(input []ConnectorCapabilities) []ConnectorCapabilities {
	result := make([]ConnectorCapabilities, len(input))
	for index, connector := range input {
		result[index] = connector.clone()
	}
	return result
}

func normalizedConnectorCapabilities(input []ConnectorCapabilities) []ConnectorCapabilities {
	result := cloneConnectorCapabilities(input)
	for index := range result {
		slices.Sort(result[index].Roles)
		slices.SortFunc(result[index].Capabilities, compareCapability)
		slices.Sort(result[index].RecordFormats)
	}
	slices.SortFunc(result, func(left, right ConnectorCapabilities) int {
		return strings.Compare(left.ConnectorID, right.ConnectorID)
	})
	return result
}

func equalCapabilitySets(left, right []Capability) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.SortFunc(left, compareCapability)
	slices.SortFunc(right, compareCapability)
	return slices.Equal(left, right)
}

func compareCapability(left, right Capability) int {
	if result := strings.Compare(left.Name, right.Name); result != 0 {
		return result
	}
	if left.Version < right.Version {
		return -1
	}
	if left.Version > right.Version {
		return 1
	}
	return 0
}

func capabilityKey(capability Capability) string {
	return fmt.Sprintf("%s@%d", capability.Name, capability.Version)
}

type RuntimeDescriptor struct {
	Identity Identity
	Platform string
	Protocol ProtocolRange
	// Capabilities contains only process-wide capabilities. Connector-scoped
	// capabilities must be advertised under Connectors.
	Capabilities []Capability
	Connectors   []ConnectorCapabilities
}

type HandshakeRequest struct {
	Nonce    []byte
	Expected Spec
}

type HandshakeResponse struct {
	Descriptor           RuntimeDescriptor
	NonceProof           []byte
	Protocol             ProtocolVersion
	Compression          Compression
	RecordFormats        []RecordFormat
	MaximumFrameBytes    uint64
	HostCallbackProtocol ProtocolVersion
	Features             []string
}

// Client is the authenticated control-plane connection to one process.
// Active replication/query operations live above this package; a process crash
// invalidates their SessionLease and is never replayed here. Close must be
// idempotent because process exit and supervisor shutdown can race.
type Client interface {
	Handshake(context.Context, HandshakeRequest) (HandshakeResponse, error)
	Health(context.Context) error
	Drain(context.Context) error
	Shutdown(context.Context) error
	Close() error
}

type Dialer interface {
	// Dial must connect only to the Unix-domain socket at the supplied path. It
	// must not fall back to TCP or follow an endpoint supplied by the plugin.
	Dial(context.Context, string) (Client, error)
}

type ArtifactVerifier interface {
	Verify(context.Context, string, [32]byte) error
}

// Clock is intentionally tiny so restart backoff and circuit behavior can be
// tested without sleeping.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

type State uint8

const (
	StateStopped State = iota
	StateStarting
	StateRunning
	StateDraining
	StateStopping
	StateBackoff
	StateCircuitOpen
)

func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateDraining:
		return "draining"
	case StateStopping:
		return "stopping"
	case StateBackoff:
		return "backoff"
	case StateCircuitOpen:
		return "circuit_open"
	default:
		return "unknown"
	}
}

type Snapshot struct {
	Identity            Identity
	State               State
	Generation          uint64
	References          int
	ConsecutiveFailures int
	RetryAt             time.Time
	LastError           error
}

// UnavailableError tells callers when a new session can be attempted. The
// caller or Temporal owns retry timing; the supervisor never replays an active
// operation.
type UnavailableError struct {
	Identity Identity
	State    State
	RetryAt  time.Time
	Cause    error
}

func (e *UnavailableError) Error() string {
	if e.RetryAt.IsZero() {
		return fmt.Sprintf("plugin %s unavailable in state %s: %v", e.Identity, e.State, e.Cause)
	}
	return fmt.Sprintf("plugin %s unavailable in state %s until %s: %v",
		e.Identity, e.State, e.RetryAt.Format(time.RFC3339Nano), e.Cause)
}

func (e *UnavailableError) Unwrap() error {
	return e.Cause
}

type Options struct {
	RuntimeRoot      string
	StartupTimeout   time.Duration
	ShutdownTimeout  time.Duration
	TerminateTimeout time.Duration
	KillTimeout      time.Duration
	InitialBackoff   time.Duration
	MaximumBackoff   time.Duration
	CircuitFailures  int
	CircuitOpenFor   time.Duration
	HealthyAfter     time.Duration
	Environment      []string
	EnvironmentAllow []string
	Random           io.Reader
	Clock            Clock
	Verifier         ArtifactVerifier
	Launcher         Launcher
}

func (o Options) withDefaults() Options {
	if o.RuntimeRoot == "" {
		o.RuntimeRoot = filepath.Join(os.TempDir(), "peerdb-plugin-runtime")
	}
	o.RuntimeRoot = filepath.Clean(o.RuntimeRoot)
	if o.StartupTimeout <= 0 {
		o.StartupTimeout = 30 * time.Second
	}
	if o.ShutdownTimeout <= 0 {
		o.ShutdownTimeout = 10 * time.Second
	}
	if o.TerminateTimeout <= 0 {
		o.TerminateTimeout = 5 * time.Second
	}
	if o.KillTimeout <= 0 {
		o.KillTimeout = 5 * time.Second
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = time.Second
	}
	if o.MaximumBackoff <= 0 {
		o.MaximumBackoff = time.Minute
	}
	if o.MaximumBackoff < o.InitialBackoff {
		o.MaximumBackoff = o.InitialBackoff
	}
	if o.CircuitFailures <= 0 {
		o.CircuitFailures = 5
	}
	if o.CircuitOpenFor <= 0 {
		o.CircuitOpenFor = 5 * time.Minute
	}
	if o.HealthyAfter <= 0 {
		o.HealthyAfter = time.Minute
	}
	if o.Environment == nil {
		o.Environment = os.Environ()
	}
	if o.Random == nil {
		o.Random = defaultRandomReader
	}
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.Verifier == nil {
		o.Verifier = FileVerifier{}
	}
	if o.Launcher == nil {
		o.Launcher = ExecLauncher{}
	}
	return o
}

func (o Options) validate() error {
	if !filepath.IsAbs(o.RuntimeRoot) {
		return fmt.Errorf("plugin runtime root must be absolute: %q", o.RuntimeRoot)
	}
	if filepath.Dir(o.RuntimeRoot) == o.RuntimeRoot {
		return fmt.Errorf("plugin runtime root must not be a filesystem root: %q", o.RuntimeRoot)
	}
	if o.RuntimeRoot == filepath.Clean(os.TempDir()) {
		return fmt.Errorf("plugin runtime root must be a dedicated directory, not the shared temporary root: %q", o.RuntimeRoot)
	}
	if o.Random == nil || o.Clock == nil || o.Verifier == nil || o.Launcher == nil {
		return errors.New("plugin supervisor dependencies are required")
	}
	return nil
}
