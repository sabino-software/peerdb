// Package pluginlock parses the deployment plugin lock and reconciles it with
// a discovered connector inventory. A discovered artifact is not authorized
// to run unless an enabled, digest-pinned lock entry matches it exactly.
package pluginlock

import "time"

const (
	// APIVersion is the only lock contract understood by this package.
	APIVersion = "peerdb.io/plugin-lock/v1alpha1"
	// Kind identifies a PeerDB deployment plugin lock.
	Kind = "PluginLock"
	// MaxBytes bounds memory use before YAML decoding.
	MaxBytes = 1 << 20
)

// State distinguishes future inventory from an artifact pinned for a
// deployment. Planned entries can never be enabled.
type State string

const (
	StatePlanned State = "planned"
	StateLocked  State = "locked"
)

// SourceType describes where an operator obtained an artifact. Source is
// provenance metadata; artifact identity is always the SHA-256 digest.
type SourceType string

const (
	SourceLocal         SourceType = "local"
	SourceOCI           SourceType = "oci"
	SourceGitHubRelease SourceType = "github-release"
)

// Lock is an immutable, validated deployment inventory. All collection
// accessors return copies.
type Lock struct {
	schema   string
	metadata Metadata
	plugins  []Entry
}

// Metadata describes how the lock was generated. It is deliberately excluded
// from the worker readiness hash.
type Metadata struct {
	generatedBy    string
	generatedAt    time.Time
	hasGeneratedAt bool
}

// Entry is one immutable desired plugin version.
type Entry struct {
	id                string
	version           string
	state             State
	enabled           bool
	platform          string
	hasPlatform       bool
	digest            string
	hasDigest         bool
	manifestDigest    string
	hasManifestDigest bool
	protocol          ProtocolVersion
	hasProtocol       bool
	trustIdentity     string
	hasTrustIdentity  bool
	source            Source
	connectors        []string
}

// ProtocolVersion pins the exact process protocol declared by the signed
// manifest. Major and minor are independent from the plugin release version.
type ProtocolVersion struct {
	major int
	minor int
}

// Source records artifact provenance without participating in runtime
// identity or readiness hashing.
type Source struct {
	typeName  SourceType
	reference string
}

func (l *Lock) Schema() string {
	if l == nil {
		return ""
	}
	return l.schema
}

func (l *Lock) APIVersion() string {
	if l == nil {
		return ""
	}
	return APIVersion
}

func (l *Lock) Kind() string {
	if l == nil {
		return ""
	}
	return Kind
}

func (l *Lock) Metadata() Metadata {
	if l == nil {
		return Metadata{}
	}
	return l.metadata
}

// Plugins returns lock entries in document order as independent copies.
func (l *Lock) Plugins() []Entry {
	if l == nil {
		return nil
	}
	entries := make([]Entry, len(l.plugins))
	for index, entry := range l.plugins {
		entries[index] = cloneEntry(entry)
	}
	return entries
}

func (m Metadata) GeneratedBy() string {
	return m.generatedBy
}

// GeneratedAt returns the generation time and whether it was present. The
// canonical schema permits null for hand-authored templates.
func (m Metadata) GeneratedAt() (time.Time, bool) {
	return m.generatedAt, m.hasGeneratedAt
}

func (e Entry) ID() string {
	return e.id
}

func (e Entry) Version() string {
	return e.version
}

func (e Entry) Key() string {
	return e.id + "@" + e.version
}

func (e Entry) State() State {
	return e.state
}

func (e Entry) Enabled() bool {
	return e.enabled
}

func (e Entry) Platform() (string, bool) {
	return e.platform, e.hasPlatform
}

func (e Entry) Digest() (string, bool) {
	return e.digest, e.hasDigest
}

func (e Entry) ManifestDigest() (string, bool) {
	return e.manifestDigest, e.hasManifestDigest
}

func (e Entry) Protocol() (ProtocolVersion, bool) {
	return e.protocol, e.hasProtocol
}

func (e Entry) TrustIdentity() (string, bool) {
	return e.trustIdentity, e.hasTrustIdentity
}

func (e Entry) Source() Source {
	return e.source
}

func (e Entry) Connectors() []string {
	return append([]string(nil), e.connectors...)
}

func (s Source) Type() SourceType {
	return s.typeName
}

func (s Source) Reference() string {
	return s.reference
}

func (p ProtocolVersion) Major() int {
	return p.major
}

func (p ProtocolVersion) Minor() int {
	return p.minor
}

func cloneEntry(entry Entry) Entry {
	clone := entry
	clone.connectors = append([]string(nil), entry.connectors...)
	return clone
}
