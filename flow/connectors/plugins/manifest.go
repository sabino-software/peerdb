// Package plugins defines the on-disk contract used to inventory and discover
// external PeerDB connector processes. It deliberately does not use Go's
// plugin package: runnable entrypoints are standalone, versioned processes.
package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	// ManifestFilename is the only filename considered during discovery.
	ManifestFilename = "peerdb-plugin.yaml"
	// APIVersion is the shared manifest schema version.
	APIVersion = "peerdb.io/plugin/v1alpha1"
	// ManifestKind identifies a connector plugin manifest.
	ManifestKind = "ConnectorPlugin"
	// RuntimeModeProcess is the only v1alpha1 runtime. Native shared libraries
	// are intentionally not an ABI.
	RuntimeModeProcess = "process"
)

type Lifecycle string

const (
	LifecyclePlanned      Lifecycle = "planned"
	LifecycleExperimental Lifecycle = "experimental"
	LifecycleBeta         Lifecycle = "beta"
	LifecycleStable       Lifecycle = "stable"
	LifecycleDeprecated   Lifecycle = "deprecated"
)

type ArtifactStatus string

const (
	ArtifactStatusUnbuilt   ArtifactStatus = "unbuilt"
	ArtifactStatusBuilt     ArtifactStatus = "built"
	ArtifactStatusPublished ArtifactStatus = "published"
)

type Role string

const (
	RoleSource      Role = "source"
	RoleDestination Role = "destination"
	RoleQuery       Role = "query"
)

type RecordFormat string

const (
	RecordFormatQValueProto RecordFormat = "qvalue-proto-v1"
	RecordFormatArrowIPC    RecordFormat = "arrow-ipc-v1"
	RecordFormatPGText      RecordFormat = "pg-text-v1"
	RecordFormatPGCopy      RecordFormat = "pg-copy-v1"
	RecordFormatObjectRef   RecordFormat = "object-ref-v1"
)

const (
	CapabilityControl                         = "control"
	CapabilitySchemaDiscovery                 = "schema.discovery"
	CapabilitySchemaTables                    = "schema.tables"
	CapabilityCDCSource                       = "cdc.source"
	CapabilityCDCDestination                  = "cdc.destination"
	CapabilityCDCNormalize                    = "cdc.normalize"
	CapabilityCDCSnapshot                     = "cdc.snapshot"
	CapabilityQRepSourceRows                  = "qrep.source.rows"
	CapabilityQRepSourceObjects               = "qrep.source.objects"
	CapabilityQRepDestinationRows             = "qrep.destination.rows"
	CapabilityQRepDestinationObjects          = "qrep.destination.objects"
	CapabilityQRepDestinationConsolidate      = "qrep.destination.consolidate"
	CapabilityTableLifecycleNormalized        = "table.lifecycle.normalized"
	CapabilityTableLifecycleCreateExisting    = "table.lifecycle.create-from-existing"
	CapabilityTableLifecycleRename            = "table.lifecycle.rename"
	CapabilityTableLifecycleRenameSoftDelete  = "table.lifecycle.rename-soft-delete"
	CapabilityTableLifecycleRaw               = "table.lifecycle.raw"
	CapabilityDiagnosticsStats                = "diagnostics.stats"
	CapabilityDiagnosticsVersion              = "diagnostics.version"
	CapabilityDiagnosticsLogRetention         = "diagnostics.log-retention"
	CapabilityDiagnosticsCommitLag            = "diagnostics.commit-lag"
	CapabilityDiagnosticsClockOffset          = "diagnostics.clock-offset"
	CapabilityDiagnosticsDatabaseVariant      = "diagnostics.database-variant"
	CapabilityDiagnosticsReplicationMechanism = "diagnostics.replication-mechanism"
	CapabilityDiagnosticsTableSize            = "diagnostics.table-size"
	CapabilityQuery                           = "query"
)

// CapabilityDefinition is one Core-owned capability registry entry.
type CapabilityDefinition struct {
	Name         string
	Version      int
	RequiredRole Role
}

var v1CapabilityDefinitions = []CapabilityDefinition{
	{Name: CapabilityControl, Version: 1},
	{Name: CapabilitySchemaDiscovery, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilitySchemaTables, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityCDCSource, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityCDCDestination, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityCDCNormalize, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityCDCSnapshot, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityQRepSourceRows, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityQRepSourceObjects, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityQRepDestinationRows, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityQRepDestinationObjects, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityQRepDestinationConsolidate, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityTableLifecycleNormalized, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityTableLifecycleCreateExisting, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityTableLifecycleRename, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityTableLifecycleRenameSoftDelete, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityTableLifecycleRaw, Version: 1, RequiredRole: RoleDestination},
	{Name: CapabilityDiagnosticsStats, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityDiagnosticsVersion, Version: 1},
	{Name: CapabilityDiagnosticsLogRetention, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityDiagnosticsCommitLag, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityDiagnosticsClockOffset, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityDiagnosticsDatabaseVariant, Version: 1},
	{Name: CapabilityDiagnosticsReplicationMechanism, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityDiagnosticsTableSize, Version: 1, RequiredRole: RoleSource},
	{Name: CapabilityQuery, Version: 1, RequiredRole: RoleQuery},
}

// V1CapabilityRegistry returns a copy of the stable capability allowlist.
func V1CapabilityRegistry() []CapabilityDefinition {
	return append([]CapabilityDefinition(nil), v1CapabilityDefinitions...)
}

// Manifest mirrors schemas/plugin-manifest.schema.json in peerdb-plugins.
type Manifest struct {
	Schema     string         `yaml:"$schema"`
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   PluginMetadata `yaml:"metadata"`
	Spec       PluginSpec     `yaml:"spec"`
	Artifact   ArtifactSpec   `yaml:"artifact"`
}

type PluginMetadata struct {
	ID          string `yaml:"id"`
	DisplayName string `yaml:"displayName"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Vendor      string `yaml:"vendor"`
	Homepage    string `yaml:"homepage"`
	License     string `yaml:"license"`
}

type PluginSpec struct {
	Lifecycle    Lifecycle        `yaml:"lifecycle"`
	Protocol     ProtocolVersion  `yaml:"protocol"`
	CoreVersions VersionRange     `yaml:"coreVersions"`
	Runtime      RuntimeSpec      `yaml:"runtime"`
	Connectors   []ConnectorSpec  `yaml:"connectors"`
	Dependencies []DependencySpec `yaml:"dependencies"`
}

type ProtocolVersion struct {
	Major int `yaml:"major"`
	Minor int `yaml:"minor"`
}

type VersionRange struct {
	Minimum          string `yaml:"minimum"`
	MaximumExclusive string `yaml:"maximumExclusive"`
}

type RuntimeSpec struct {
	Mode       string  `yaml:"mode"`
	Entrypoint *string `yaml:"entrypoint"`
}

type ConnectorSpec struct {
	ID            string          `yaml:"id"`
	DisplayName   string          `yaml:"displayName"`
	Description   string          `yaml:"description"`
	LegacyDBTypes []string        `yaml:"legacyDbTypes"`
	Roles         []Role          `yaml:"roles"`
	Capabilities  []CapabilityRef `yaml:"capabilities"`
	RecordFormats []RecordFormat  `yaml:"recordFormats"`
	Stability     Lifecycle       `yaml:"stability"`
	Config        ConfigSpec      `yaml:"config"`
}

type CapabilityRef struct {
	Name    string `yaml:"name"`
	Version int    `yaml:"version"`
}

type ConfigSpec struct {
	Schema             string   `yaml:"schema"`
	UIHints            string   `yaml:"uiHints"`
	SchemaVersion      int      `yaml:"schemaVersion"`
	SecretJSONPointers []string `yaml:"secretJsonPointers"`
	Placeholder        bool     `yaml:"placeholder"`
}

type DependencySpec struct {
	ID       string       `yaml:"id"`
	Versions VersionRange `yaml:"versions"`
}

type ArtifactSpec struct {
	Status  ArtifactStatus   `yaml:"status"`
	Bundles []ArtifactBundle `yaml:"bundles"`
}

type ArtifactBundle struct {
	Platform string `yaml:"platform"`
	Digest   string `yaml:"digest"`
}

// ValidationError contains every independently detectable manifest problem.
// Problems are returned in deterministic field/document order.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid plugin manifest: " + strings.Join(e.Problems, "; ")
}

var (
	pluginIDPattern     = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	connectorIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	legacyDBTypePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	capabilityPattern   = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)
	semverPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformPattern     = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+$`)
	configSchemaPattern = regexp.MustCompile(`^schemas/[A-Za-z0-9._-]+\.schema\.json$`)
	uiHintsPattern      = regexp.MustCompile(`^schemas/(?:[A-Za-z0-9._-]+\.)?ui-hints\.json$`)
)

// ValidateManifest validates canonical manifest semantics and referenced schema
// paths. Planned inventory entries are valid without a binary or digest.
func ValidateManifest(manifest Manifest, pluginDir string) error {
	problems := make([]string, 0)
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(manifest.Schema) == "" {
		add("$schema must not be empty")
	}
	if manifest.APIVersion != APIVersion {
		add("apiVersion must be %q", APIVersion)
	}
	if manifest.Kind != ManifestKind {
		add("kind must be %q", ManifestKind)
	}
	validateMetadata(manifest.Metadata, &problems)
	validateLifecycle("spec.lifecycle", manifest.Spec.Lifecycle, true, &problems)
	if manifest.Spec.Protocol.Major < 1 {
		add("spec.protocol.major must be at least 1")
	}
	if manifest.Spec.Protocol.Minor < 0 {
		add("spec.protocol.minor must not be negative")
	}
	validateVersionRange("spec.coreVersions", manifest.Spec.CoreVersions, &problems)
	if manifest.Spec.Lifecycle != LifecyclePlanned && !versionRangeIsNonEmpty(manifest.Spec.CoreVersions) {
		add("spec.coreVersions must be a non-empty interval for a runnable plugin")
	}
	if manifest.Spec.Runtime.Mode != RuntimeModeProcess {
		add("spec.runtime.mode must be %q", RuntimeModeProcess)
	}
	if len(manifest.Spec.Connectors) == 0 {
		add("spec.connectors must contain at least one connector")
	}
	validateConnectors(manifest.Spec.Connectors, manifest.Spec.Lifecycle, pluginDir, &problems)
	validateDependencies(manifest.Metadata.ID, manifest.Spec.Dependencies, &problems)
	if manifest.Spec.Lifecycle == LifecyclePlanned && len(manifest.Spec.Dependencies) != 0 {
		add("spec.dependencies must be empty while lifecycle is planned")
	}
	validateArtifact(manifest, pluginDir, &problems)

	if len(problems) != 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func validateMetadata(metadata PluginMetadata, problems *[]string) {
	add := func(format string, args ...any) {
		*problems = append(*problems, fmt.Sprintf(format, args...))
	}
	if !pluginIDPattern.MatchString(metadata.ID) {
		add("metadata.id must be a lowercase reverse-domain plugin id")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "displayName", value: metadata.DisplayName},
		{name: "description", value: metadata.Description},
		{name: "vendor", value: metadata.Vendor},
		{name: "license", value: metadata.License},
	} {
		if strings.TrimSpace(field.value) == "" {
			add("metadata.%s must not be empty", field.name)
		}
	}
	if !semverPattern.MatchString(metadata.Version) {
		add("metadata.version must be a semantic version")
	}
	homepage, err := url.ParseRequestURI(metadata.Homepage)
	if err != nil || homepage.Scheme == "" || homepage.Host == "" {
		add("metadata.homepage must be an absolute URI")
	}
}

func validateConnectors(
	connectors []ConnectorSpec,
	pluginLifecycle Lifecycle,
	pluginDir string,
	problems *[]string,
) {
	seen := make(map[string]struct{}, len(connectors))
	for index, connector := range connectors {
		prefix := fmt.Sprintf("spec.connectors[%d]", index)
		if !connectorIDPattern.MatchString(connector.ID) {
			*problems = append(*problems, prefix+".id must be a lowercase connector id")
		}
		if _, duplicate := seen[connector.ID]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s.id duplicates %q", prefix, connector.ID))
		}
		seen[connector.ID] = struct{}{}
		if strings.TrimSpace(connector.DisplayName) == "" {
			*problems = append(*problems, prefix+".displayName must not be empty")
		}
		if strings.TrimSpace(connector.Description) == "" {
			*problems = append(*problems, prefix+".description must not be empty")
		}
		validateStringSet(prefix+".legacyDbTypes", connector.LegacyDBTypes, func(value string) bool {
			return legacyDBTypePattern.MatchString(value)
		}, problems)
		validateRoles(prefix, connector.Roles, problems)
		validateCapabilities(
			prefix,
			connector.Capabilities,
			connector.Roles,
			pluginLifecycle != LifecyclePlanned,
			problems,
		)
		validateRecordFormats(prefix, connector.RecordFormats, problems)
		validateLifecycle(prefix+".stability", connector.Stability, false, problems)
		validateConfig(prefix, connector.Config, pluginDir, problems)
		if pluginLifecycle == LifecyclePlanned {
			if len(connector.Capabilities) != 0 {
				*problems = append(*problems, prefix+".capabilities must be empty while lifecycle is planned")
			}
			if len(connector.RecordFormats) != 0 {
				*problems = append(*problems, prefix+".recordFormats must be empty while lifecycle is planned")
			}
			if !connector.Config.Placeholder {
				*problems = append(*problems, prefix+".config.placeholder must be true while lifecycle is planned")
			}
		} else if connector.Config.Placeholder {
			*problems = append(*problems, prefix+".config.placeholder must be false for a runnable plugin")
		}
	}
}

func validateRoles(prefix string, roles []Role, problems *[]string) {
	if len(roles) == 0 {
		*problems = append(*problems, prefix+".roles must contain at least one role")
	}
	seen := make(map[Role]struct{}, len(roles))
	for index, role := range roles {
		switch role {
		case RoleSource, RoleDestination, RoleQuery:
		default:
			*problems = append(*problems, fmt.Sprintf("%s.roles[%d] contains unsupported role %q", prefix, index, role))
		}
		if _, duplicate := seen[role]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s.roles[%d] duplicates %q", prefix, index, role))
		}
		seen[role] = struct{}{}
	}
}

func validateCapabilities(
	prefix string,
	capabilities []CapabilityRef,
	roles []Role,
	enforceRegistry bool,
	problems *[]string,
) {
	seen := make(map[string]struct{}, len(capabilities))
	for index, capability := range capabilities {
		if !capabilityPattern.MatchString(capability.Name) {
			*problems = append(*problems, fmt.Sprintf("%s.capabilities[%d].name is invalid", prefix, index))
		}
		if _, duplicate := seen[capability.Name]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s.capabilities[%d] duplicates %q", prefix, index, capability.Name))
		}
		seen[capability.Name] = struct{}{}
		if capability.Version < 1 {
			*problems = append(*problems, fmt.Sprintf("%s.capabilities[%d].version must be at least 1", prefix, index))
		}
		if !enforceRegistry {
			continue
		}
		definition, known := v1CapabilityDefinition(capability.Name)
		if !known {
			*problems = append(*problems, fmt.Sprintf(
				"%s.capabilities[%d].name %q is not in the Core v1 capability registry",
				prefix,
				index,
				capability.Name,
			))
			continue
		}
		if capability.Version != definition.Version {
			*problems = append(*problems, fmt.Sprintf(
				"%s.capabilities[%d] %q supports version %d, got %d",
				prefix,
				index,
				capability.Name,
				definition.Version,
				capability.Version,
			))
		}
		if definition.RequiredRole != "" && !containsRole(roles, definition.RequiredRole) {
			*problems = append(*problems, fmt.Sprintf(
				"%s.capabilities[%d] %q requires role %q",
				prefix,
				index,
				capability.Name,
				definition.RequiredRole,
			))
		}
	}
}

func v1CapabilityDefinition(name string) (CapabilityDefinition, bool) {
	for _, definition := range v1CapabilityDefinitions {
		if definition.Name == name {
			return definition, true
		}
	}
	return CapabilityDefinition{}, false
}

func containsRole(roles []Role, role Role) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func validateRecordFormats(prefix string, formats []RecordFormat, problems *[]string) {
	seen := make(map[RecordFormat]struct{}, len(formats))
	for index, format := range formats {
		switch format {
		case RecordFormatQValueProto, RecordFormatArrowIPC, RecordFormatPGText,
			RecordFormatPGCopy, RecordFormatObjectRef:
		default:
			*problems = append(*problems, fmt.Sprintf("%s.recordFormats[%d] contains unsupported format %q", prefix, index, format))
		}
		if _, duplicate := seen[format]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s.recordFormats[%d] duplicates %q", prefix, index, format))
		}
		seen[format] = struct{}{}
	}
}

func validateConfig(prefix string, config ConfigSpec, pluginDir string, problems *[]string) {
	if !configSchemaPattern.MatchString(config.Schema) {
		*problems = append(*problems, prefix+".config.schema must match schemas/*.schema.json")
	} else if _, err := resolveContainedFile(pluginDir, config.Schema); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s.config.schema: %v", prefix, err))
	}
	if !uiHintsPattern.MatchString(config.UIHints) {
		*problems = append(*problems, prefix+".config.uiHints must reference a schemas/*ui-hints.json file")
	} else if _, err := resolveContainedFile(pluginDir, config.UIHints); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s.config.uiHints: %v", prefix, err))
	}
	if config.SchemaVersion < 0 {
		*problems = append(*problems, prefix+".config.schemaVersion must not be negative")
	}
	validateJSONPointers(prefix+".config.secretJsonPointers", config.SecretJSONPointers, problems)
}

func validateDependencies(pluginID string, dependencies []DependencySpec, problems *[]string) {
	seen := make(map[string]struct{}, len(dependencies))
	for index, dependency := range dependencies {
		prefix := fmt.Sprintf("spec.dependencies[%d]", index)
		if !pluginIDPattern.MatchString(dependency.ID) {
			*problems = append(*problems, prefix+".id must be a lowercase reverse-domain plugin id")
		}
		if dependency.ID == pluginID {
			*problems = append(*problems, prefix+".id must not reference the plugin itself")
		}
		if _, duplicate := seen[dependency.ID]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s.id duplicates %q", prefix, dependency.ID))
		}
		seen[dependency.ID] = struct{}{}
		validateVersionRange(prefix+".versions", dependency.Versions, problems)
		if !versionRangeIsNonEmpty(dependency.Versions) {
			*problems = append(*problems, prefix+".versions must be a non-empty interval")
		}
	}
}

func validateArtifact(manifest Manifest, pluginDir string, problems *[]string) {
	add := func(format string, args ...any) {
		*problems = append(*problems, fmt.Sprintf(format, args...))
	}
	planned := manifest.Spec.Lifecycle == LifecyclePlanned
	if planned {
		if manifest.Spec.Runtime.Entrypoint != nil {
			add("spec.runtime.entrypoint must be null while lifecycle is planned")
		}
		if manifest.Spec.CoreVersions.Minimum != "0.0.0" || manifest.Spec.CoreVersions.MaximumExclusive != "0.0.0" {
			add("spec.coreVersions must be the empty 0.0.0 interval while lifecycle is planned")
		}
		if manifest.Artifact.Status != ArtifactStatusUnbuilt {
			add("artifact.status must be %q while lifecycle is planned", ArtifactStatusUnbuilt)
		}
		if len(manifest.Artifact.Bundles) != 0 {
			add("artifact.bundles must be empty while lifecycle is planned")
		}
		return
	}

	if manifest.Spec.Runtime.Entrypoint == nil {
		add("spec.runtime.entrypoint is required for a runnable plugin")
	} else if _, err := resolveContainedFile(pluginDir, *manifest.Spec.Runtime.Entrypoint); err != nil {
		add("spec.runtime.entrypoint: %v", err)
	} else {
		extension := strings.ToLower(filepath.Ext(*manifest.Spec.Runtime.Entrypoint))
		if extension == ".so" || extension == ".dylib" || extension == ".dll" {
			add("spec.runtime.entrypoint must be a process executable, not a shared library")
		}
	}
	if manifest.Artifact.Status != ArtifactStatusBuilt && manifest.Artifact.Status != ArtifactStatusPublished {
		add("artifact.status must be built or published for a runnable plugin")
	}
	if len(manifest.Artifact.Bundles) == 0 {
		add("artifact.bundles must contain at least one platform bundle for a runnable plugin")
	}
	seenPlatforms := make(map[string]struct{}, len(manifest.Artifact.Bundles))
	for index, bundle := range manifest.Artifact.Bundles {
		if !platformPattern.MatchString(bundle.Platform) {
			add("artifact.bundles[%d].platform must use os/arch form", index)
		}
		if _, duplicate := seenPlatforms[bundle.Platform]; duplicate {
			add("artifact.bundles[%d].platform duplicates %q", index, bundle.Platform)
		}
		seenPlatforms[bundle.Platform] = struct{}{}
		if !digestPattern.MatchString(bundle.Digest) {
			add("artifact.bundles[%d].digest must be sha256 followed by 64 lowercase hexadecimal characters", index)
		}
	}
}

func validateLifecycle(prefix string, lifecycle Lifecycle, allowPlanned bool, problems *[]string) {
	switch lifecycle {
	case LifecycleExperimental, LifecycleBeta, LifecycleStable, LifecycleDeprecated:
		return
	case LifecyclePlanned:
		if allowPlanned {
			return
		}
	}
	*problems = append(*problems, fmt.Sprintf("%s contains unsupported value %q", prefix, lifecycle))
}

func validateVersionRange(prefix string, versionRange VersionRange, problems *[]string) {
	minimum, minimumOK := parseSemanticVersion(versionRange.Minimum)
	maximum, maximumOK := parseSemanticVersion(versionRange.MaximumExclusive)
	if !minimumOK {
		*problems = append(*problems, prefix+".minimum must be a semantic version")
	}
	if !maximumOK {
		*problems = append(*problems, prefix+".maximumExclusive must be a semantic version")
	}
	if minimumOK && maximumOK && compareSemanticVersions(minimum, maximum) > 0 {
		*problems = append(*problems, prefix+" must not have minimum greater than maximumExclusive")
	}
}

func versionRangeIsNonEmpty(versionRange VersionRange) bool {
	minimum, minimumOK := parseSemanticVersion(versionRange.Minimum)
	maximum, maximumOK := parseSemanticVersion(versionRange.MaximumExclusive)
	return minimumOK && maximumOK && compareSemanticVersions(minimum, maximum) < 0
}

func validateStringSet(prefix string, values []string, valid func(string) bool, problems *[]string) {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !valid(value) {
			*problems = append(*problems, fmt.Sprintf("%s[%d] is invalid", prefix, index))
		}
		if _, duplicate := seen[value]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s[%d] duplicates %q", prefix, index, value))
		}
		seen[value] = struct{}{}
	}
}

func validateJSONPointers(prefix string, pointers []string, problems *[]string) {
	seen := make(map[string]struct{}, len(pointers))
	for index, pointer := range pointers {
		if !validJSONPointer(pointer) {
			*problems = append(*problems, fmt.Sprintf("%s[%d] must be a non-root RFC 6901 JSON pointer", prefix, index))
		}
		if _, duplicate := seen[pointer]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s[%d] duplicates %q", prefix, index, pointer))
		}
		seen[pointer] = struct{}{}
	}
}

func validJSONPointer(pointer string) bool {
	if pointer == "" || pointer[0] != '/' {
		return false
	}
	for index := 0; index < len(pointer); index++ {
		if pointer[index] != '~' {
			continue
		}
		if index+1 >= len(pointer) || (pointer[index+1] != '0' && pointer[index+1] != '1') {
			return false
		}
		index++
	}
	return true
}

// VerifyArtifact hashes the declared runtime entrypoint. Planned plugins have
// no runtime bytes and return nil. Runnable plugins must pass this check before
// discovery marks them ready.
func VerifyArtifact(manifest Manifest, pluginDir string, platform string) error {
	if manifest.Spec.Lifecycle == LifecyclePlanned {
		return nil
	}
	if manifest.Spec.Runtime.Entrypoint == nil {
		return fmt.Errorf("runnable plugin is missing an entrypoint")
	}
	bundle, found := artifactBundleForPlatform(manifest, platform)
	if !found {
		return fmt.Errorf("plugin does not declare an artifact bundle for %q", platform)
	}
	entrypoint, err := resolveContainedFile(pluginDir, *manifest.Spec.Runtime.Entrypoint)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(entrypoint)
		if statErr != nil {
			return fmt.Errorf("stat artifact: %w", statErr)
		}
		if info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("artifact entrypoint is not executable")
		}
	}
	file, err := os.Open(entrypoint)
	if err != nil {
		return fmt.Errorf("open artifact: %w", err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("hash artifact: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close artifact: %w", closeErr)
	}
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != bundle.Digest {
		return fmt.Errorf("artifact digest mismatch: expected %s, got %s", bundle.Digest, actual)
	}
	return nil
}

func artifactBundleForPlatform(manifest Manifest, platform string) (ArtifactBundle, bool) {
	for _, bundle := range manifest.Artifact.Bundles {
		if bundle.Platform == platform {
			return bundle, true
		}
	}
	return ArtifactBundle{}, false
}

func versionInRange(version string, versionRange VersionRange) bool {
	candidate, candidateOK := parseSemanticVersion(version)
	minimum, minimumOK := parseSemanticVersion(versionRange.Minimum)
	maximum, maximumOK := parseSemanticVersion(versionRange.MaximumExclusive)
	if !candidateOK || !minimumOK || !maximumOK {
		return false
	}
	return compareSemanticVersions(candidate, minimum) >= 0 && compareSemanticVersions(candidate, maximum) < 0
}

// ValidateSemanticVersion checks the strict semantic-version representation
// shared by plugin manifests and Core compatibility selection.
func ValidateSemanticVersion(version string) error {
	if _, valid := parseSemanticVersion(version); !valid {
		return fmt.Errorf("%q is not a semantic version", version)
	}
	return nil
}

// SupportsCoreVersion reports whether coreVersion is inside the manifest's
// half-open Core compatibility interval.
func SupportsCoreVersion(manifest Manifest, coreVersion string) (bool, error) {
	if err := ValidateSemanticVersion(coreVersion); err != nil {
		return false, err
	}
	if !versionRangeIsNonEmpty(manifest.Spec.CoreVersions) {
		return false, fmt.Errorf(
			"manifest Core version interval [%s, %s) is invalid or empty",
			manifest.Spec.CoreVersions.Minimum,
			manifest.Spec.CoreVersions.MaximumExclusive,
		)
	}
	return versionInRange(coreVersion, manifest.Spec.CoreVersions), nil
}

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []string
}

func parseSemanticVersion(version string) (semanticVersion, bool) {
	matches := semverPattern.FindStringSubmatch(version)
	if matches == nil {
		return semanticVersion{}, false
	}
	major, majorErr := strconv.ParseUint(matches[1], 10, 64)
	minor, minorErr := strconv.ParseUint(matches[2], 10, 64)
	patch, patchErr := strconv.ParseUint(matches[3], 10, 64)
	if majorErr != nil || minorErr != nil || patchErr != nil {
		return semanticVersion{}, false
	}
	parsed := semanticVersion{major: major, minor: minor, patch: patch}
	if matches[4] != "" {
		parsed.prerelease = strings.Split(matches[4], ".")
		for _, identifier := range parsed.prerelease {
			if len(identifier) > 1 && identifier[0] == '0' && isNumericIdentifier(identifier) {
				return semanticVersion{}, false
			}
		}
	}
	return parsed, true
}

func compareSemanticVersions(left, right semanticVersion) int {
	for _, pair := range [][2]uint64{
		{left.major, right.major},
		{left.minor, right.minor},
		{left.patch, right.patch},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) == 0 {
		return 0
	}
	if len(left.prerelease) == 0 {
		return 1
	}
	if len(right.prerelease) == 0 {
		return -1
	}
	limit := len(left.prerelease)
	if len(right.prerelease) < limit {
		limit = len(right.prerelease)
	}
	for index := 0; index < limit; index++ {
		leftPart := left.prerelease[index]
		rightPart := right.prerelease[index]
		leftNumeric := isNumericIdentifier(leftPart)
		rightNumeric := isNumericIdentifier(rightPart)
		switch {
		case leftNumeric && rightNumeric && len(leftPart) < len(rightPart):
			return -1
		case leftNumeric && rightNumeric && len(leftPart) > len(rightPart):
			return 1
		case leftNumeric && !rightNumeric:
			return -1
		case !leftNumeric && rightNumeric:
			return 1
		case leftPart < rightPart:
			return -1
		case leftPart > rightPart:
			return 1
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}

func isNumericIdentifier(identifier string) bool {
	if identifier == "" {
		return false
	}
	for _, character := range identifier {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func resolveContainedFile(pluginDir string, relativePath string) (string, error) {
	if strings.TrimSpace(relativePath) == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if filepath.IsAbs(relativePath) || filepath.VolumeName(relativePath) != "" || strings.Contains(relativePath, `\`) {
		return "", fmt.Errorf("path must be a portable relative path")
	}
	cleanPath := filepath.Clean(relativePath)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the plugin directory")
	}

	basePath, err := filepath.Abs(pluginDir)
	if err != nil {
		return "", fmt.Errorf("resolve plugin directory: %w", err)
	}
	basePath, err = filepath.EvalSymlinks(basePath)
	if err != nil {
		return "", fmt.Errorf("resolve plugin directory symlinks: %w", err)
	}
	targetPath := filepath.Join(basePath, cleanPath)
	targetPath, err = filepath.EvalSymlinks(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	relative, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return "", fmt.Errorf("compare path with plugin directory: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path resolves outside the plugin directory")
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		return "", fmt.Errorf("stat path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path must reference a regular file")
	}
	return targetPath, nil
}

func cloneManifest(manifest Manifest) Manifest {
	clone := manifest
	if manifest.Spec.Runtime.Entrypoint != nil {
		entrypoint := *manifest.Spec.Runtime.Entrypoint
		clone.Spec.Runtime.Entrypoint = &entrypoint
	}
	clone.Artifact.Bundles = append([]ArtifactBundle(nil), manifest.Artifact.Bundles...)
	clone.Spec.Dependencies = append([]DependencySpec(nil), manifest.Spec.Dependencies...)
	clone.Spec.Connectors = make([]ConnectorSpec, len(manifest.Spec.Connectors))
	for index, connector := range manifest.Spec.Connectors {
		clone.Spec.Connectors[index] = connector
		clone.Spec.Connectors[index].LegacyDBTypes = append([]string(nil), connector.LegacyDBTypes...)
		clone.Spec.Connectors[index].Roles = append([]Role(nil), connector.Roles...)
		clone.Spec.Connectors[index].Capabilities = append([]CapabilityRef(nil), connector.Capabilities...)
		clone.Spec.Connectors[index].RecordFormats = append([]RecordFormat(nil), connector.RecordFormats...)
		clone.Spec.Connectors[index].Config.SecretJSONPointers = append(
			[]string(nil),
			connector.Config.SecretJSONPointers...,
		)
	}
	return clone
}
