package pluginmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/PeerDB-io/peerdb/flow/connectors/pluginlock"
	"github.com/PeerDB-io/peerdb/flow/connectors/pluginruntime"
	"github.com/PeerDB-io/peerdb/flow/connectors/plugins"
	"gopkg.in/yaml.v3"
)

const managerTestTrustIdentity = "sigstore.dev/peerdb-manager-test"

func TestBuildSpecsPreservesDependencyAndConnectorCapabilityScopes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dependencyID := "io.peerdb.test.manager-base"
	consumerID := "io.peerdb.test.manager-consumer"
	writeManagerPlugin(
		t,
		root,
		"z-base",
		dependencyID,
		[]plugins.ConnectorSpec{
			{
				ID:    "base-source",
				Roles: []plugins.Role{plugins.RoleSource},
				Capabilities: []plugins.CapabilityRef{
					{Name: plugins.CapabilityControl, Version: 1},
					{Name: plugins.CapabilityCDCSource, Version: 1},
				},
				RecordFormats: []plugins.RecordFormat{plugins.RecordFormatQValueProto},
			},
			{
				ID:    "base-destination",
				Roles: []plugins.Role{plugins.RoleDestination},
				Capabilities: []plugins.CapabilityRef{
					{Name: plugins.CapabilityControl, Version: 1},
					{Name: plugins.CapabilityCDCDestination, Version: 1},
					{Name: plugins.CapabilityCDCNormalize, Version: 1},
				},
				RecordFormats: []plugins.RecordFormat{plugins.RecordFormatQValueProto},
			},
		},
		nil,
	)
	writeManagerPlugin(
		t,
		root,
		"a-consumer",
		consumerID,
		[]plugins.ConnectorSpec{
			{
				ID:    "consumer-query",
				Roles: []plugins.Role{plugins.RoleQuery},
				Capabilities: []plugins.CapabilityRef{
					{Name: plugins.CapabilityControl, Version: 1},
					{Name: plugins.CapabilityQuery, Version: 1},
				},
				RecordFormats: []plugins.RecordFormat{plugins.RecordFormatArrowIPC},
			},
		},
		[]plugins.DependencySpec{
			{
				ID: dependencyID,
				Versions: plugins.VersionRange{
					Minimum:          "1.0.0",
					MaximumExclusive: "2.0.0",
				},
			},
		},
	)

	snapshot := discoverManagerPlugins(t, root)
	result := reconcileManagerPlugins(t, snapshot, true)
	adapter, err := New("1.5.0")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	specs, err := adapter.BuildSpecs(result)
	if err != nil {
		t.Fatalf("Adapter.BuildSpecs() error = %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("len(BuildSpecs()) = %d, want 2", len(specs))
	}
	if specs[0].Identity.ID != dependencyID || specs[1].Identity.ID != consumerID {
		t.Fatalf("spec dependency order = [%s, %s]", specs[0].Identity.ID, specs[1].Identity.ID)
	}
	for _, spec := range specs {
		if !filepath.IsAbs(spec.Executable) {
			t.Fatalf("spec executable is not absolute: %q", spec.Executable)
		}
		if spec.Platform != runtime.GOOS+"/"+runtime.GOARCH {
			t.Fatalf("spec platform = %q", spec.Platform)
		}
		if spec.Protocol != (pluginruntime.ProtocolRange{Major: 1, MinimumMinor: 0, MaximumMinor: 3}) {
			t.Fatalf("spec protocol = %#v", spec.Protocol)
		}
		if len(spec.ManifestCapabilities) != 0 {
			t.Fatalf("plugin-wide capabilities were populated: %#v", spec.ManifestCapabilities)
		}
	}

	base := specs[0]
	if base.Identity.Digest() != snapshot.Descriptors()[0].SHA256() {
		t.Fatalf("identity digest = %q, want %q", base.Identity.Digest(), snapshot.Descriptors()[0].SHA256())
	}
	if len(base.ManifestConnectors) != 2 {
		t.Fatalf("base connector scopes = %#v", base.ManifestConnectors)
	}
	wantSource := []pluginruntime.Capability{
		{Name: plugins.CapabilityControl, Version: 1},
		{Name: plugins.CapabilityCDCSource, Version: 1},
	}
	wantDestination := []pluginruntime.Capability{
		{Name: plugins.CapabilityControl, Version: 1},
		{Name: plugins.CapabilityCDCDestination, Version: 1},
		{Name: plugins.CapabilityCDCNormalize, Version: 1},
	}
	if base.ManifestConnectors[0].ConnectorID != "base-source" ||
		!slices.Equal(base.ManifestConnectors[0].Roles, []pluginruntime.ConnectorRole{
			pluginruntime.ConnectorRoleSource,
		}) ||
		!slices.Equal(base.ManifestConnectors[0].RecordFormats, []pluginruntime.RecordFormat{
			pluginruntime.RecordFormatQValueProtoV1,
		}) ||
		!slices.Equal(base.ManifestConnectors[0].Capabilities, wantSource) {
		t.Fatalf("source capability scope = %#v", base.ManifestConnectors[0])
	}
	if base.ManifestConnectors[1].ConnectorID != "base-destination" ||
		!slices.Equal(base.ManifestConnectors[1].Roles, []pluginruntime.ConnectorRole{
			pluginruntime.ConnectorRoleDestination,
		}) ||
		!slices.Equal(base.ManifestConnectors[1].RecordFormats, []pluginruntime.RecordFormat{
			pluginruntime.RecordFormatQValueProtoV1,
		}) ||
		!slices.Equal(base.ManifestConnectors[1].Capabilities, wantDestination) {
		t.Fatalf("destination capability scope = %#v", base.ManifestConnectors[1])
	}
	query := specs[1].ManifestConnectors[0]
	if !slices.Equal(query.Roles, []pluginruntime.ConnectorRole{pluginruntime.ConnectorRoleQuery}) ||
		!slices.Equal(query.RecordFormats, []pluginruntime.RecordFormat{pluginruntime.RecordFormatArrowIPCV1}) {
		t.Fatalf("query connector scope = %#v", query)
	}
	if got := query.Capabilities; !slices.Equal(got, []pluginruntime.Capability{
		{Name: plugins.CapabilityControl, Version: 1},
		{Name: plugins.CapabilityQuery, Version: 1},
	}) {
		t.Fatalf("query capability scope = %#v", got)
	}
}

func TestBuildSpecsFailsClosed(t *testing.T) {
	t.Parallel()
	var nilAdapter *Adapter
	if _, err := nilAdapter.BuildSpecs(nil); !errors.Is(err, ErrAdapterRequired) {
		t.Fatalf("nil Adapter.BuildSpecs() error = %v", err)
	}
	if _, err := BuildSpecs(nil, "1.5.0"); !errors.Is(err, ErrResultRequired) {
		t.Fatalf("BuildSpecs(nil) error = %v", err)
	}

	root := t.TempDir()
	writeManagerPlugin(
		t,
		root,
		"one",
		"io.peerdb.test.manager-one",
		[]plugins.ConnectorSpec{
			{
				ID:           "manager-one",
				Roles:        []plugins.Role{plugins.RoleDestination},
				Capabilities: []plugins.CapabilityRef{{Name: plugins.CapabilityControl, Version: 1}},
			},
		},
		nil,
	)
	snapshot := discoverManagerPlugins(t, root)
	unready := reconcileManagerPlugins(t, snapshot, false)
	_, firstErr := BuildSpecs(unready, "1.5.0")
	_, secondErr := BuildSpecs(unready, "1.5.0")
	if !errors.Is(firstErr, ErrResultNotReady) || firstErr.Error() != secondErr.Error() {
		t.Fatalf("unready errors are not deterministic: %v / %v", firstErr, secondErr)
	}
	var notReady *NotReadyError
	if !errors.As(firstErr, &notReady) || len(notReady.Issues()) != 1 {
		t.Fatalf("BuildSpecs() error = %#v", firstErr)
	}
	issues := notReady.Issues()
	issues[0].Message = "mutated"
	if notReady.Issues()[0].Message == "mutated" {
		t.Fatal("NotReadyError.Issues() exposed mutable state")
	}
}

func TestBuildSpecsRequiresCompatibleSemanticCoreVersion(t *testing.T) {
	t.Parallel()
	if adapter, err := New("not-semver"); adapter != nil || err == nil ||
		!strings.Contains(err.Error(), "not a semantic version") {
		t.Fatalf("New(invalid Core version) = %#v, %v", adapter, err)
	}
	root := t.TempDir()
	writeManagerPlugin(
		t,
		root,
		"core-range",
		"io.peerdb.test.manager-core",
		[]plugins.ConnectorSpec{
			{
				ID:           "manager-core",
				Roles:        []plugins.Role{plugins.RoleDestination},
				Capabilities: []plugins.CapabilityRef{{Name: plugins.CapabilityControl, Version: 1}},
			},
		},
		nil,
	)
	result := reconcileManagerPlugins(t, discoverManagerPlugins(t, root), true)

	if _, err := BuildSpecs(result, "not-semver"); err == nil || !strings.Contains(err.Error(), "not a semantic version") {
		t.Fatalf("invalid Core version error = %v", err)
	}
	_, firstErr := BuildSpecs(result, "2.0.0")
	_, secondErr := BuildSpecs(result, "2.0.0")
	if firstErr == nil || !strings.Contains(firstErr.Error(), "outside manifest interval [1.0.0, 2.0.0)") ||
		firstErr.Error() != secondErr.Error() {
		t.Fatalf("incompatible Core version errors = %v / %v", firstErr, secondErr)
	}
}

func TestRuntimeManifestEnums(t *testing.T) {
	t.Parallel()
	roleCases := []struct {
		name string
		in   plugins.Role
		want pluginruntime.ConnectorRole
	}{
		{name: "source", in: plugins.RoleSource, want: pluginruntime.ConnectorRoleSource},
		{name: "destination", in: plugins.RoleDestination, want: pluginruntime.ConnectorRoleDestination},
		{name: "query", in: plugins.RoleQuery, want: pluginruntime.ConnectorRoleQuery},
	}
	for _, testCase := range roleCases {
		t.Run("role/"+testCase.name, func(t *testing.T) {
			got, err := runtimeRoles("test", []plugins.Role{testCase.in})
			if err != nil || !slices.Equal(got, []pluginruntime.ConnectorRole{testCase.want}) {
				t.Fatalf("runtimeRoles() = %#v, %v", got, err)
			}
		})
	}
	if _, err := runtimeRoles("test", []plugins.Role{"unknown"}); err == nil {
		t.Fatal("runtimeRoles() accepted an unknown role")
	}

	formatCases := []struct {
		name string
		in   plugins.RecordFormat
		want pluginruntime.RecordFormat
	}{
		{name: "qvalue", in: plugins.RecordFormatQValueProto, want: pluginruntime.RecordFormatQValueProtoV1},
		{name: "arrow", in: plugins.RecordFormatArrowIPC, want: pluginruntime.RecordFormatArrowIPCV1},
		{name: "pg-text", in: plugins.RecordFormatPGText, want: pluginruntime.RecordFormatPGTextV1},
		{name: "pg-copy", in: plugins.RecordFormatPGCopy, want: pluginruntime.RecordFormatPGCopyV1},
		{name: "object-ref", in: plugins.RecordFormatObjectRef, want: pluginruntime.RecordFormatObjectRefV1},
	}
	for _, testCase := range formatCases {
		t.Run("format/"+testCase.name, func(t *testing.T) {
			got, err := runtimeRecordFormats("test", []plugins.RecordFormat{testCase.in})
			if err != nil || !slices.Equal(got, []pluginruntime.RecordFormat{testCase.want}) {
				t.Fatalf("runtimeRecordFormats() = %#v, %v", got, err)
			}
		})
	}
	if _, err := runtimeRecordFormats("test", []plugins.RecordFormat{"unknown"}); err == nil {
		t.Fatal("runtimeRecordFormats() accepted an unknown format")
	}
}

func writeManagerPlugin(
	t *testing.T,
	root string,
	directoryName string,
	pluginID string,
	connectors []plugins.ConnectorSpec,
	dependencies []plugins.DependencySpec,
) {
	t.Helper()
	directory := filepath.Join(root, directoryName)
	entrypoint := "bin/connector"
	content := []byte(pluginID + "@1.0.0\n")
	writeManagerFile(t, filepath.Join(directory, entrypoint), content, 0o755)
	writeManagerFile(t, filepath.Join(directory, "schemas/config.schema.json"), []byte("{}\n"), 0o644)
	writeManagerFile(t, filepath.Join(directory, "schemas/ui-hints.json"), []byte("{}\n"), 0o644)
	for index := range connectors {
		connectors[index].DisplayName = "Test " + connectors[index].ID
		connectors[index].Description = "Plugin manager connector fixture."
		connectors[index].LegacyDBTypes = []string{}
		if connectors[index].RecordFormats == nil {
			connectors[index].RecordFormats = []plugins.RecordFormat{}
		}
		connectors[index].Stability = plugins.LifecycleStable
		connectors[index].Config = plugins.ConfigSpec{
			Schema:             "schemas/config.schema.json",
			UIHints:            "schemas/ui-hints.json",
			SchemaVersion:      1,
			SecretJSONPointers: []string{},
			Placeholder:        false,
		}
	}
	if dependencies == nil {
		dependencies = []plugins.DependencySpec{}
	}
	digest := sha256.Sum256(content)
	manifest := plugins.Manifest{
		Schema:     "https://peerdb.io/schemas/plugin-manifest/v1alpha1.json",
		APIVersion: plugins.APIVersion,
		Kind:       plugins.ManifestKind,
		Metadata: plugins.PluginMetadata{
			ID:          pluginID,
			DisplayName: "Test " + directoryName,
			Version:     "1.0.0",
			Description: "Plugin manager fixture.",
			Vendor:      "PeerDB tests",
			Homepage:    "https://example.test/plugins/" + directoryName,
			License:     "Apache-2.0",
		},
		Spec: plugins.PluginSpec{
			Lifecycle:    plugins.LifecycleStable,
			Protocol:     plugins.ProtocolVersion{Major: 1, Minor: 3},
			CoreVersions: plugins.VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"},
			Runtime:      plugins.RuntimeSpec{Mode: plugins.RuntimeModeProcess, Entrypoint: &entrypoint},
			Connectors:   connectors,
			Dependencies: dependencies,
		},
		Artifact: plugins.ArtifactSpec{
			Status: plugins.ArtifactStatusBuilt,
			Bundles: []plugins.ArtifactBundle{
				{
					Platform: runtime.GOOS + "/" + runtime.GOARCH,
					Digest:   "sha256:" + hex.EncodeToString(digest[:]),
				},
			},
		},
	}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal plugin manifest: %v", err)
	}
	writeManagerFile(t, filepath.Join(directory, plugins.ManifestFilename), data, 0o644)
}

func discoverManagerPlugins(t *testing.T, root string) *plugins.Snapshot {
	t.Helper()
	snapshot, err := plugins.Discover(root)
	if err != nil {
		t.Fatalf("plugins.Discover() error = %v", err)
	}
	for _, report := range snapshot.Reports() {
		if report.Status != plugins.PluginStatusReady {
			t.Fatalf("plugin report = %#v", report)
		}
	}
	return snapshot
}

func reconcileManagerPlugins(t *testing.T, snapshot *plugins.Snapshot, attest bool) *pluginlock.Result {
	t.Helper()
	descriptors := snapshot.Descriptors()
	document := managerLockDocument{
		Schema:     "https://peerdb.io/schemas/plugin-lock/v1alpha1.json",
		APIVersion: pluginlock.APIVersion,
		Kind:       pluginlock.Kind,
		Metadata: managerLockMetadata{
			GeneratedBy: "pluginmanager-test",
		},
		Plugins: make([]managerLockEntry, 0, len(descriptors)),
	}
	attestations := make([]pluginlock.VerifiedAttestation, 0, len(descriptors))
	for index := len(descriptors) - 1; index >= 0; index-- {
		descriptor := descriptors[index]
		manifest := descriptor.Manifest()
		connectorIDs := make([]string, len(manifest.Spec.Connectors))
		for connectorIndex, connector := range manifest.Spec.Connectors {
			connectorIDs[connectorIndex] = connector.ID
		}
		document.Plugins = append(document.Plugins, managerLockEntry{
			ID:             descriptor.ID(),
			Version:        descriptor.Version(),
			State:          pluginlock.StateLocked,
			Enabled:        true,
			Platform:       descriptor.Platform(),
			Digest:         descriptor.SHA256(),
			ManifestDigest: descriptor.ManifestSHA256(),
			Protocol: managerLockProtocol{
				Major: manifest.Spec.Protocol.Major,
				Minor: manifest.Spec.Protocol.Minor,
			},
			TrustIdentity: managerTestTrustIdentity,
			Source:        managerLockSource{Type: pluginlock.SourceLocal, Reference: descriptor.Directory()},
			Connectors:    connectorIDs,
		})
		attestations = append(attestations, pluginlock.VerifiedAttestation{
			PluginKey:      descriptor.Key(),
			ArtifactDigest: descriptor.SHA256(),
			ManifestDigest: descriptor.ManifestSHA256(),
			TrustIdentity:  managerTestTrustIdentity,
		})
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatalf("marshal plugin lock: %v", err)
	}
	lock, err := pluginlock.Parse(data)
	if err != nil {
		t.Fatalf("pluginlock.Parse() error = %v\n%s", err, data)
	}
	var result *pluginlock.Result
	if attest {
		result, err = pluginlock.ReconcileWithAttestations(lock, snapshot, attestations)
	} else {
		result, err = pluginlock.Reconcile(lock, snapshot)
	}
	if err != nil {
		t.Fatalf("reconcile plugin lock: %v", err)
	}
	return result
}

type managerLockDocument struct {
	Schema     string              `yaml:"$schema"`
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   managerLockMetadata `yaml:"metadata"`
	Plugins    []managerLockEntry  `yaml:"plugins"`
}

type managerLockMetadata struct {
	GeneratedBy string  `yaml:"generatedBy"`
	GeneratedAt *string `yaml:"generatedAt"`
}

type managerLockEntry struct {
	ID             string              `yaml:"id"`
	Version        string              `yaml:"version"`
	State          pluginlock.State    `yaml:"state"`
	Enabled        bool                `yaml:"enabled"`
	Platform       string              `yaml:"platform"`
	Digest         string              `yaml:"digest"`
	ManifestDigest string              `yaml:"manifestDigest"`
	Protocol       managerLockProtocol `yaml:"protocol"`
	TrustIdentity  string              `yaml:"trustIdentity"`
	Source         managerLockSource   `yaml:"source"`
	Connectors     []string            `yaml:"connectors"`
}

type managerLockProtocol struct {
	Major int `yaml:"major"`
	Minor int `yaml:"minor"`
}

type managerLockSource struct {
	Type      pluginlock.SourceType `yaml:"type"`
	Reference string                `yaml:"reference"`
}

func writeManagerFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write test file %s: %v", path, err)
	}
}
