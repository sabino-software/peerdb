package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func plannedManifest(pluginID, version, connectorID string) Manifest {
	return Manifest{
		Schema:     "https://peerdb.io/schemas/plugin-manifest/v1alpha1.json",
		APIVersion: APIVersion,
		Kind:       ManifestKind,
		Metadata: PluginMetadata{
			ID:          pluginID,
			DisplayName: "Test " + connectorID,
			Version:     version,
			Description: "Connector used by plugin package tests.",
			Vendor:      "PeerDB tests",
			Homepage:    "https://example.test/plugins/" + connectorID,
			License:     "Apache-2.0",
		},
		Spec: PluginSpec{
			Lifecycle:    LifecyclePlanned,
			Protocol:     ProtocolVersion{Major: 1, Minor: 0},
			CoreVersions: VersionRange{Minimum: "0.0.0", MaximumExclusive: "0.0.0"},
			Runtime:      RuntimeSpec{Mode: RuntimeModeProcess},
			Dependencies: []DependencySpec{},
			Connectors: []ConnectorSpec{
				{
					ID:            connectorID,
					DisplayName:   "Test " + connectorID,
					Description:   "Connector used by plugin package tests.",
					LegacyDBTypes: []string{},
					Roles:         []Role{RoleDestination},
					Capabilities:  []CapabilityRef{},
					RecordFormats: []RecordFormat{},
					Stability:     LifecycleExperimental,
					Config: ConfigSpec{
						Schema:             "schemas/config.schema.json",
						UIHints:            "schemas/ui-hints.json",
						SchemaVersion:      0,
						SecretJSONPointers: []string{},
						Placeholder:        true,
					},
				},
			},
		},
		Artifact: ArtifactSpec{Status: ArtifactStatusUnbuilt, Bundles: []ArtifactBundle{}},
	}
}

func runnableManifest(t *testing.T, pluginDir, pluginID, version, connectorID string) Manifest {
	t.Helper()
	manifest := plannedManifest(pluginID, version, connectorID)
	entrypoint := "bin/connector"
	manifest.Spec.Lifecycle = LifecycleStable
	manifest.Spec.CoreVersions = VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}
	manifest.Spec.Runtime.Entrypoint = &entrypoint
	manifest.Spec.Connectors[0].Capabilities = []CapabilityRef{
		{Name: "control", Version: 1},
	}
	manifest.Spec.Connectors[0].RecordFormats = []RecordFormat{RecordFormatQValueProto}
	manifest.Spec.Connectors[0].Stability = LifecycleStable
	manifest.Spec.Connectors[0].Config.SchemaVersion = 1
	manifest.Spec.Connectors[0].Config.SecretJSONPointers = []string{"/password"}
	manifest.Spec.Connectors[0].Config.Placeholder = false

	writePluginSupportFiles(t, pluginDir)
	content := []byte(pluginID + "@" + version + "\n")
	writeFile(t, filepath.Join(pluginDir, entrypoint), content)
	digest := sha256.Sum256(content)
	manifest.Artifact = ArtifactSpec{
		Status: ArtifactStatusBuilt,
		Bundles: []ArtifactBundle{
			{
				Platform: runtime.GOOS + "/" + runtime.GOARCH,
				Digest:   "sha256:" + hex.EncodeToString(digest[:]),
			},
		},
	}
	return manifest
}

func writePluginSupportFiles(t *testing.T, pluginDir string) {
	t.Helper()
	writeFile(t, filepath.Join(pluginDir, "schemas/config.schema.json"), []byte("{}\n"))
	writeFile(t, filepath.Join(pluginDir, "schemas/ui-hints.json"), []byte("{}\n"))
}

func writeManifest(t *testing.T, pluginDir string, manifest Manifest) string {
	t.Helper()
	writePluginSupportFiles(t, pluginDir)
	data, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(pluginDir, ManifestFilename)
	writeFile(t, path, data)
	return path
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func manifestYAML(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	data, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return data
}

func stringPointer(value string) *string {
	return &value
}
