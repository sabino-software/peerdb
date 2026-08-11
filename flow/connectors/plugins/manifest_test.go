package plugins

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateManifest(t *testing.T) {
	t.Parallel()
	pluginDir := t.TempDir()
	base := runnableManifest(t, pluginDir, "io.peerdb.test.validation", "1.2.3", "validation")

	tests := []struct {
		name      string
		mutate    func(*Manifest)
		wantError string
	}{
		{name: "valid runnable"},
		{
			name:      "wrong api version",
			mutate:    func(manifest *Manifest) { manifest.APIVersion = "peerdb.io/v1" },
			wantError: "apiVersion",
		},
		{
			name:      "invalid plugin id",
			mutate:    func(manifest *Manifest) { manifest.Metadata.ID = "INVALID" },
			wantError: "metadata.id",
		},
		{
			name:      "invalid semver",
			mutate:    func(manifest *Manifest) { manifest.Metadata.Version = "1.2" },
			wantError: "metadata.version",
		},
		{
			name:      "relative homepage",
			mutate:    func(manifest *Manifest) { manifest.Metadata.Homepage = "/docs" },
			wantError: "metadata.homepage",
		},
		{
			name:      "bad protocol",
			mutate:    func(manifest *Manifest) { manifest.Spec.Protocol.Major = 0 },
			wantError: "protocol.major",
		},
		{
			name: "empty core range",
			mutate: func(manifest *Manifest) {
				manifest.Spec.CoreVersions.MaximumExclusive = manifest.Spec.CoreVersions.Minimum
			},
			wantError: "non-empty interval",
		},
		{
			name:      "unsupported runtime",
			mutate:    func(manifest *Manifest) { manifest.Spec.Runtime.Mode = "go-plugin" },
			wantError: "runtime.mode",
		},
		{
			name:      "missing runnable entrypoint",
			mutate:    func(manifest *Manifest) { manifest.Spec.Runtime.Entrypoint = nil },
			wantError: "entrypoint is required",
		},
		{
			name:      "entrypoint traversal",
			mutate:    func(manifest *Manifest) { manifest.Spec.Runtime.Entrypoint = stringPointer("../escape") },
			wantError: "escapes the plugin directory",
		},
		{
			name: "shared library",
			mutate: func(manifest *Manifest) {
				writeFile(t, filepath.Join(pluginDir, "bin/connector.so"), []byte("not a plugin"))
				manifest.Spec.Runtime.Entrypoint = stringPointer("bin/connector.so")
			},
			wantError: "shared library",
		},
		{
			name:      "invalid artifact status",
			mutate:    func(manifest *Manifest) { manifest.Artifact.Status = ArtifactStatusUnbuilt },
			wantError: "built or published",
		},
		{
			name:      "invalid digest",
			mutate:    func(manifest *Manifest) { manifest.Artifact.Bundles[0].Digest = "abc" },
			wantError: "bundles[0].digest",
		},
		{
			name: "duplicate platform",
			mutate: func(manifest *Manifest) {
				manifest.Artifact.Bundles = append(manifest.Artifact.Bundles, manifest.Artifact.Bundles[0])
			},
			wantError: "duplicates",
		},
		{
			name:      "invalid connector id",
			mutate:    func(manifest *Manifest) { manifest.Spec.Connectors[0].ID = "Bad_ID" },
			wantError: "connectors[0].id",
		},
		{
			name: "duplicate role",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Roles = []Role{RoleDestination, RoleDestination}
			},
			wantError: "roles[1] duplicates",
		},
		{
			name:      "missing role",
			mutate:    func(manifest *Manifest) { manifest.Spec.Connectors[0].Roles = []Role{} },
			wantError: "roles must contain at least one role",
		},
		{
			name:      "invalid capability version",
			mutate:    func(manifest *Manifest) { manifest.Spec.Connectors[0].Capabilities[0].Version = 0 },
			wantError: "capabilities[0].version",
		},
		{
			name: "duplicate capability name",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Capabilities = append(
					manifest.Spec.Connectors[0].Capabilities,
					CapabilityRef{Name: "control", Version: 2},
				)
			},
			wantError: "capabilities[1] duplicates",
		},
		{
			name: "unknown runnable capability",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Capabilities = []CapabilityRef{{Name: "vendor.magic", Version: 1}}
			},
			wantError: "not in the Core v1 capability registry",
		},
		{
			name: "unsupported capability version",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Capabilities = []CapabilityRef{{Name: CapabilityControl, Version: 2}}
			},
			wantError: "supports version 1",
		},
		{
			name: "capability role mismatch",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Capabilities = []CapabilityRef{{Name: CapabilityCDCSource, Version: 1}}
			},
			wantError: "requires role \"source\"",
		},
		{
			name: "invalid record format",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].RecordFormats = []RecordFormat{"gob"}
			},
			wantError: "recordFormats[0]",
		},
		{
			name: "missing config schema",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Config.Schema = "schemas/missing.schema.json"
			},
			wantError: "config.schema",
		},
		{
			name: "invalid secret pointer",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Connectors[0].Config.SecretJSONPointers = []string{"password"}
			},
			wantError: "secretJsonPointers[0]",
		},
		{
			name:      "placeholder runnable config",
			mutate:    func(manifest *Manifest) { manifest.Spec.Connectors[0].Config.Placeholder = true },
			wantError: "placeholder must be false",
		},
		{
			name: "self dependency",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Dependencies = []DependencySpec{
					{ID: manifest.Metadata.ID, Versions: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}},
				}
			},
			wantError: "must not reference the plugin itself",
		},
		{
			name: "empty dependency range",
			mutate: func(manifest *Manifest) {
				manifest.Spec.Dependencies = []DependencySpec{
					{ID: "io.peerdb.test.base", Versions: VersionRange{Minimum: "1.0.0", MaximumExclusive: "1.0.0"}},
				}
			},
			wantError: "versions must be a non-empty interval",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := cloneManifest(base)
			if test.mutate != nil {
				test.mutate(&manifest)
			}
			err := ValidateManifest(manifest, pluginDir)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ValidateManifest() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateManifest() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestValidateManifestPlannedInventory(t *testing.T) {
	t.Parallel()
	pluginDir := t.TempDir()
	writePluginSupportFiles(t, pluginDir)
	manifest := plannedManifest("io.peerdb.test.planned", "0.0.0-dev", "planned")
	if err := ValidateManifest(manifest, pluginDir); err != nil {
		t.Fatalf("ValidateManifest() error = %v", err)
	}

	manifest.Spec.Connectors[0].Capabilities = []CapabilityRef{{Name: "control", Version: 1}}
	if err := ValidateManifest(manifest, pluginDir); err == nil || !strings.Contains(err.Error(), "while lifecycle is planned") {
		t.Fatalf("ValidateManifest() error = %v, want planned-lifecycle error", err)
	}
}

func TestVerifyArtifact(t *testing.T) {
	t.Parallel()
	pluginDir := t.TempDir()
	manifest := runnableManifest(t, pluginDir, "io.peerdb.test.digest", "1.0.0", "digest")
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if err := VerifyArtifact(manifest, pluginDir, platform); err != nil {
		t.Fatalf("VerifyArtifact() error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(pluginDir, *manifest.Spec.Runtime.Entrypoint), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	if err := VerifyArtifact(manifest, pluginDir, platform); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("VerifyArtifact() error = %v, want digest mismatch", err)
	}
	if err := VerifyArtifact(manifest, pluginDir, "plan9/amd64"); err == nil || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("VerifyArtifact() error = %v, want platform error", err)
	}
}

func TestVerifyArtifactRejectsNonExecutableEntrypoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows executable permission is not represented by Unix mode bits")
	}
	t.Parallel()
	pluginDir := t.TempDir()
	manifest := runnableManifest(t, pluginDir, "io.peerdb.test.permissions", "1.0.0", "permissions")
	entrypoint := filepath.Join(pluginDir, *manifest.Spec.Runtime.Entrypoint)
	if err := os.Chmod(entrypoint, 0o644); err != nil {
		t.Fatalf("remove executable bit: %v", err)
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if err := VerifyArtifact(manifest, pluginDir, platform); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("VerifyArtifact() error = %v, want executable-permission error", err)
	}
}

func TestVersionInRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version string
		range_  VersionRange
		want    bool
	}{
		{version: "1.0.0", range_: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}, want: true},
		{version: "1.9.9", range_: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}, want: true},
		{version: "2.0.0", range_: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}, want: false},
		{version: "1.0.0-beta.1", range_: VersionRange{Minimum: "1.0.0-beta.1", MaximumExclusive: "1.0.0"}, want: true},
		{version: "1.0.0-beta.01", range_: VersionRange{Minimum: "1.0.0-beta.1", MaximumExclusive: "1.0.0"}, want: false},
		{
			version: "1.0.0-99999999999999999999",
			range_: VersionRange{
				Minimum:          "1.0.0-99999999999999999999",
				MaximumExclusive: "1.0.0-100000000000000000000",
			},
			want: true,
		},
	}
	for _, test := range tests {
		if got := versionInRange(test.version, test.range_); got != test.want {
			t.Errorf("versionInRange(%q, %#v) = %v, want %v", test.version, test.range_, got, test.want)
		}
	}
}

func TestDocumentedExampleFixture(t *testing.T) {
	t.Parallel()
	pluginDir := filepath.Join("testdata", "example")
	manifest, err := LoadManifest(filepath.Join(pluginDir, ManifestFilename))
	if err != nil {
		t.Fatalf("LoadManifest() error = %v", err)
	}
	if err := ValidateManifest(manifest, pluginDir); err != nil {
		t.Fatalf("ValidateManifest() error = %v", err)
	}
	if err := VerifyArtifact(manifest, pluginDir, "linux/amd64"); err != nil {
		t.Fatalf("VerifyArtifact() error = %v", err)
	}
}

func TestV1CapabilityRegistryIsImmutable(t *testing.T) {
	t.Parallel()
	registry := V1CapabilityRegistry()
	if len(registry) == 0 {
		t.Fatal("V1CapabilityRegistry() is empty")
	}
	registry[0].Name = "mutated"
	if V1CapabilityRegistry()[0].Name != CapabilityControl {
		t.Fatal("V1CapabilityRegistry() exposed mutable package state")
	}
}
