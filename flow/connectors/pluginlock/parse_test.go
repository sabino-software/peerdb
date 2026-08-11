package pluginlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseValidLockAndImmutableAccessors(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	data := lockDocumentYAML(
		"unit-test",
		`"2026-08-11T12:34:56Z"`,
		lockedEntryYAML(
			"io.peerdb.connector.search",
			"1.2.3",
			true,
			"linux/amd64",
			digest,
			"oci",
			"registry.example.test/search@"+digest,
			[]string{"elasticsearch", "opensearch"},
		),
		plannedEntryYAML("io.peerdb.connector.future", "0.0.0-dev", "future"),
	)

	lock, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if lock.Schema() != "schemas/plugins-lock.schema.json" ||
		lock.APIVersion() != APIVersion || lock.Kind() != Kind {
		t.Fatalf("lock identity = %q, %q, %q", lock.Schema(), lock.APIVersion(), lock.Kind())
	}
	if lock.Metadata().GeneratedBy() != "unit-test" {
		t.Fatalf("GeneratedBy() = %q", lock.Metadata().GeneratedBy())
	}
	generatedAt, present := lock.Metadata().GeneratedAt()
	if !present || !generatedAt.Equal(time.Date(2026, 8, 11, 12, 34, 56, 0, time.UTC)) {
		t.Fatalf("GeneratedAt() = %v, %v", generatedAt, present)
	}

	entries := lock.Plugins()
	if len(entries) != 2 {
		t.Fatalf("len(Plugins()) = %d, want 2", len(entries))
	}
	platform, hasPlatform := entries[0].Platform()
	entryDigest, hasDigest := entries[0].Digest()
	manifestDigest, hasManifestDigest := entries[0].ManifestDigest()
	protocol, hasProtocol := entries[0].Protocol()
	trustIdentity, hasTrustIdentity := entries[0].TrustIdentity()
	if entries[0].Key() != "io.peerdb.connector.search@1.2.3" ||
		entries[0].State() != StateLocked || !entries[0].Enabled() ||
		platform != "linux/amd64" || !hasPlatform || entryDigest != digest || !hasDigest ||
		manifestDigest != defaultManifestDigest() || !hasManifestDigest ||
		protocol.Major() != 1 || protocol.Minor() != 0 || !hasProtocol ||
		trustIdentity != defaultTrustIdentity() || !hasTrustIdentity ||
		entries[0].Source().Type() != SourceOCI {
		t.Fatalf("locked entry = %#v", entries[0])
	}
	if _, present := entries[1].Platform(); present {
		t.Fatal("planned platform unexpectedly present")
	}
	if _, present := entries[1].Digest(); present {
		t.Fatal("planned digest unexpectedly present")
	}
	if _, present := entries[1].ManifestDigest(); present {
		t.Fatal("planned manifest digest unexpectedly present")
	}
	if _, present := entries[1].Protocol(); present {
		t.Fatal("planned protocol unexpectedly present")
	}
	if _, present := entries[1].TrustIdentity(); present {
		t.Fatal("planned trust identity unexpectedly present")
	}

	connectors := entries[0].Connectors()
	connectors[0] = "mutated"
	entries[0].connectors[1] = "also-mutated"
	entries[1] = Entry{}
	fresh := lock.Plugins()
	if got := fresh[0].Connectors(); got[0] != "elasticsearch" || got[1] != "opensearch" {
		t.Fatalf("lock was mutated through accessor: %v", got)
	}
	if fresh[1].ID() != "io.peerdb.connector.future" {
		t.Fatalf("entry slice mutated lock: %#v", fresh[1])
	}
}

func TestParseRejectsStrictYAMLAndSchemaViolations(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("b", 64)
	validEntry := lockedEntryYAML(
		"io.peerdb.connector.test",
		"1.0.0",
		true,
		"linux/amd64",
		digest,
		"local",
		"plugins/test",
		[]string{"test"},
	)
	valid := string(lockDocumentYAML("unit-test", "null", validEntry))
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "unknown field",
			data:    strings.Replace(valid, "kind: PluginLock", "kind: PluginLock\nunknown: true", 1),
			wantErr: "field unknown not found",
		},
		{
			name:    "duplicate mapping key",
			data:    strings.Replace(valid, "kind: PluginLock", "kind: PluginLock\nkind: PluginLock", 1),
			wantErr: "mapping key \"kind\" already defined",
		},
		{
			name:    "second document",
			data:    valid + "---\n{}\n",
			wantErr: "exactly one YAML document",
		},
		{
			name:    "missing false boolean",
			data:    strings.Replace(valid, "    enabled: true\n", "", 1),
			wantErr: "plugins[0].enabled is required",
		},
		{
			name:    "numeric version is not coerced",
			data:    strings.Replace(valid, "    version: 1.0.0", "    version: 100", 1),
			wantErr: "",
		},
		{
			name:    "invalid semantic version",
			data:    strings.Replace(valid, "    version: 1.0.0", "    version: definitely-not-semver", 1),
			wantErr: "version must be a semantic version",
		},
		{
			name: "aliases",
			data: strings.Replace(
				valid,
				"metadata:\n  generatedBy: unit-test",
				"metadata: &metadata\n  generatedBy: unit-test",
				1,
			) + "metadataCopy: *metadata\n",
			wantErr: "field metadataCopy not found",
		},
		{
			name:    "planned enabled",
			data:    string(lockDocumentYAML("unit-test", "null", strings.Replace(plannedEntryYAML("io.peerdb.connector.test", "0.0.0-dev", "test"), "enabled: false", "enabled: true", 1))),
			wantErr: "enabled must be false while state is planned",
		},
		{
			name:    "planned pinned",
			data:    string(lockDocumentYAML("unit-test", "null", strings.Replace(plannedEntryYAML("io.peerdb.connector.test", "0.0.0-dev", "test"), "platform: null", "platform: linux/amd64", 1))),
			wantErr: "platform must be null while state is planned",
		},
		{
			name:    "locked missing digest",
			data:    strings.Replace(valid, "    digest: "+digest, "    digest: null", 1),
			wantErr: "digest must be set while state is locked",
		},
		{
			name:    "locked missing manifest digest",
			data:    strings.Replace(valid, "    manifestDigest: "+defaultManifestDigest(), "    manifestDigest: null", 1),
			wantErr: "manifestDigest must be set while state is locked",
		},
		{
			name:    "locked missing protocol",
			data:    strings.Replace(valid, "    protocol: {major: 1, minor: 0}", "    protocol: null", 1),
			wantErr: "protocol must be set while state is locked",
		},
		{
			name:    "locked missing trust identity",
			data:    strings.Replace(valid, "    trustIdentity: "+defaultTrustIdentity(), "    trustIdentity: null", 1),
			wantErr: "trustIdentity must be set while state is locked",
		},
		{
			name:    "invalid digest",
			data:    strings.Replace(valid, digest, "sha256:"+strings.Repeat("B", 64), 1),
			wantErr: "digest must be a lowercase sha256 digest",
		},
		{
			name:    "unsupported source",
			data:    strings.Replace(valid, "      type: local", "      type: http", 1),
			wantErr: "source.type is unsupported",
		},
		{
			name:    "duplicate connector",
			data:    strings.Replace(valid, "    connectors: [test]", "    connectors: [test, test]", 1),
			wantErr: "duplicates \"test\"",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(test.data))
			if err == nil || test.wantErr != "" && !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Parse() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestParseRejectsDuplicateLogicalPluginKey(t *testing.T) {
	t.Parallel()
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	data := lockDocumentYAML(
		"unit-test",
		"null",
		lockedEntryYAML(
			"io.peerdb.connector.same", "1.0.0", true, "linux/amd64", digestA,
			"local", "one", []string{"one"},
		),
		lockedEntryYAML(
			"io.peerdb.connector.same", "1.0.0", false, "linux/arm64", digestB,
			"oci", "two", []string{"two"},
		),
	)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), `duplicates plugin key "io.peerdb.connector.same@1.0.0"`) {
		t.Fatalf("Parse() error = %v, want duplicate logical key", err)
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Parse() error type = %T, want *ValidationError", err)
	}
	problems := validationErr.Problems()
	problems[0] = "mutated"
	if validationErr.Problems()[0] == "mutated" {
		t.Fatal("ValidationError.Problems exposed mutable state")
	}
}

func TestParseAndLoadSizeAndFileGuards(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, MaxBytes+1)
	if _, err := Parse(oversized); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("Parse(oversized) error = %v", err)
	}

	root := t.TempDir()
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load(directory) error = %v", err)
	}
	path := filepath.Join(root, "plugins.lock.yaml")
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatalf("write oversized lock: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("Load(oversized) error = %v", err)
	}

	target := filepath.Join(root, "target.lock.yaml")
	if err := os.WriteFile(target, lockDocumentYAML("unit-test", "null"), 0o600); err != nil {
		t.Fatalf("write lock target: %v", err)
	}
	symlink := filepath.Join(root, "symlink.lock.yaml")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if _, err := Load(symlink); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Load(symlink) error = %v", err)
	}
}

func lockDocumentYAML(generatedBy string, generatedAt string, entries ...string) []byte {
	pluginsYAML := "plugins: []\n"
	if len(entries) != 0 {
		pluginsYAML = "plugins:\n" + strings.Join(entries, "")
	}
	return []byte("$schema: schemas/plugins-lock.schema.json\n" +
		"apiVersion: peerdb.io/plugin-lock/v1alpha1\n" +
		"kind: PluginLock\n" +
		"metadata:\n" +
		"  generatedBy: " + generatedBy + "\n" +
		"  generatedAt: " + generatedAt + "\n" +
		pluginsYAML)
}

func lockedEntryYAML(
	id string,
	version string,
	enabled bool,
	platform string,
	digest string,
	sourceType string,
	sourceReference string,
	connectors []string,
) string {
	return "  - id: " + id + "\n" +
		"    version: " + version + "\n" +
		"    state: locked\n" +
		"    enabled: " + boolYAML(enabled) + "\n" +
		"    platform: " + platform + "\n" +
		"    digest: " + digest + "\n" +
		"    manifestDigest: " + defaultManifestDigest() + "\n" +
		"    protocol: {major: 1, minor: 0}\n" +
		"    trustIdentity: " + defaultTrustIdentity() + "\n" +
		"    source:\n" +
		"      type: " + sourceType + "\n" +
		"      reference: " + sourceReference + "\n" +
		"    connectors: [" + strings.Join(connectors, ", ") + "]\n"
}

func plannedEntryYAML(id string, version string, connector string) string {
	return "  - id: " + id + "\n" +
		"    version: " + version + "\n" +
		"    state: planned\n" +
		"    enabled: false\n" +
		"    platform: null\n" +
		"    digest: null\n" +
		"    manifestDigest: null\n" +
		"    protocol: null\n" +
		"    trustIdentity: null\n" +
		"    source:\n" +
		"      type: local\n" +
		"      reference: plugins/" + connector + "\n" +
		"    connectors: [" + connector + "]\n"
}

func defaultManifestDigest() string {
	return "sha256:" + strings.Repeat("d", 64)
}

func defaultTrustIdentity() string {
	return "peerdb-test-root/test-signer"
}

func boolYAML(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
