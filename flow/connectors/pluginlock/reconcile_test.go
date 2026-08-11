package pluginlock

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/PeerDB-io/peerdb/flow/connectors/plugins"
	"gopkg.in/yaml.v3"
)

type pluginFixture struct {
	id             string
	version        string
	platform       string
	digest         string
	manifestDigest string
	connectors     []string
}

func TestReconcileAuthorizesExactEnabledEntry(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fixture := writeRunnablePlugin(
		t,
		root,
		"search",
		"io.peerdb.connector.search",
		"1.2.3",
		[]string{"opensearch", "elasticsearch"},
	)
	snapshot := discover(t, root)
	trustIdentity := "sigstore.dev/peerdb-official"
	lock := mustParseLock(t, lockDocumentYAML(
		"unit-test",
		"null",
		lockedVerifiedEntryYAML(
			fixture.id,
			fixture.version,
			true,
			fixture.platform,
			fixture.digest,
			"local",
			"different-host-path-is-not-identity",
			[]string{"elasticsearch", "opensearch"},
			fixture.manifestDigest,
			1,
			0,
			trustIdentity,
		),
	))

	unattested, err := Reconcile(lock, snapshot)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if unattested.Ready() || len(unattested.Authorized()) != 0 ||
		len(unattested.Issues()) != 1 || unattested.Issues()[0].Code != IssueTrustUnverified {
		t.Fatalf("unattested reconciliation did not fail closed: %#v", unattested.Issues())
	}

	result, err := ReconcileWithAttestations(
		lock,
		snapshot,
		[]VerifiedAttestation{fixtureAttestation(fixture, trustIdentity)},
	)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !result.Ready() || len(result.Issues()) != 0 {
		t.Fatalf("Reconcile() issues = %#v", result.Issues())
	}
	authorized := result.Authorized()
	if len(authorized) != 1 || authorized[0].Key() != fixture.id+"@"+fixture.version {
		t.Fatalf("Authorized() = %#v", authorized)
	}
	if !digestPattern.MatchString(result.InventoryHash()) {
		t.Fatalf("InventoryHash() = %q", result.InventoryHash())
	}

	authorized[0] = plugins.Descriptor{}
	issues := result.Issues()
	issues = append(issues, Issue{Code: IssueMissingPlugin})
	if len(result.Authorized()) != 1 || len(result.Issues()) != 0 {
		t.Fatal("Result accessors exposed mutable state")
	}
}

func TestReconcileUsesCapturedManifestIdentityAfterPathSwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fixture := writeRunnablePlugin(
		t,
		root,
		"captured",
		"io.peerdb.connector.captured",
		"1.0.0",
		[]string{"captured"},
	)
	snapshot := discover(t, root)
	writeTestFile(
		t,
		filepath.Join(root, "captured", plugins.ManifestFilename),
		[]byte("swapped after discovery\n"),
		0o644,
	)

	trustIdentity := "sigstore.dev/peerdb-official"
	lock := mustParseLock(t, lockDocumentYAML(
		"unit-test",
		"null",
		lockedVerifiedEntryYAML(
			fixture.id,
			fixture.version,
			true,
			fixture.platform,
			fixture.digest,
			"local",
			"captured",
			fixture.connectors,
			fixture.manifestDigest,
			1,
			0,
			trustIdentity,
		),
	))
	result, err := ReconcileWithAttestations(
		lock,
		snapshot,
		[]VerifiedAttestation{fixtureAttestation(fixture, trustIdentity)},
	)
	if err != nil {
		t.Fatalf("ReconcileWithAttestations() error = %v", err)
	}
	if !result.Ready() || len(result.Authorized()) != 1 {
		t.Fatalf("path swap changed captured manifest identity: %#v", result.Issues())
	}
}

func TestReconcileReportsMissingMismatchAndUnapprovedDeterministically(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	actual := writeRunnablePlugin(
		t,
		root,
		"actual",
		"io.peerdb.connector.actual",
		"1.0.0",
		[]string{"actual"},
	)
	extra := writeRunnablePlugin(
		t,
		root,
		"extra",
		"io.peerdb.connector.extra",
		"1.0.0",
		[]string{"extra"},
	)
	snapshot := discover(t, root)
	missingDigest := "sha256:" + strings.Repeat("c", 64)
	wrongManifestDigest := "sha256:" + strings.Repeat("e", 64)
	trustIdentity := "sigstore.dev/peerdb-official"
	lock := mustParseLock(t, lockDocumentYAML(
		"unit-test",
		"null",
		lockedEntryYAML(
			"io.peerdb.connector.missing", "2.0.0", true, actual.platform, missingDigest,
			"oci", "missing", []string{"missing"},
		),
		lockedVerifiedEntryYAML(
			actual.id, actual.version, true, "plan9/amd64", "sha256:"+strings.Repeat("0", 64),
			"local", "actual", []string{"different"}, wrongManifestDigest, 1, 1, trustIdentity,
		),
		lockedEntryYAML(
			extra.id, extra.version, false, extra.platform, extra.digest,
			"local", "extra", extra.connectors,
		),
	))

	result, err := ReconcileWithAttestations(
		lock,
		snapshot,
		[]VerifiedAttestation{fixtureAttestation(actual, trustIdentity)},
	)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Ready() || len(result.Authorized()) != 0 {
		t.Fatalf("Reconcile() ready = %v, authorized = %#v", result.Ready(), result.Authorized())
	}
	issues := result.Issues()
	want := []struct {
		key  string
		code IssueCode
	}{
		{actual.id + "@" + actual.version, IssueConnectorMismatch},
		{actual.id + "@" + actual.version, IssueDigestMismatch},
		{actual.id + "@" + actual.version, IssueManifestDigest},
		{actual.id + "@" + actual.version, IssuePlatformMismatch},
		{actual.id + "@" + actual.version, IssueProtocolMismatch},
		{actual.id + "@" + actual.version, IssueTrustMismatch},
		{extra.id + "@" + extra.version, IssueUnapprovedPlugin},
		{"io.peerdb.connector.missing@2.0.0", IssueMissingPlugin},
	}
	if len(issues) != len(want) {
		t.Fatalf("Issues() = %#v, want %d issues", issues, len(want))
	}
	for index := range want {
		if issues[index].PluginKey != want[index].key || issues[index].Code != want[index].code {
			t.Fatalf("Issues()[%d] = %#v, want key=%q code=%q", index, issues[index], want[index].key, want[index].code)
		}
	}
}

func TestReconcileUsesExactVersionKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	actual := writeRunnablePlugin(
		t,
		root,
		"v1",
		"io.peerdb.connector.exact",
		"1.0.0",
		[]string{"exact"},
	)
	snapshot := discover(t, root)
	lock := mustParseLock(t, lockDocumentYAML(
		"unit-test",
		"null",
		lockedEntryYAML(
			actual.id, "2.0.0", true, actual.platform, actual.digest,
			"local", "v2", actual.connectors,
		),
	))

	result, err := Reconcile(lock, snapshot)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	issues := result.Issues()
	if len(issues) != 2 ||
		issues[0].Code != IssueUnapprovedPlugin ||
		issues[0].PluginKey != actual.id+"@1.0.0" ||
		issues[1].Code != IssueMissingPlugin ||
		issues[1].PluginKey != actual.id+"@2.0.0" {
		t.Fatalf("exact-key issues = %#v", issues)
	}
}

func TestReconcilePlannedInventoryIsNonRunnable(t *testing.T) {
	t.Parallel()
	snapshot := discover(t, t.TempDir())
	planned := mustParseLock(t, lockDocumentYAML(
		"one-generator",
		"null",
		plannedEntryYAML("io.peerdb.connector.future", "0.0.0-dev", "future"),
	))
	empty := mustParseLock(t, lockDocumentYAML("another-generator", `"2027-01-01T00:00:00Z"`))

	plannedResult, err := Reconcile(planned, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(planned) error = %v", err)
	}
	emptyResult, err := Reconcile(empty, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(empty) error = %v", err)
	}
	if !plannedResult.Ready() || len(plannedResult.Authorized()) != 0 || len(plannedResult.Issues()) != 0 {
		t.Fatalf("planned result = ready %v, authorized %#v, issues %#v", plannedResult.Ready(), plannedResult.Authorized(), plannedResult.Issues())
	}
	if plannedResult.InventoryHash() != emptyResult.InventoryHash() {
		t.Fatalf("planned entry changed runnable hash: %q != %q", plannedResult.InventoryHash(), emptyResult.InventoryHash())
	}
}

func TestInventoryHashCanonicalizesRunnableIdentityOnly(t *testing.T) {
	t.Parallel()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	entryA1 := lockedEntryYAML(
		"io.peerdb.connector.a", "1.0.0", true, platform, digestA,
		"local", "/host/one/a", []string{"a-two", "a-one"},
	)
	entryB1 := lockedEntryYAML(
		"io.peerdb.connector.b", "2.0.0", true, platform, digestB,
		"oci", "registry-one/b", []string{"b"},
	)
	entryA2 := lockedEntryYAML(
		"io.peerdb.connector.a", "1.0.0", true, platform, digestA,
		"github-release", "release-two/a", []string{"a-one", "a-two"},
	)
	entryB2 := lockedEntryYAML(
		"io.peerdb.connector.b", "2.0.0", true, platform, digestB,
		"local", "/host/two/b", []string{"b"},
	)
	first := mustParseLock(t, lockDocumentYAML(
		"generator-one", "null", entryA1, entryB1,
		plannedEntryYAML("io.peerdb.connector.future", "0.0.0-dev", "future"),
	))
	second := mustParseLock(t, lockDocumentYAML(
		"generator-two", `"2030-01-01T00:00:00Z"`, entryB2, entryA2,
	))
	snapshot := discover(t, t.TempDir())
	firstResult, err := Reconcile(first, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(first) error = %v", err)
	}
	secondResult, err := Reconcile(second, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(second) error = %v", err)
	}
	if firstResult.InventoryHash() != secondResult.InventoryHash() {
		t.Fatalf("canonical hashes differ: %q != %q", firstResult.InventoryHash(), secondResult.InventoryHash())
	}

	changed := mustParseLock(t, lockDocumentYAML(
		"generator-two",
		"null",
		entryA2,
		strings.Replace(entryB2, digestB, "sha256:"+strings.Repeat("c", 64), 1),
	))
	changedResult, err := Reconcile(changed, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(changed) error = %v", err)
	}
	if changedResult.InventoryHash() == firstResult.InventoryHash() {
		t.Fatal("artifact identity change did not change inventory hash")
	}
	changedTrust := mustParseLock(t, lockDocumentYAML(
		"generator-two",
		"null",
		strings.Replace(entryA2, defaultTrustIdentity(), "another/trust-root", 1),
		entryB2,
	))
	changedTrustResult, err := Reconcile(changedTrust, snapshot)
	if err != nil {
		t.Fatalf("Reconcile(changed trust) error = %v", err)
	}
	if changedTrustResult.InventoryHash() == firstResult.InventoryHash() {
		t.Fatal("trust identity change did not change inventory hash")
	}
}

func TestReconcileRejectsNilInputs(t *testing.T) {
	t.Parallel()
	snapshot := discover(t, t.TempDir())
	lock := mustParseLock(t, lockDocumentYAML("unit-test", "null"))
	if _, err := Reconcile(nil, snapshot); err == nil {
		t.Fatal("Reconcile(nil lock) succeeded")
	}
	if _, err := Reconcile(lock, nil); err == nil {
		t.Fatal("Reconcile(nil snapshot) succeeded")
	}
}

func TestReconcileRejectsDuplicateAttestations(t *testing.T) {
	t.Parallel()
	snapshot := discover(t, t.TempDir())
	lock := mustParseLock(t, lockDocumentYAML("unit-test", "null"))
	attestation := VerifiedAttestation{PluginKey: "io.peerdb.connector.same@1.0.0"}
	if _, err := ReconcileWithAttestations(
		lock,
		snapshot,
		[]VerifiedAttestation{attestation, attestation},
	); err == nil || !strings.Contains(err.Error(), "duplicate plugin key") {
		t.Fatalf("duplicate attestation error = %v", err)
	}
}

func mustParseLock(t *testing.T, data []byte) *Lock {
	t.Helper()
	lock, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v\n%s", err, data)
	}
	return lock
}

func discover(t *testing.T, root string) *plugins.Snapshot {
	t.Helper()
	snapshot, err := plugins.Discover(root)
	if err != nil {
		t.Fatalf("plugins.Discover() error = %v", err)
	}
	for _, report := range snapshot.Reports() {
		if report.Status != plugins.PluginStatusReady {
			t.Fatalf("plugin discovery report = %#v", report)
		}
	}
	return snapshot
}

func writeRunnablePlugin(
	t *testing.T,
	root string,
	directoryName string,
	pluginID string,
	version string,
	connectorIDs []string,
) pluginFixture {
	t.Helper()
	directory := filepath.Join(root, directoryName)
	entrypoint := "bin/connector"
	content := []byte(pluginID + "@" + version + "\n")
	writeTestFile(t, filepath.Join(directory, entrypoint), content, 0o755)
	writeTestFile(t, filepath.Join(directory, "schemas/config.schema.json"), []byte("{}\n"), 0o644)
	writeTestFile(t, filepath.Join(directory, "schemas/ui-hints.json"), []byte("{}\n"), 0o644)
	digestBytes := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	platform := runtime.GOOS + "/" + runtime.GOARCH

	connectors := make([]plugins.ConnectorSpec, len(connectorIDs))
	for index, connectorID := range connectorIDs {
		connectors[index] = plugins.ConnectorSpec{
			ID:            connectorID,
			DisplayName:   "Test " + connectorID,
			Description:   "Hermetic plugin lock reconciliation fixture.",
			LegacyDBTypes: []string{},
			Roles:         []plugins.Role{plugins.RoleDestination},
			Capabilities: []plugins.CapabilityRef{
				{Name: plugins.CapabilityControl, Version: 1},
			},
			RecordFormats: []plugins.RecordFormat{plugins.RecordFormatQValueProto},
			Stability:     plugins.LifecycleStable,
			Config: plugins.ConfigSpec{
				Schema:             "schemas/config.schema.json",
				UIHints:            "schemas/ui-hints.json",
				SchemaVersion:      1,
				SecretJSONPointers: []string{},
				Placeholder:        false,
			},
		}
	}
	manifest := plugins.Manifest{
		Schema:     "https://peerdb.io/schemas/plugin-manifest/v1alpha1.json",
		APIVersion: plugins.APIVersion,
		Kind:       plugins.ManifestKind,
		Metadata: plugins.PluginMetadata{
			ID:          pluginID,
			DisplayName: "Test plugin " + directoryName,
			Version:     version,
			Description: "Hermetic plugin lock reconciliation fixture.",
			Vendor:      "PeerDB tests",
			Homepage:    "https://example.test/plugins/" + directoryName,
			License:     "Apache-2.0",
		},
		Spec: plugins.PluginSpec{
			Lifecycle:    plugins.LifecycleStable,
			Protocol:     plugins.ProtocolVersion{Major: 1, Minor: 0},
			CoreVersions: plugins.VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"},
			Runtime:      plugins.RuntimeSpec{Mode: plugins.RuntimeModeProcess, Entrypoint: &entrypoint},
			Connectors:   connectors,
			Dependencies: []plugins.DependencySpec{},
		},
		Artifact: plugins.ArtifactSpec{
			Status: plugins.ArtifactStatusBuilt,
			Bundles: []plugins.ArtifactBundle{
				{Platform: platform, Digest: digest},
			},
		},
	}
	manifestData, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal plugin manifest: %v", err)
	}
	writeTestFile(t, filepath.Join(directory, plugins.ManifestFilename), manifestData, 0o644)
	manifestDigestBytes := sha256.Sum256(manifestData)
	return pluginFixture{
		id:             pluginID,
		version:        version,
		platform:       platform,
		digest:         digest,
		manifestDigest: "sha256:" + hex.EncodeToString(manifestDigestBytes[:]),
		connectors:     slices.Clone(connectorIDs),
	}
}

func lockedVerifiedEntryYAML(
	id string,
	version string,
	enabled bool,
	platform string,
	digest string,
	sourceType string,
	sourceReference string,
	connectors []string,
	manifestDigest string,
	protocolMajor int,
	protocolMinor int,
	trustIdentity string,
) string {
	entry := lockedEntryYAML(
		id,
		version,
		enabled,
		platform,
		digest,
		sourceType,
		sourceReference,
		connectors,
	)
	entry = strings.Replace(entry, defaultManifestDigest(), manifestDigest, 1)
	entry = strings.Replace(
		entry,
		"protocol: {major: 1, minor: 0}",
		"protocol: {major: "+strconv.Itoa(protocolMajor)+", minor: "+strconv.Itoa(protocolMinor)+"}",
		1,
	)
	return strings.Replace(entry, defaultTrustIdentity(), trustIdentity, 1)
}

func fixtureAttestation(fixture pluginFixture, trustIdentity string) VerifiedAttestation {
	return VerifiedAttestation{
		PluginKey:      fixture.id + "@" + fixture.version,
		ArtifactDigest: fixture.digest,
		ManifestDigest: fixture.manifestDigest,
		TrustIdentity:  trustIdentity,
	}
}

func writeTestFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write test file %s: %v", path, err)
	}
}
