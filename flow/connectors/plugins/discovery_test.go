package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDiscoverPlannedInventory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := plannedManifest("io.peerdb.test.planned", "0.0.0-dev", "planned")
	writeManifest(t, filepath.Join(root, "planned"), manifest)

	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(snapshot.Descriptors()) != 0 || len(snapshot.LoadOrder()) != 0 {
		t.Fatalf("planned plugin became runnable: %#v", snapshot.Descriptors())
	}
	reports := snapshot.Reports()
	if len(reports) != 1 || reports[0].Status != PluginStatusPlanned {
		t.Fatalf("Discover() reports = %#v, want one planned report", reports)
	}
	if !slices.Equal(reports[0].ConnectorIDs, []string{"planned"}) {
		t.Fatalf("planned connector inventory = %v", reports[0].ConnectorIDs)
	}
}

func TestDiscoverSideBySideVersionsAndDependencies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, version := range []string{"1.0.0", "1.5.0", "2.0.0"} {
		dir := filepath.Join(root, "base-"+version)
		manifest := runnableManifest(t, dir, "io.peerdb.test.base", version, "base")
		writeManifest(t, dir, manifest)
	}
	childDir := filepath.Join(root, "child")
	child := runnableManifest(t, childDir, "io.peerdb.test.child", "1.0.0", "child")
	child.Spec.Dependencies = []DependencySpec{
		{
			ID: "io.peerdb.test.base",
			Versions: VersionRange{
				Minimum:          "1.0.0",
				MaximumExclusive: "2.0.0",
			},
		},
	}
	writeManifest(t, childDir, child)

	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got, want := len(snapshot.Descriptors()), 4; got != want {
		t.Fatalf("len(Descriptors()) = %d, want %d; reports = %#v", got, want, snapshot.Reports())
	}
	childDescriptor, found := snapshot.Descriptor(PluginKey("io.peerdb.test.child", "1.0.0"))
	if !found {
		t.Fatal("exact child descriptor not found")
	}
	dependencies := childDescriptor.Dependencies()
	if len(dependencies) != 1 || dependencies[0].Version != "1.5.0" {
		t.Fatalf("resolved dependencies = %#v, want highest compatible 1.5.0", dependencies)
	}
	order := snapshot.LoadOrder()
	baseIndex := slices.Index(order, PluginKey("io.peerdb.test.base", "1.5.0"))
	childIndex := slices.Index(order, PluginKey("io.peerdb.test.child", "1.0.0"))
	if baseIndex < 0 || childIndex < 0 || baseIndex >= childIndex {
		t.Fatalf("dependency order = %v", order)
	}
	for _, report := range snapshot.Reports() {
		if report.Status != PluginStatusReady {
			t.Fatalf("side-by-side report = %#v, want ready", report)
		}
	}
}

func TestDiscoverDuplicateRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		manifests []struct {
			dir       string
			pluginID  string
			version   string
			connector string
		}
		wantCode IssueCode
	}{
		{
			name: "same plugin version",
			manifests: []struct {
				dir       string
				pluginID  string
				version   string
				connector string
			}{
				{dir: "one", pluginID: "io.peerdb.test.same", version: "1.0.0", connector: "same"},
				{dir: "two", pluginID: "io.peerdb.test.same", version: "1.0.0", connector: "same"},
			},
			wantCode: IssueDuplicatePlugin,
		},
		{
			name: "connector claimed by different plugin ids",
			manifests: []struct {
				dir       string
				pluginID  string
				version   string
				connector string
			}{
				{dir: "one", pluginID: "io.peerdb.test.one", version: "1.0.0", connector: "claimed"},
				{dir: "two", pluginID: "io.peerdb.test.two", version: "2.0.0", connector: "claimed"},
			},
			wantCode: IssueDuplicateConnector,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for _, item := range test.manifests {
				dir := filepath.Join(root, item.dir)
				manifest := runnableManifest(t, dir, item.pluginID, item.version, item.connector)
				writeManifest(t, dir, manifest)
			}
			snapshot, err := Discover(root)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(snapshot.Descriptors()) != 0 {
				t.Fatalf("duplicate manifests became ready: %#v", snapshot.Descriptors())
			}
			for _, report := range snapshot.Reports() {
				if report.Status != PluginStatusRejected || !reportHasIssue(report, test.wantCode) {
					t.Fatalf("duplicate report = %#v, want %q", report, test.wantCode)
				}
			}
		})
	}
}

func TestDiscoverDependencyFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		addProvider func(*testing.T, string)
		wantCode    IssueCode
	}{
		{name: "missing", wantCode: IssueMissingDependency},
		{
			name: "incompatible version",
			addProvider: func(t *testing.T, root string) {
				dir := filepath.Join(root, "base")
				writeManifest(t, dir, runnableManifest(t, dir, "io.peerdb.test.base", "2.0.0", "base"))
			},
			wantCode: IssueDependencyVersion,
		},
		{
			name: "planned provider",
			addProvider: func(t *testing.T, root string) {
				dir := filepath.Join(root, "base")
				writeManifest(t, dir, plannedManifest("io.peerdb.test.base", "1.0.0", "base"))
			},
			wantCode: IssueDependencyUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.addProvider != nil {
				test.addProvider(t, root)
			}
			childDir := filepath.Join(root, "child")
			child := runnableManifest(t, childDir, "io.peerdb.test.child", "1.0.0", "child")
			child.Spec.Dependencies = []DependencySpec{
				{
					ID: "io.peerdb.test.base",
					Versions: VersionRange{
						Minimum:          "1.0.0",
						MaximumExclusive: "2.0.0",
					},
				},
			}
			writeManifest(t, childDir, child)

			snapshot, err := Discover(root)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			report := reportFor(snapshot.Reports(), child.Metadata.ID)
			if report.Status != PluginStatusRejected || !reportHasIssue(report, test.wantCode) {
				t.Fatalf("dependency report = %#v, want %q", report, test.wantCode)
			}
		})
	}
}

func TestDiscoverDependencyCycle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	aDir := filepath.Join(root, "a")
	bDir := filepath.Join(root, "b")
	a := runnableManifest(t, aDir, "io.peerdb.test.a", "1.0.0", "a")
	b := runnableManifest(t, bDir, "io.peerdb.test.b", "1.0.0", "b")
	a.Spec.Dependencies = []DependencySpec{{
		ID:       b.Metadata.ID,
		Versions: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"},
	}}
	b.Spec.Dependencies = []DependencySpec{{
		ID:       a.Metadata.ID,
		Versions: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"},
	}}
	writeManifest(t, aDir, a)
	writeManifest(t, bDir, b)

	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(snapshot.Descriptors()) != 0 {
		t.Fatalf("cyclic descriptors became ready: %#v", snapshot.Descriptors())
	}
	for _, report := range snapshot.Reports() {
		if !reportHasIssue(report, IssueDependencyCycle) {
			t.Fatalf("cycle report = %#v", report)
		}
	}
}

func TestDiscoverArtifactFailuresAreIsolated(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	goodDir := filepath.Join(root, "good")
	writeManifest(t, goodDir, runnableManifest(t, goodDir, "io.peerdb.test.good", "1.0.0", "good"))

	badDigestDir := filepath.Join(root, "bad-digest")
	badDigest := runnableManifest(t, badDigestDir, "io.peerdb.test.bad-digest", "1.0.0", "bad-digest")
	badDigest.Artifact.Bundles[0].Digest = "sha256:" + strings.Repeat("0", 64)
	writeManifest(t, badDigestDir, badDigest)

	badPlatformDir := filepath.Join(root, "bad-platform")
	badPlatform := runnableManifest(t, badPlatformDir, "io.peerdb.test.bad-platform", "1.0.0", "bad-platform")
	unsupportedPlatform := "plan9/amd64"
	if unsupportedPlatform == runtime.GOOS+"/"+runtime.GOARCH {
		unsupportedPlatform = "aix/ppc64"
	}
	badPlatform.Artifact.Bundles[0].Platform = unsupportedPlatform
	writeManifest(t, badPlatformDir, badPlatform)

	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := snapshot.LoadOrder(); !slices.Equal(got, []string{PluginKey("io.peerdb.test.good", "1.0.0")}) {
		t.Fatalf("LoadOrder() = %v", got)
	}
	if !reportHasIssue(reportFor(snapshot.Reports(), badDigest.Metadata.ID), IssueArtifactDigest) {
		t.Fatalf("digest failure not reported: %#v", snapshot.Reports())
	}
	if !reportHasIssue(reportFor(snapshot.Reports(), badPlatform.Metadata.ID), IssueUnsupportedPlatform) {
		t.Fatalf("platform failure not reported: %#v", snapshot.Reports())
	}
}

func TestSnapshotIsImmutable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "immutable")
	manifest := runnableManifest(t, dir, "io.peerdb.test.immutable", "1.0.0", "immutable")
	writeManifest(t, dir, manifest)
	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	descriptors := snapshot.Descriptors()
	descriptors[0].manifest.Metadata.ID = "mutated"
	descriptors[0].manifest.Spec.Connectors[0].Roles[0] = RoleSource
	copy := descriptors[0].Manifest()
	copy.Spec.Connectors[0].Config.SecretJSONPointers[0] = "/changed"

	reports := snapshot.Reports()
	reports[0].ConnectorIDs[0] = "mutated"
	reports[0].Issues = append(reports[0].Issues, Issue{Code: IssueValidation, Message: "mutated"})
	order := snapshot.LoadOrder()
	order[0] = "mutated"

	freshDescriptor, found := snapshot.Descriptor(PluginKey(manifest.Metadata.ID, manifest.Metadata.Version))
	if !found || freshDescriptor.ID() != manifest.Metadata.ID {
		t.Fatalf("snapshot descriptor was mutated: %#v", freshDescriptor)
	}
	freshManifest := freshDescriptor.Manifest()
	if freshManifest.Spec.Connectors[0].Roles[0] != RoleDestination ||
		freshManifest.Spec.Connectors[0].Config.SecretJSONPointers[0] != "/password" {
		t.Fatalf("nested manifest data was mutated: %#v", freshManifest.Spec.Connectors[0])
	}
	if snapshot.Reports()[0].ConnectorIDs[0] != "immutable" || len(snapshot.Reports()[0].Issues) != 0 {
		t.Fatalf("snapshot report was mutated: %#v", snapshot.Reports()[0])
	}
	if snapshot.LoadOrder()[0] != PluginKey(manifest.Metadata.ID, manifest.Metadata.Version) {
		t.Fatalf("snapshot order was mutated: %v", snapshot.LoadOrder())
	}
}

func TestDescriptorCapturesExactManifestBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "captured")
	manifest := runnableManifest(t, dir, "io.peerdb.test.captured", "1.0.0", "captured")
	manifestPath := writeManifest(t, dir, manifest)
	originalBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	originalDigest := sha256.Sum256(originalBytes)
	wantDigest := "sha256:" + hex.EncodeToString(originalDigest[:])

	snapshot, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("swapped after discovery\n"), 0o644); err != nil {
		t.Fatalf("swap manifest after discovery: %v", err)
	}

	descriptor, found := snapshot.Descriptor(PluginKey(manifest.Metadata.ID, manifest.Metadata.Version))
	if !found {
		t.Fatal("captured descriptor not found")
	}
	if got := descriptor.ManifestSHA256(); got != wantDigest {
		t.Fatalf("ManifestSHA256() = %q, want captured digest %q", got, wantDigest)
	}
	if got := descriptor.Manifest().Metadata.Version; got != manifest.Metadata.Version {
		t.Fatalf("captured manifest version = %q, want %q", got, manifest.Metadata.Version)
	}
}

func TestDiscoverRejectsNonDirectoryRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, []byte("not a directory"))
	if _, err := Discover(path); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("Discover() error = %v, want directory error", err)
	}
}

func reportHasIssue(report Report, code IssueCode) bool {
	for _, issue := range report.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func reportFor(reports []Report, pluginID string) Report {
	for _, report := range reports {
		if report.PluginID == pluginID {
			return report
		}
	}
	return Report{}
}

func TestRuntimePlatformMatchesFixtureConvention(t *testing.T) {
	t.Parallel()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !platformPattern.MatchString(platform) {
		t.Fatalf("runtime platform %q does not match manifest convention", platform)
	}
}
