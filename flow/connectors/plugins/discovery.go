package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// PluginStatus is the inventory outcome for one discovered manifest.
type PluginStatus string

const (
	PluginStatusPlanned  PluginStatus = "planned"
	PluginStatusReady    PluginStatus = "ready"
	PluginStatusRejected PluginStatus = "rejected"
)

// IssueCode is a stable, machine-readable discovery failure category.
type IssueCode string

const (
	IssueManifestLoad          IssueCode = "manifest-load"
	IssueValidation            IssueCode = "validation"
	IssueArtifactDigest        IssueCode = "artifact-digest"
	IssueUnsupportedPlatform   IssueCode = "unsupported-platform"
	IssueDuplicatePlugin       IssueCode = "duplicate-plugin"
	IssueDuplicateConnector    IssueCode = "duplicate-connector"
	IssueMissingDependency     IssueCode = "missing-dependency"
	IssueDependencyVersion     IssueCode = "dependency-version"
	IssueDependencyUnavailable IssueCode = "dependency-unavailable"
	IssueDependencyCycle       IssueCode = "dependency-cycle"
)

// Issue describes why a manifest was rejected. Message is intended for
// operators; callers should branch on Code.
type Issue struct {
	Code    IssueCode
	Message string
}

// Report is the inventory result for one peerdb-plugin.yaml file. Planned
// manifests are represented here without being exposed as runnable Descriptors.
type Report struct {
	ManifestPath  string
	PluginID      string
	PluginVersion string
	PluginKey     string
	Lifecycle     Lifecycle
	ConnectorIDs  []string
	Status        PluginStatus
	Issues        []Issue
}

// PluginReference pins one installed plugin version.
type PluginReference struct {
	ID      string
	Version string
}

func (r PluginReference) Key() string {
	return PluginKey(r.ID, r.Version)
}

// PluginKey returns the stable in-memory registry identity for a plugin
// version. Plugin IDs cannot contain '@', so the representation is unambiguous.
func PluginKey(pluginID string, version string) string {
	return pluginID + "@" + version
}

// Descriptor is an immutable view of a ready plugin. Its fields are private and
// Manifest returns a deep copy, preventing callers from mutating a Snapshot.
type Descriptor struct {
	directory      string
	manifestPath   string
	manifestSHA256 string
	entrypoint     string
	bundle         ArtifactBundle
	dependencies   []PluginReference
	manifest       Manifest
}

func (d Descriptor) ID() string {
	return d.manifest.Metadata.ID
}

func (d Descriptor) Version() string {
	return d.manifest.Metadata.Version
}

func (d Descriptor) Key() string {
	return PluginKey(d.ID(), d.Version())
}

func (d Descriptor) Directory() string {
	return d.directory
}

func (d Descriptor) ManifestPath() string {
	return d.manifestPath
}

// ManifestSHA256 is the canonical digest of the exact manifest bytes captured
// and parsed by discovery. It never rereads ManifestPath.
func (d Descriptor) ManifestSHA256() string {
	return d.manifestSHA256
}

func (d Descriptor) Entrypoint() string {
	return d.entrypoint
}

func (d Descriptor) Platform() string {
	return d.bundle.Platform
}

func (d Descriptor) SHA256() string {
	return d.bundle.Digest
}

func (d Descriptor) Dependencies() []PluginReference {
	return append([]PluginReference(nil), d.dependencies...)
}

func (d Descriptor) Manifest() Manifest {
	return cloneManifest(d.manifest)
}

// Snapshot is the complete result of one directory scan. A Snapshot never
// changes after Discover returns; a caller performs a new scan to observe disk
// changes.
type Snapshot struct {
	root        string
	descriptors []Descriptor
	loadOrder   []string
	reports     []Report
}

func (s *Snapshot) Root() string {
	return s.root
}

// Descriptors returns runnable plugins in dependency load order.
func (s *Snapshot) Descriptors() []Descriptor {
	descriptors := make([]Descriptor, len(s.descriptors))
	for index, descriptor := range s.descriptors {
		descriptors[index] = cloneDescriptor(descriptor)
	}
	return descriptors
}

// Descriptor resolves an exact id@version key.
func (s *Snapshot) Descriptor(key string) (Descriptor, bool) {
	for _, descriptor := range s.descriptors {
		if descriptor.Key() == key {
			return cloneDescriptor(descriptor), true
		}
	}
	return Descriptor{}, false
}

func (s *Snapshot) LoadOrder() []string {
	return append([]string(nil), s.loadOrder...)
}

func (s *Snapshot) Reports() []Report {
	reports := make([]Report, len(s.reports))
	for index, report := range s.reports {
		reports[index] = cloneReport(report)
	}
	return reports
}

type mutableReport struct {
	report Report
}

func (r *mutableReport) addIssue(code IssueCode, message string) bool {
	for _, issue := range r.report.Issues {
		if issue.Code == code && issue.Message == message {
			return false
		}
	}
	r.report.Issues = append(r.report.Issues, Issue{Code: code, Message: message})
	return true
}

type candidate struct {
	descriptor           Descriptor
	report               *mutableReport
	resolvedDependencies []*candidate
	runnable             bool
	rejected             bool
}

func (c *candidate) reject(code IssueCode, message string) bool {
	added := c.report.addIssue(code, message)
	c.rejected = true
	return added
}

// Discover recursively scans root for peerdb-plugin.yaml files, validates the
// entire inventory, verifies current-platform runnable artifacts, and returns
// ready descriptors in dependency order. A bad plugin is isolated in Reports;
// traversal failures are returned because they make the snapshot incomplete.
func Discover(root string) (*Snapshot, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin root: %w", err)
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("stat plugin root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("plugin root must be a directory")
	}

	manifestPaths := make([]string, 0)
	err = filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && entry.Name() == ManifestFilename {
			manifestPaths = append(manifestPaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan plugin root: %w", err)
	}
	sort.Strings(manifestPaths)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	reports := make([]*mutableReport, 0, len(manifestPaths))
	candidates := make([]*candidate, 0, len(manifestPaths))
	for _, manifestPath := range manifestPaths {
		report := &mutableReport{report: Report{
			ManifestPath: manifestPath,
			Status:       PluginStatusRejected,
		}}
		reports = append(reports, report)

		manifest, manifestBytes, loadErr := loadManifest(manifestPath)
		if loadErr != nil {
			report.addIssue(IssueManifestLoad, loadErr.Error())
			continue
		}
		manifestDigest := sha256.Sum256(manifestBytes)
		manifestSHA256 := "sha256:" + hex.EncodeToString(manifestDigest[:])
		populateReportIdentity(report, manifest)
		pluginDir := filepath.Dir(manifestPath)
		if validationErr := ValidateManifest(manifest, pluginDir); validationErr != nil {
			addValidationIssues(report, validationErr)
			continue
		}

		candidate := &candidate{
			descriptor: Descriptor{
				directory:      pluginDir,
				manifestPath:   manifestPath,
				manifestSHA256: manifestSHA256,
				manifest:       cloneManifest(manifest),
			},
			report:   report,
			runnable: manifest.Spec.Lifecycle != LifecyclePlanned,
		}
		if candidate.runnable {
			bundle, supported := artifactBundleForPlatform(manifest, platform)
			if !supported {
				candidate.reject(
					IssueUnsupportedPlatform,
					fmt.Sprintf("plugin does not declare an artifact bundle for %q", platform),
				)
				candidates = append(candidates, candidate)
				continue
			}
			if verifyErr := VerifyArtifact(manifest, pluginDir, platform); verifyErr != nil {
				candidate.reject(IssueArtifactDigest, verifyErr.Error())
				candidates = append(candidates, candidate)
				continue
			}
			entrypoint, resolveErr := resolveContainedFile(pluginDir, *manifest.Spec.Runtime.Entrypoint)
			if resolveErr != nil {
				candidate.reject(IssueValidation, "spec.runtime.entrypoint: "+resolveErr.Error())
				candidates = append(candidates, candidate)
				continue
			}
			candidate.descriptor.entrypoint = entrypoint
			candidate.descriptor.bundle = bundle
		}
		candidates = append(candidates, candidate)
	}

	providersByKey := groupPluginProvidersByKey(candidates)
	rejectDuplicatePluginVersions(providersByKey)
	rejectDuplicateConnectorIDs(candidates)
	providersByID := groupPluginProvidersByID(candidates)
	resolveDependencies(candidates, providersByID)
	propagateRequiredDependencyFailures(candidates)
	rejectDependencyCycles(candidates)
	propagateRequiredDependencyFailures(candidates)
	finalizeResolvedDependencies(candidates)

	ordered, orderErr := orderCandidates(candidates)
	if orderErr != nil {
		return nil, orderErr
	}
	descriptors := make([]Descriptor, 0, len(ordered))
	loadOrder := make([]string, 0, len(ordered))
	for _, candidate := range ordered {
		descriptors = append(descriptors, cloneDescriptor(candidate.descriptor))
		loadOrder = append(loadOrder, candidate.descriptor.Key())
	}

	finalReports := make([]Report, len(reports))
	for index, report := range reports {
		switch {
		case len(report.report.Issues) != 0:
			report.report.Status = PluginStatusRejected
		case report.report.Lifecycle == LifecyclePlanned:
			report.report.Status = PluginStatusPlanned
		default:
			report.report.Status = PluginStatusReady
		}
		finalReports[index] = cloneReport(report.report)
	}

	return &Snapshot{
		root:        rootPath,
		descriptors: descriptors,
		loadOrder:   loadOrder,
		reports:     finalReports,
	}, nil
}

func populateReportIdentity(report *mutableReport, manifest Manifest) {
	report.report.PluginID = manifest.Metadata.ID
	report.report.PluginVersion = manifest.Metadata.Version
	report.report.PluginKey = PluginKey(manifest.Metadata.ID, manifest.Metadata.Version)
	report.report.Lifecycle = manifest.Spec.Lifecycle
	report.report.ConnectorIDs = make([]string, len(manifest.Spec.Connectors))
	for index, connector := range manifest.Spec.Connectors {
		report.report.ConnectorIDs[index] = connector.ID
	}
}

func addValidationIssues(report *mutableReport, validationErr error) {
	var details *ValidationError
	if errors.As(validationErr, &details) {
		for _, problem := range details.Problems {
			report.addIssue(IssueValidation, problem)
		}
		return
	}
	report.addIssue(IssueValidation, validationErr.Error())
}

func groupPluginProvidersByKey(candidates []*candidate) map[string][]*candidate {
	providers := make(map[string][]*candidate, len(candidates))
	for _, candidate := range candidates {
		providers[candidate.descriptor.Key()] = append(
			providers[candidate.descriptor.Key()],
			candidate,
		)
	}
	return providers
}

func groupPluginProvidersByID(candidates []*candidate) map[string][]*candidate {
	providers := make(map[string][]*candidate, len(candidates))
	for _, candidate := range candidates {
		providers[candidate.descriptor.ID()] = append(
			providers[candidate.descriptor.ID()],
			candidate,
		)
	}
	return providers
}

func rejectDuplicatePluginVersions(providers map[string][]*candidate) {
	for _, pluginKey := range sortedProviderIDs(providers) {
		matches := providers[pluginKey]
		if len(matches) < 2 {
			continue
		}
		paths := make([]string, len(matches))
		for index, match := range matches {
			paths[index] = match.descriptor.ManifestPath()
		}
		sort.Strings(paths)
		message := fmt.Sprintf("plugin version %q is declared by %s", pluginKey, strings.Join(paths, ", "))
		for _, match := range matches {
			match.reject(IssueDuplicatePlugin, message)
		}
	}
}

// The same connector ID may appear in side-by-side versions of one plugin ID.
// It is a collision only when different plugin IDs claim that connector.
func rejectDuplicateConnectorIDs(candidates []*candidate) {
	providers := make(map[string]map[string][]*candidate)
	for _, candidate := range candidates {
		for _, connector := range candidate.descriptor.manifest.Spec.Connectors {
			if providers[connector.ID] == nil {
				providers[connector.ID] = make(map[string][]*candidate)
			}
			pluginID := candidate.descriptor.ID()
			providers[connector.ID][pluginID] = append(providers[connector.ID][pluginID], candidate)
		}
	}
	connectorIDs := make([]string, 0, len(providers))
	for connectorID := range providers {
		connectorIDs = append(connectorIDs, connectorID)
	}
	sort.Strings(connectorIDs)
	for _, connectorID := range connectorIDs {
		matchesByPlugin := providers[connectorID]
		if len(matchesByPlugin) < 2 {
			continue
		}
		pluginIDs := make([]string, 0, len(matchesByPlugin))
		for pluginID := range matchesByPlugin {
			pluginIDs = append(pluginIDs, pluginID)
		}
		sort.Strings(pluginIDs)
		message := fmt.Sprintf("connector id %q is declared by plugins %s", connectorID, strings.Join(pluginIDs, ", "))
		for _, pluginID := range pluginIDs {
			for _, match := range matchesByPlugin[pluginID] {
				match.reject(IssueDuplicateConnector, message)
			}
		}
	}
}

func resolveDependencies(candidates []*candidate, providers map[string][]*candidate) {
	for _, candidate := range candidates {
		if candidate.rejected || !candidate.runnable {
			continue
		}
		for _, dependency := range candidate.descriptor.manifest.Spec.Dependencies {
			matches := make([]*candidate, 0)
			hasRunnableProvider := false
			hasMatchingProvider := false
			for _, provider := range providers[dependency.ID] {
				if provider.runnable {
					hasRunnableProvider = true
				}
				if provider.runnable && versionInRange(provider.descriptor.Version(), dependency.Versions) {
					hasMatchingProvider = true
				}
				if provider.runnable && !provider.rejected && hasMatchingProvider &&
					versionInRange(provider.descriptor.Version(), dependency.Versions) {
					matches = append(matches, provider)
				}
			}
			if len(matches) == 0 {
				switch {
				case len(providers[dependency.ID]) == 0:
					candidate.reject(
						IssueMissingDependency,
						fmt.Sprintf("required plugin %q was not discovered", dependency.ID),
					)
				case !hasRunnableProvider || hasMatchingProvider:
					candidate.reject(
						IssueDependencyUnavailable,
						fmt.Sprintf("required plugin %q has no runnable version", dependency.ID),
					)
				default:
					candidate.reject(
						IssueDependencyVersion,
						fmt.Sprintf(
							"required plugin %q has no version in [%s, %s)",
							dependency.ID,
							dependency.Versions.Minimum,
							dependency.Versions.MaximumExclusive,
						),
					)
				}
				break
			}
			sort.Slice(matches, func(left, right int) bool {
				leftVersion, _ := parseSemanticVersion(matches[left].descriptor.Version())
				rightVersion, _ := parseSemanticVersion(matches[right].descriptor.Version())
				comparison := compareSemanticVersions(leftVersion, rightVersion)
				if comparison != 0 {
					return comparison > 0
				}
				return matches[left].descriptor.Key() < matches[right].descriptor.Key()
			})
			candidate.resolvedDependencies = append(candidate.resolvedDependencies, matches[0])
		}
	}
}

func propagateRequiredDependencyFailures(candidates []*candidate) {
	for {
		changed := false
		for _, candidate := range candidates {
			if candidate.rejected || !candidate.runnable {
				continue
			}
			for _, dependency := range candidate.resolvedDependencies {
				if dependency.rejected {
					changed = candidate.reject(
						IssueDependencyUnavailable,
						fmt.Sprintf("required plugin %q is unavailable", dependency.descriptor.Key()),
					) || changed
					break
				}
			}
		}
		if !changed {
			return
		}
	}
}

func rejectDependencyCycles(candidates []*candidate) {
	active := activeCandidatesByKey(candidates)
	index := 0
	indices := make(map[string]int, len(active))
	lowlinks := make(map[string]int, len(active))
	onStack := make(map[string]bool, len(active))
	stack := make([]string, 0, len(active))

	var visit func(string)
	visit = func(pluginKey string) {
		indices[pluginKey] = index
		lowlinks[pluginKey] = index
		index++
		stack = append(stack, pluginKey)
		onStack[pluginKey] = true

		for _, dependencyKey := range activeDependencyKeys(active[pluginKey]) {
			if _, exists := active[dependencyKey]; !exists {
				continue
			}
			if _, visited := indices[dependencyKey]; !visited {
				visit(dependencyKey)
				if lowlinks[dependencyKey] < lowlinks[pluginKey] {
					lowlinks[pluginKey] = lowlinks[dependencyKey]
				}
			} else if onStack[dependencyKey] && indices[dependencyKey] < lowlinks[pluginKey] {
				lowlinks[pluginKey] = indices[dependencyKey]
			}
		}

		if lowlinks[pluginKey] != indices[pluginKey] {
			return
		}
		component := make([]string, 0)
		for {
			last := len(stack) - 1
			member := stack[last]
			stack = stack[:last]
			onStack[member] = false
			component = append(component, member)
			if member == pluginKey {
				break
			}
		}
		if len(component) > 1 {
			sort.Strings(component)
			message := "dependency cycle contains plugins " + strings.Join(component, ", ")
			for _, member := range component {
				active[member].reject(IssueDependencyCycle, message)
			}
		}
	}

	pluginKeys := make([]string, 0, len(active))
	for pluginKey := range active {
		pluginKeys = append(pluginKeys, pluginKey)
	}
	sort.Strings(pluginKeys)
	for _, pluginKey := range pluginKeys {
		if _, visited := indices[pluginKey]; !visited {
			visit(pluginKey)
		}
	}
}

func orderCandidates(candidates []*candidate) ([]*candidate, error) {
	active := activeCandidatesByKey(candidates)
	indegree := make(map[string]int, len(active))
	outgoing := make(map[string][]string, len(active))
	for pluginKey := range active {
		indegree[pluginKey] = 0
	}
	for pluginKey, candidate := range active {
		for _, dependencyKey := range activeDependencyKeys(candidate) {
			if _, exists := active[dependencyKey]; !exists {
				continue
			}
			indegree[pluginKey]++
			outgoing[dependencyKey] = append(outgoing[dependencyKey], pluginKey)
		}
	}
	for dependencyKey := range outgoing {
		sort.Strings(outgoing[dependencyKey])
	}

	ready := make([]string, 0, len(active))
	for pluginKey, degree := range indegree {
		if degree == 0 {
			ready = append(ready, pluginKey)
		}
	}
	sort.Strings(ready)
	ordered := make([]*candidate, 0, len(active))
	for len(ready) != 0 {
		pluginKey := ready[0]
		ready = ready[1:]
		ordered = append(ordered, active[pluginKey])
		for _, dependentKey := range outgoing[pluginKey] {
			indegree[dependentKey]--
			if indegree[dependentKey] == 0 {
				ready = append(ready, dependentKey)
				sort.Strings(ready)
			}
		}
	}
	if len(ordered) != len(active) {
		return nil, fmt.Errorf("internal error: unresolved plugin dependency cycle")
	}
	return ordered, nil
}

func activeCandidatesByKey(candidates []*candidate) map[string]*candidate {
	active := make(map[string]*candidate, len(candidates))
	for _, candidate := range candidates {
		if candidate.runnable && !candidate.rejected {
			active[candidate.descriptor.Key()] = candidate
		}
	}
	return active
}

func activeDependencyKeys(candidate *candidate) []string {
	dependencyKeys := make([]string, 0, len(candidate.resolvedDependencies))
	for _, dependency := range candidate.resolvedDependencies {
		if dependency.runnable && !dependency.rejected {
			dependencyKeys = append(dependencyKeys, dependency.descriptor.Key())
		}
	}
	sort.Strings(dependencyKeys)
	return dependencyKeys
}

func finalizeResolvedDependencies(candidates []*candidate) {
	for _, candidate := range candidates {
		if candidate.rejected || !candidate.runnable {
			continue
		}
		candidate.descriptor.dependencies = make(
			[]PluginReference,
			0,
			len(candidate.resolvedDependencies),
		)
		for _, dependency := range candidate.resolvedDependencies {
			candidate.descriptor.dependencies = append(candidate.descriptor.dependencies, PluginReference{
				ID:      dependency.descriptor.ID(),
				Version: dependency.descriptor.Version(),
			})
		}
	}
}

func sortedProviderIDs(providers map[string][]*candidate) []string {
	pluginIDs := make([]string, 0, len(providers))
	for pluginID := range providers {
		pluginIDs = append(pluginIDs, pluginID)
	}
	sort.Strings(pluginIDs)
	return pluginIDs
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	clone := descriptor
	clone.dependencies = append([]PluginReference(nil), descriptor.dependencies...)
	clone.manifest = cloneManifest(descriptor.manifest)
	return clone
}

func cloneReport(report Report) Report {
	clone := report
	clone.ConnectorIDs = append([]string(nil), report.ConnectorIDs...)
	clone.Issues = append([]Issue(nil), report.Issues...)
	return clone
}
