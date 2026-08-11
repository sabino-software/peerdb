package pluginlock

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/PeerDB-io/peerdb/flow/connectors/plugins"
	"gopkg.in/yaml.v3"
)

var (
	pluginIDPattern    = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	platformPattern    = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+$`)
	digestPattern      = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	connectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

type lockDocument struct {
	Schema     string           `yaml:"$schema"`
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   metadataDocument `yaml:"metadata"`
	Plugins    []entryDocument  `yaml:"plugins"`
}

type metadataDocument struct {
	GeneratedBy string  `yaml:"generatedBy"`
	GeneratedAt *string `yaml:"generatedAt"`
}

type entryDocument struct {
	ID             string            `yaml:"id"`
	Version        string            `yaml:"version"`
	State          State             `yaml:"state"`
	Enabled        bool              `yaml:"enabled"`
	Platform       *string           `yaml:"platform"`
	Digest         *string           `yaml:"digest"`
	ManifestDigest *string           `yaml:"manifestDigest"`
	Protocol       *protocolDocument `yaml:"protocol"`
	TrustIdentity  *string           `yaml:"trustIdentity"`
	Source         sourceDocument    `yaml:"source"`
	Connectors     []string          `yaml:"connectors"`
}

type protocolDocument struct {
	Major int `yaml:"major"`
	Minor int `yaml:"minor"`
}

type sourceDocument struct {
	Type      SourceType `yaml:"type"`
	Reference string     `yaml:"reference"`
}

// ValidationError contains every independently detectable semantic problem in
// deterministic document order.
type ValidationError struct {
	problems []string
}

func (e *ValidationError) Error() string {
	return "invalid plugin lock: " + strings.Join(e.problems, "; ")
}

func (e *ValidationError) Problems() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.problems...)
}

// Parse decodes exactly one strict YAML document and validates the canonical
// v1alpha1 lock invariants. Unknown fields, duplicate mapping keys, aliases,
// missing required keys, and scalar type coercions are rejected.
func Parse(data []byte) (*Lock, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("plugin lock exceeds %d-byte limit", MaxBytes)
	}

	document := lockDocument{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("plugin lock is empty")
		}
		return nil, fmt.Errorf("decode plugin lock: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decode trailing YAML document: %w", err)
		}
		return nil, fmt.Errorf("plugin lock must contain exactly one YAML document")
	}

	var syntax yaml.Node
	if err := yaml.Unmarshal(data, &syntax); err != nil {
		return nil, fmt.Errorf("inspect plugin lock fields: %w", err)
	}
	if problems := inspectDocument(&syntax); len(problems) != 0 {
		return nil, &ValidationError{problems: problems}
	}
	if problems := validateDocument(document); len(problems) != 0 {
		return nil, &ValidationError{problems: problems}
	}

	return newLock(document), nil
}

// Load reads and parses a regular lock file.
func Load(path string) (*Lock, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat plugin lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("plugin lock must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("plugin lock must be a regular file")
	}
	if info.Size() > MaxBytes {
		return nil, fmt.Errorf("plugin lock exceeds %d-byte limit", MaxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open plugin lock: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened plugin lock: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("plugin lock changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read plugin lock: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("plugin lock exceeds %d-byte limit", MaxBytes)
	}
	return Parse(data)
}

func newLock(document lockDocument) *Lock {
	lock := &Lock{
		schema: document.Schema,
		metadata: Metadata{
			generatedBy: document.Metadata.GeneratedBy,
		},
		plugins: make([]Entry, len(document.Plugins)),
	}
	if document.Metadata.GeneratedAt != nil {
		lock.metadata.generatedAt, _ = time.Parse(time.RFC3339, *document.Metadata.GeneratedAt)
		lock.metadata.hasGeneratedAt = true
	}
	for index, source := range document.Plugins {
		entry := Entry{
			id:         source.ID,
			version:    source.Version,
			state:      source.State,
			enabled:    source.Enabled,
			source:     Source{typeName: source.Source.Type, reference: source.Source.Reference},
			connectors: append([]string(nil), source.Connectors...),
		}
		if source.Platform != nil {
			entry.platform = *source.Platform
			entry.hasPlatform = true
		}
		if source.Digest != nil {
			entry.digest = *source.Digest
			entry.hasDigest = true
		}
		if source.ManifestDigest != nil {
			entry.manifestDigest = *source.ManifestDigest
			entry.hasManifestDigest = true
		}
		if source.Protocol != nil {
			entry.protocol = ProtocolVersion{
				major: source.Protocol.Major,
				minor: source.Protocol.Minor,
			}
			entry.hasProtocol = true
		}
		if source.TrustIdentity != nil {
			entry.trustIdentity = *source.TrustIdentity
			entry.hasTrustIdentity = true
		}
		lock.plugins[index] = entry
	}
	return lock
}

func validateDocument(document lockDocument) []string {
	problems := make([]string, 0)
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(document.Schema) == "" {
		add("$schema must not be empty")
	}
	if document.APIVersion != APIVersion {
		add("apiVersion must be %q", APIVersion)
	}
	if document.Kind != Kind {
		add("kind must be %q", Kind)
	}
	if strings.TrimSpace(document.Metadata.GeneratedBy) == "" {
		add("metadata.generatedBy must not be empty")
	}
	if document.Metadata.GeneratedAt != nil {
		if _, err := time.Parse(time.RFC3339, *document.Metadata.GeneratedAt); err != nil {
			add("metadata.generatedAt must be an RFC 3339 date-time or null")
		}
	}

	seenKeys := make(map[string]int, len(document.Plugins))
	for index, entry := range document.Plugins {
		prefix := fmt.Sprintf("plugins[%d]", index)
		if !pluginIDPattern.MatchString(entry.ID) {
			add("%s.id must be a lowercase reverse-domain plugin id", prefix)
		}
		if err := plugins.ValidateSemanticVersion(entry.Version); err != nil {
			add("%s.version must be a semantic version", prefix)
		}
		key := entry.ID + "@" + entry.Version
		if previous, duplicate := seenKeys[key]; duplicate {
			add("%s duplicates plugin key %q from plugins[%d]", prefix, key, previous)
		} else {
			seenKeys[key] = index
		}
		switch entry.State {
		case StatePlanned:
			if entry.Enabled {
				add("%s.enabled must be false while state is planned", prefix)
			}
			if entry.Platform != nil {
				add("%s.platform must be null while state is planned", prefix)
			}
			if entry.Digest != nil {
				add("%s.digest must be null while state is planned", prefix)
			}
			if entry.ManifestDigest != nil {
				add("%s.manifestDigest must be null while state is planned", prefix)
			}
			if entry.Protocol != nil {
				add("%s.protocol must be null while state is planned", prefix)
			}
			if entry.TrustIdentity != nil {
				add("%s.trustIdentity must be null while state is planned", prefix)
			}
		case StateLocked:
			if entry.Platform == nil {
				add("%s.platform must be set while state is locked", prefix)
			}
			if entry.Digest == nil {
				add("%s.digest must be set while state is locked", prefix)
			}
			if entry.ManifestDigest == nil {
				add("%s.manifestDigest must be set while state is locked", prefix)
			}
			if entry.Protocol == nil {
				add("%s.protocol must be set while state is locked", prefix)
			}
			if entry.TrustIdentity == nil {
				add("%s.trustIdentity must be set while state is locked", prefix)
			}
		default:
			add("%s.state must be %q or %q", prefix, StatePlanned, StateLocked)
		}
		if entry.Platform != nil && !platformPattern.MatchString(*entry.Platform) {
			add("%s.platform must be a lowercase os/architecture pair", prefix)
		}
		if entry.Digest != nil && !digestPattern.MatchString(*entry.Digest) {
			add("%s.digest must be a lowercase sha256 digest", prefix)
		}
		if entry.ManifestDigest != nil && !digestPattern.MatchString(*entry.ManifestDigest) {
			add("%s.manifestDigest must be a lowercase sha256 digest", prefix)
		}
		if entry.Protocol != nil {
			if entry.Protocol.Major < 1 {
				add("%s.protocol.major must be at least 1", prefix)
			}
			if entry.Protocol.Minor < 0 {
				add("%s.protocol.minor must not be negative", prefix)
			}
		}
		if entry.TrustIdentity != nil && strings.TrimSpace(*entry.TrustIdentity) == "" {
			add("%s.trustIdentity must not be empty", prefix)
		}
		switch entry.Source.Type {
		case SourceLocal, SourceOCI, SourceGitHubRelease:
		default:
			add("%s.source.type is unsupported", prefix)
		}
		if strings.TrimSpace(entry.Source.Reference) == "" {
			add("%s.source.reference must not be empty", prefix)
		}
		if len(entry.Connectors) == 0 {
			add("%s.connectors must contain at least one connector id", prefix)
		}
		seenConnectors := make(map[string]int, len(entry.Connectors))
		for connectorIndex, connectorID := range entry.Connectors {
			if !connectorIDPattern.MatchString(connectorID) {
				add("%s.connectors[%d] must be a lowercase connector id", prefix, connectorIndex)
			}
			if previous, duplicate := seenConnectors[connectorID]; duplicate {
				add(
					"%s.connectors[%d] duplicates %q from connectors[%d]",
					prefix,
					connectorIndex,
					connectorID,
					previous,
				)
			} else {
				seenConnectors[connectorID] = connectorIndex
			}
		}
	}
	return problems
}

func inspectDocument(document *yaml.Node) []string {
	root := document
	if root.Kind == yaml.DocumentNode && len(root.Content) != 0 {
		root = root.Content[0]
	}
	problems := make([]string, 0)
	if containsAlias(root) {
		problems = append(problems, "YAML aliases are not allowed")
		return problems
	}
	if root.Kind != yaml.MappingNode {
		return append(problems, "document must be a mapping")
	}
	requireKeys(root, "", []string{"$schema", "apiVersion", "kind", "metadata", "plugins"}, &problems)
	requireString(mappingValue(root, "$schema"), "$schema", false, &problems)
	requireString(mappingValue(root, "apiVersion"), "apiVersion", false, &problems)
	requireString(mappingValue(root, "kind"), "kind", false, &problems)

	metadata := mappingValue(root, "metadata")
	requireMapping(metadata, "metadata", &problems)
	requireKeys(metadata, "metadata", []string{"generatedBy", "generatedAt"}, &problems)
	requireString(mappingValue(metadata, "generatedBy"), "metadata.generatedBy", false, &problems)
	requireNullableString(mappingValue(metadata, "generatedAt"), "metadata.generatedAt", true, &problems)

	pluginsNode := mappingValue(root, "plugins")
	requireSequence(pluginsNode, "plugins", &problems)
	if pluginsNode != nil && pluginsNode.Kind == yaml.SequenceNode {
		for index, entry := range pluginsNode.Content {
			prefix := fmt.Sprintf("plugins[%d]", index)
			requireMapping(entry, prefix, &problems)
			requireKeys(entry, prefix, []string{
				"id", "version", "state", "enabled", "platform", "digest", "manifestDigest",
				"protocol", "trustIdentity", "source", "connectors",
			}, &problems)
			requireString(mappingValue(entry, "id"), prefix+".id", false, &problems)
			requireString(mappingValue(entry, "version"), prefix+".version", false, &problems)
			requireString(mappingValue(entry, "state"), prefix+".state", false, &problems)
			requireBoolean(mappingValue(entry, "enabled"), prefix+".enabled", &problems)
			requireNullableString(mappingValue(entry, "platform"), prefix+".platform", false, &problems)
			requireNullableString(mappingValue(entry, "digest"), prefix+".digest", false, &problems)
			requireNullableString(mappingValue(entry, "manifestDigest"), prefix+".manifestDigest", false, &problems)
			requireNullableString(mappingValue(entry, "trustIdentity"), prefix+".trustIdentity", false, &problems)

			protocol := mappingValue(entry, "protocol")
			requireNullableMapping(protocol, prefix+".protocol", &problems)
			if protocol != nil && protocol.Kind == yaml.MappingNode {
				requireKeys(protocol, prefix+".protocol", []string{"major", "minor"}, &problems)
				requireInteger(mappingValue(protocol, "major"), prefix+".protocol.major", &problems)
				requireInteger(mappingValue(protocol, "minor"), prefix+".protocol.minor", &problems)
			}

			source := mappingValue(entry, "source")
			requireMapping(source, prefix+".source", &problems)
			requireKeys(source, prefix+".source", []string{"type", "reference"}, &problems)
			requireString(mappingValue(source, "type"), prefix+".source.type", false, &problems)
			requireString(mappingValue(source, "reference"), prefix+".source.reference", false, &problems)

			connectors := mappingValue(entry, "connectors")
			requireSequence(connectors, prefix+".connectors", &problems)
			if connectors != nil && connectors.Kind == yaml.SequenceNode {
				for connectorIndex, connector := range connectors.Content {
					requireString(
						connector,
						fmt.Sprintf("%s.connectors[%d]", prefix, connectorIndex),
						false,
						&problems,
					)
				}
			}
		}
	}
	return problems
}

func containsAlias(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsAlias(child) {
			return true
		}
	}
	return false
}

func requireKeys(node *yaml.Node, prefix string, keys []string, problems *[]string) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for _, key := range keys {
		if mappingValue(node, key) != nil {
			continue
		}
		if prefix == "" {
			*problems = append(*problems, key+" is required")
		} else {
			*problems = append(*problems, prefix+"."+key+" is required")
		}
	}
}

func requireMapping(node *yaml.Node, path string, problems *[]string) {
	if node != nil && node.Kind != yaml.MappingNode {
		*problems = append(*problems, path+" must be a mapping")
	}
}

func requireNullableMapping(node *yaml.Node, path string, problems *[]string) {
	if node == nil || node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return
	}
	requireMapping(node, path, problems)
}

func requireSequence(node *yaml.Node, path string, problems *[]string) {
	if node != nil && node.Kind != yaml.SequenceNode {
		*problems = append(*problems, path+" must be a sequence")
	}
}

func requireString(node *yaml.Node, path string, allowTimestamp bool, problems *[]string) {
	if node == nil {
		return
	}
	validTag := node.Tag == "!!str" || allowTimestamp && node.Tag == "!!timestamp"
	if node.Kind != yaml.ScalarNode || !validTag {
		*problems = append(*problems, path+" must be a string")
	}
}

func requireNullableString(node *yaml.Node, path string, allowTimestamp bool, problems *[]string) {
	if node == nil {
		return
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return
	}
	requireString(node, path, allowTimestamp, problems)
}

func requireBoolean(node *yaml.Node, path string, problems *[]string) {
	if node == nil {
		return
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		*problems = append(*problems, path+" must be a boolean")
	}
}

func requireInteger(node *yaml.Node, path string, problems *[]string) {
	if node == nil {
		return
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
		*problems = append(*problems, path+" must be an integer")
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}
