package plugins

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// MaxManifestBytes bounds memory use before YAML decoding. Plugin binaries,
	// schemas, and UI metadata belong in separate files referenced by a manifest.
	MaxManifestBytes = 1 << 20
)

// ParseManifest decodes exactly one YAML document. Unknown fields and duplicate
// mapping keys are rejected so misspelled security- or compatibility-sensitive
// settings cannot be silently ignored.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d-byte limit", MaxManifestBytes)
	}

	manifest := Manifest{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		if err == io.EOF {
			return Manifest{}, fmt.Errorf("manifest is empty")
		}
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return Manifest{}, fmt.Errorf("decode trailing YAML document: %w", err)
		}
		return Manifest{}, fmt.Errorf("manifest must contain exactly one YAML document")
	}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Manifest{}, fmt.Errorf("inspect manifest fields: %w", err)
	}
	if containsYAMLAlias(&document) {
		return Manifest{}, fmt.Errorf("manifest YAML aliases are not allowed")
	}
	missing := requiredFieldProblems(&document)
	if len(missing) != 0 {
		return Manifest{}, fmt.Errorf("manifest is missing required fields: %s", strings.Join(missing, ", "))
	}
	return manifest, nil
}

func containsYAMLAlias(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsYAMLAlias(child) {
			return true
		}
	}
	return false
}

func requiredFieldProblems(document *yaml.Node) []string {
	root := document
	if root.Kind == yaml.DocumentNode && len(root.Content) != 0 {
		root = root.Content[0]
	}
	problems := make([]string, 0)
	requireMappingKeys(root, "", []string{"$schema", "apiVersion", "kind", "metadata", "spec", "artifact"}, &problems)

	metadata := mappingValue(root, "metadata")
	requireMappingKeys(metadata, "metadata", []string{
		"id", "displayName", "version", "description", "vendor", "homepage", "license",
	}, &problems)

	spec := mappingValue(root, "spec")
	requireMappingKeys(spec, "spec", []string{
		"lifecycle", "protocol", "coreVersions", "runtime", "dependencies", "connectors",
	}, &problems)
	requireMappingKeys(mappingValue(spec, "protocol"), "spec.protocol", []string{"major", "minor"}, &problems)
	requireVersionRangeKeys(mappingValue(spec, "coreVersions"), "spec.coreVersions", &problems)
	requireMappingKeys(mappingValue(spec, "runtime"), "spec.runtime", []string{"mode", "entrypoint"}, &problems)

	dependencies := mappingValue(spec, "dependencies")
	if dependencies != nil && dependencies.Kind == yaml.SequenceNode {
		for index, dependency := range dependencies.Content {
			prefix := fmt.Sprintf("spec.dependencies[%d]", index)
			requireMappingKeys(dependency, prefix, []string{"id", "versions"}, &problems)
			requireVersionRangeKeys(mappingValue(dependency, "versions"), prefix+".versions", &problems)
		}
	}

	connectors := mappingValue(spec, "connectors")
	if connectors != nil && connectors.Kind == yaml.SequenceNode {
		for index, connector := range connectors.Content {
			prefix := fmt.Sprintf("spec.connectors[%d]", index)
			requireMappingKeys(connector, prefix, []string{
				"id", "displayName", "description", "legacyDbTypes", "roles", "capabilities",
				"recordFormats", "stability", "config",
			}, &problems)
			capabilities := mappingValue(connector, "capabilities")
			if capabilities != nil && capabilities.Kind == yaml.SequenceNode {
				for capabilityIndex, capability := range capabilities.Content {
					requireMappingKeys(
						capability,
						fmt.Sprintf("%s.capabilities[%d]", prefix, capabilityIndex),
						[]string{"name", "version"},
						&problems,
					)
				}
			}
			requireMappingKeys(mappingValue(connector, "config"), prefix+".config", []string{
				"schema", "uiHints", "schemaVersion", "secretJsonPointers", "placeholder",
			}, &problems)
		}
	}

	artifact := mappingValue(root, "artifact")
	requireMappingKeys(artifact, "artifact", []string{"status", "bundles"}, &problems)
	bundles := mappingValue(artifact, "bundles")
	if bundles != nil && bundles.Kind == yaml.SequenceNode {
		for index, bundle := range bundles.Content {
			requireMappingKeys(
				bundle,
				fmt.Sprintf("artifact.bundles[%d]", index),
				[]string{"platform", "digest"},
				&problems,
			)
		}
	}
	return problems
}

func requireVersionRangeKeys(node *yaml.Node, prefix string, problems *[]string) {
	requireMappingKeys(node, prefix, []string{"minimum", "maximumExclusive"}, problems)
}

func requireMappingKeys(node *yaml.Node, prefix string, keys []string, problems *[]string) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for _, key := range keys {
		if mappingValue(node, key) != nil {
			continue
		}
		if prefix == "" {
			*problems = append(*problems, key)
		} else {
			*problems = append(*problems, prefix+"."+key)
		}
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

// LoadManifest reads and strictly parses a manifest file.
func LoadManifest(path string) (Manifest, error) {
	manifest, _, err := loadManifest(path)
	return manifest, err
}

// loadManifest reads a manifest exactly once and parses that captured byte
// slice. Callers that need a content identity must hash the returned bytes
// rather than reopening path.
func loadManifest(path string) (Manifest, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("stat manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, nil, fmt.Errorf("manifest must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, nil, fmt.Errorf("manifest must be a regular file")
	}
	if info.Size() > MaxManifestBytes {
		return Manifest{}, nil, fmt.Errorf("manifest exceeds %d-byte limit", MaxManifestBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("open manifest: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("stat opened manifest: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return Manifest{}, nil, fmt.Errorf("manifest changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read manifest: %w", err)
	}
	if len(data) > MaxManifestBytes {
		return Manifest{}, nil, fmt.Errorf("manifest exceeds %d-byte limit", MaxManifestBytes)
	}
	manifest, err := ParseManifest(data)
	if err != nil {
		return Manifest{}, nil, err
	}
	return manifest, data, nil
}
