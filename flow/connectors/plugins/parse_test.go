package plugins

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifestStrict(t *testing.T) {
	t.Parallel()
	valid := manifestYAML(t, plannedManifest("io.peerdb.test.strict", "1.2.3", "strict"))

	tests := []struct {
		name      string
		data      []byte
		wantError string
	}{
		{name: "canonical document", data: valid},
		{name: "empty", data: nil, wantError: "empty"},
		{
			name:      "unknown field",
			data:      append(append([]byte(nil), valid...), []byte("unknown: true\n")...),
			wantError: "field unknown not found",
		},
		{
			name:      "duplicate field",
			data:      append(append([]byte(nil), valid...), []byte("kind: ConnectorPlugin\n")...),
			wantError: "mapping key \"kind\" already defined",
		},
		{
			name:      "multiple documents",
			data:      append(append([]byte(nil), valid...), []byte("---\nkind: ConnectorPlugin\n")...),
			wantError: "exactly one YAML document",
		},
		{
			name:      "missing explicit boolean",
			data:      []byte(removeYAMLLine(string(valid), "placeholder: true")),
			wantError: "placeholder",
		},
		{
			name: "aliases",
			data: []byte(strings.Replace(
				strings.Replace(string(valid), "displayName: Test strict", "displayName: &display-name Test strict", 1),
				"vendor: PeerDB tests",
				"vendor: *display-name",
				1,
			)),
			wantError: "aliases are not allowed",
		},
		{
			name:      "oversized",
			data:      bytes.Repeat([]byte("x"), MaxManifestBytes+1),
			wantError: "exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, err := ParseManifest(test.data)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ParseManifest() error = %v", err)
				}
				if manifest.APIVersion != APIVersion || manifest.Spec.Lifecycle != LifecyclePlanned {
					t.Fatalf("ParseManifest() returned unexpected manifest: %#v", manifest)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ParseManifest() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func removeYAMLLine(document string, trimmedLine string) string {
	lines := strings.SplitAfter(document, "\n")
	for index, line := range lines {
		if strings.TrimSpace(line) == trimmedLine {
			return strings.Join(append(lines[:index], lines[index+1:]...), "")
		}
	}
	return document
}

func TestLoadManifestRejectsDirectory(t *testing.T) {
	t.Parallel()
	_, err := LoadManifest(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("LoadManifest() error = %v, want regular-file error", err)
	}
}

func TestLoadManifestRejectsSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	if err := os.WriteFile(target, manifestYAML(t, plannedManifest("io.peerdb.test.link", "1.0.0", "link")), 0o600); err != nil {
		t.Fatalf("write target manifest: %v", err)
	}
	link := filepath.Join(root, ManifestFilename)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := LoadManifest(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("LoadManifest() error = %v, want symbolic-link error", err)
	}
}
