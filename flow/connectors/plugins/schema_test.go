package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const canonicalSchemaSHA256 = "5f4e2d0a95b31ad8dee884148852f9c23538f98889080799d2f60b254b2e0a2f"

func TestVendoredManifestSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join("schema", "plugin-manifest.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	digest := sha256.Sum256(data)
	if actual := hex.EncodeToString(digest[:]); actual != canonicalSchemaSHA256 {
		t.Fatalf("canonical schema SHA-256 = %s, want %s; update both repository copies deliberately", actual, canonicalSchemaSHA256)
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("canonical schema is not valid JSON: %v", err)
	}
	if schema["$id"] != "https://peerdb.io/schemas/plugin-manifest/v1alpha1.json" {
		t.Fatalf("canonical schema $id = %v", schema["$id"])
	}
}
