# Canonical manifest schema

`plugin-manifest.schema.json` is the Core-owned runtime copy of the connector
plugin contract. The `peerdb-plugins` repository keeps a byte-identical
authoring copy at `schemas/plugin-manifest.schema.json` so plugin CI can validate
manifests without checking out Core.

The expected SHA-256 is pinned in `schema_test.go`. A contract change must update
the Core model, parser/validator tests, this schema, the authoring copy, and that
hash in one coordinated change. Comparing both files with `sha256sum` is the
cross-repository drift check until schema publication is automated.
