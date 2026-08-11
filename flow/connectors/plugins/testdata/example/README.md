# Example connector plugin manifest

This fixture documents the canonical `peerdb.io/plugin/v1alpha1` contract shared
with the `peerdb-plugins` repository. The executable is a harmless placeholder;
production plugins implement the gRPC process ABI in
`protos/peerdb/plugin/v1`, publish one digest-pinned bundle per platform, and
are pinned by exact plugin ID, version, platform, and digest.

The same script bytes are used for both Linux example bundles, so their SHA-256
digests are intentionally identical. A real release normally builds and signs
separate platform bundles.

Planned inventory manifests use `lifecycle: planned`, a null entrypoint, an
empty `dependencies` array, and `artifact: {status: unbuilt, bundles: []}`. Core
reports those manifests as planned but never returns them as runnable plugin
descriptors.
