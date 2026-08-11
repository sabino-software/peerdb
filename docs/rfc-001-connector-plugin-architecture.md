# RFC-001: Out-of-Process Connector Plugin Architecture

**Status**: Proposed
**Authors**: Sabino Software / PeerDB contributors
**Date**: 2026-08-11
**Decision scope**: Connector discovery, execution, configuration, data transport, packaging, and migration
**Target repositories**: peerdb and peerdb-plugins

---

## 1. Summary

PeerDB connectors will become independently versioned, out-of-process plugins discovered from declarative manifests and invoked through a versioned gRPC protocol over local Unix domain sockets.

PeerDB Core will retain:

- Flow API and public API compatibility.
- Temporal workflows and activity orchestration.
- Catalog ownership and encryption.
- Cross-connector planning, record transformation, backpressure, and progress bookkeeping.
- Plugin discovery, verification, supervision, and RPC adapters.
- The canonical plugin protocol, SDK, and conformance testkit.

Each connector plugin will own:

- Database- or service-specific clients and dependencies.
- Connection validation and connector-specific configuration migration.
- Schema discovery and type conversion at its boundary.
- Source capture, snapshot, and query logic that it advertises.
- Destination ingestion, normalization, and target-side metadata that it advertises.
- Its manifest, declarative configuration schema, tests, release artifacts, and SBOM.

The initial official plugin set will live in the peerdb-plugins repository. Each connector will be built and released as a separate executable artifact.

This design intentionally does not use Go shared-object plugins. Metabase's manifest, discovery, capability, and community-distribution model is useful; its in-process JVM class-loading mechanism is not a safe ABI for a Go application.

---

## 2. Decision

PeerDB adopts the following architectural decisions:

1. **A connector is identified by a stable string ID**, not a closed numeric enum.
2. **A plugin artifact contains one executable and one signed manifest**. It normally exposes one connector, but may expose multiple closely related descriptors (for example Elasticsearch and OpenSearch) when they share a release, trust boundary, and failure domain. Each descriptor advertises its own roles and capabilities.
3. **Plugins execute as supervised local subprocesses** and expose versioned gRPC services on private Unix domain sockets.
4. **The wire contract is language-neutral protobuf**, not Go interfaces, gob values, channels, pointers, or driver-specific objects.
5. **Temporal remains the retry and durability boundary**. A plugin process is never assumed to survive a worker, activity, or deployment restart.
6. **The host brokers all source-to-destination data**. Source and destination plugins never connect directly to one another.
7. **Catalog credentials are not exposed to plugins**. Core owns catalog state and offers only narrowly scoped host callbacks when necessary.
8. **Plugin versions and artifact digests are pinned** on peers and flows. Existing flows never silently switch to a newer plugin.
9. **Plugin installation is startup-scoped in protocol v1**. Side-by-side versions and controlled draining replace in-place hot reload.
10. **The UI is descriptor-driven** through JSON Schema and declarative UI hints. Plugin-supplied browser JavaScript is not accepted in protocol v1.

---

## 3. Context and Current Constraints

### 3.1 Static connector registry

The current connector abstraction is defined by 35 Go capability interfaces in
[flow/connectors/core.go](../flow/connectors/core.go). The capability composition is valuable, but registration and construction are static:

- Every connector package is imported by flow/connectors/core.go.
- BuildPeerConfig contains a switch for every peer configuration.
- getConnector contains a switch for every concrete constructor.
- GetAs uses in-process Go type assertions for capability discovery.
- Compile-time assertions import every concrete connector type.

Adding a connector therefore requires rebuilding PeerDB Core.

### 3.2 Closed identity and configuration model

[protos/peers.proto](../protos/peers.proto) represents connector identity as the closed DBType enum and connector configuration as a Peer oneof.

That model is generated into:

- Go for the Flow API and workers.
- Rust for Nexus and catalog decoding.
- TypeScript for the UI.

The catalog stores a numeric type and connector-specific protobuf payload in the peers table. Both create and load paths contain connector-specific switches. A genuinely external connector cannot add a new identity or configuration without changing Core.

### 3.3 In-process-only data types

Current connector method signatures contain values that cannot cross a process boundary:

- Go channels and latches.
- Generic Go interfaces and concrete QValue implementations.
- atomic.Int64 pointers.
- shared.CatalogPool and OtelManager pointers.
- any transaction values.
- Live database connections.
- Connector-specific PgCopyReader values.
- QObjectStream HeaderProvider callbacks.

The new protocol must define explicit serializable messages and lifecycle handles instead of attempting to expose the current interfaces remotely.

### 3.4 Cross-package coupling

Every current connector imports flow/internal. Go's internal-package visibility rule prevents those packages from compiling after they are moved to a separate repository.

Connectors also import application-owned model, shared, generated/protos, connector utilities, external metadata, monitoring, and telemetry packages. The repository split must follow—not precede—the extraction of a stable SDK and the inversion of catalog and monitoring dependencies.

### 3.5 Hard-coded control and query paths

Connector knowledge exists outside flow/connectors:

- UI peer forms, icons, peer lists, and mirror feature branches.
- Rust Nexus parser, option analyzer, catalog decoder, and query executor routing.
- Go Switchboard query adapters.
- Postgres-specific activity and API paths.
- Destination-specific AVRO and QValue conversion branches in Core.

Pluginization is complete only when a new conforming connector can be installed without rebuilding Go, Rust, or TypeScript application code.

---

## 4. Goals and Non-Goals

### 4.1 Goals

- Install an independently released connector without recompiling Core.
- Preserve current CDC, QRep, snapshot, normalization, and query semantics.
- Preserve Temporal determinism and activity retry behavior.
- Support official and community connectors through the same contract.
- Isolate dependency conflicts and connector crashes from the PeerDB process.
- Make connector capabilities, compatibility, configuration, and UI discoverable.
- Keep memory bounded under slow sources, destinations, or clients.
- Support side-by-side plugin versions and deterministic upgrades.
- Remove database driver dependencies from the Core binary.
- Provide stable contracts that can be implemented in languages other than Go.
- Make connector testing possible without importing the PeerDB application.

### 4.2 Non-goals for protocol v1

- Treating arbitrary native plugins as a strong security sandbox.
- Installing or replacing plugins while active flows are using them.
- Allowing plugins to execute custom JavaScript in the PeerDB UI.
- Allowing plugins to issue arbitrary SQL against the PeerDB catalog.
- Allowing direct source-plugin to destination-plugin communication.
- Guaranteeing that every connector supports every capability.
- Replacing Temporal with plugin-managed scheduling or retries.
- Supporting remote, multi-tenant plugin services as the default deployment mode.

Remote plugin endpoints may be added later if they preserve the same authenticated protocol and operational guarantees.

---

## 5. Target Architecture

~~~mermaid
flowchart TB
    Clients["UI, API clients, and Nexus"] --> Control["Flow API and connector descriptors"]
    Temporal["Temporal workflows"] --> Workers["Flow and snapshot activities"]
    Control --> Registry["Plugin registry"]
    Workers --> Adapters["Capability RPC adapters"]
    Registry --> Supervisor["Plugin supervisor"]
    Adapters --> Supervisor

    subgraph Plugins["Verified plugin processes"]
        direction TB
        Source["Source plugin"]
        Destination["Destination plugin"]
        Query["Query-capable plugin"]
    end

    Supervisor --> Source
    Supervisor --> Destination
    Supervisor --> Query
    Workers --> Catalog["PeerDB catalog"]
    Workers --> Telemetry["Logs, metrics, and traces"]
    Source -. "Scoped state callbacks" .-> Workers
    Destination -. "Scoped state callbacks" .-> Workers
~~~

### 5.1 Plugin registry

The registry:

- Scans configured plugin roots at process startup.
- Parses manifests without executing plugin code.
- Validates manifest schema and path safety.
- Verifies artifact digest and signature policy.
- Rejects duplicate ID, version, and digest collisions.
- Resolves an exact ConnectorRef.
- Exposes immutable descriptors to the API, UI, workers, and Nexus bridge.
- Records why an artifact was accepted, disabled, or quarantined.

Discovery does not mean activation. A plugin process starts lazily when a service first opens a session, or eagerly when an administrator requests a health check.

### 5.2 Plugin supervisor

The supervisor:

- Runs one process per plugin ID, version, and digest per PeerDB service instance.
- Multiplexes multiple connector sessions onto that process.
- Creates private runtime directories and Unix sockets.
- Authenticates the handshake before sending configuration or credentials.
- Propagates deadlines, cancellation, trace context, and operation metadata.
- Applies resource, process, and restart policies.
- Tracks open sessions and invalidates them after a process crash.
- Exposes health, crash, restart, and resource metrics.
- Drains old versions without changing the version used by an existing flow.

### 5.3 Capability RPC adapters

Core activities depend on local adapter interfaces, not generated gRPC clients directly. An adapter:

- Resolves the pinned plugin.
- Opens and closes sessions.
- Checks the advertised capability and capability revision.
- Converts Core activity models to protocol messages.
- Pumps bounded streams.
- Maps PluginError to PeerDB error classes.
- Emits Core-owned catalog, monitoring, and Temporal heartbeat updates.

The adapter is not permitted to infer capability support by trial-calling methods.

### 5.4 Host services

Core may expose a reverse gRPC service to a plugin process. Its surface is deliberately narrow:

- Namespaced plugin state get, put, compare-and-swap, and delete.
- Optional state transaction begin, commit, and rollback.
- Explicit flow progress events that cannot mutate arbitrary catalog rows.
- Configuration-value lookup limited to non-secret keys included in the opened session.

Host services never expose:

- Catalog DSNs.
- Generic SQL execution.
- Other peers' configurations.
- Other plugins' state.
- Core filesystem paths outside the session sandbox.

The host authorizes every callback by process token, session ID, plugin ID, peer ID, and flow ID.

---

## 6. Plugin Artifact and Manifest

### 6.1 Artifact layout

One unpacked, platform-specific artifact has this shape:

~~~text
io.peerdb.connector.postgresql/
  peerdb-plugin.yaml
  bin/peerdb-plugin-postgresql
  schemas/
    connection.schema.json
    connection.ui.json
    cdc-source.schema.json
    cdc-destination.schema.json
    qrep-source.schema.json
    qrep-destination.schema.json
  assets/
    icon.svg
  LICENSE
  SBOM.spdx.json
  signature.bundle
~~~

Paths in a manifest are relative to the artifact root. Symlinks that escape the artifact root are rejected.

An artifact may be distributed as:

- A content-addressed directory included in the PeerDB image.
- A signed OCI artifact fetched by an init container or installation command.
- A local archive expanded into the content-addressed plugin cache.

Core does not download floating URLs during normal startup.

### 6.2 Required manifest fields

~~~yaml
$schema: https://peerdb.io/schemas/plugin-manifest/v1alpha1.json
apiVersion: peerdb.io/plugin/v1alpha1
kind: ConnectorPlugin
metadata:
  id: io.peerdb.connector.postgresql
  displayName: PeerDB PostgreSQL Connector
  version: 1.4.2
  description: PostgreSQL source, destination, and query connector
  vendor: PeerDB
  homepage: https://github.com/PeerDB-io/peerdb-plugins
  license: AGPL-3.0-only
spec:
  lifecycle: stable
  protocol: {major: 1, minor: 4}
  coreVersions: {minimum: 1.8.0, maximumExclusive: 2.0.0}
  runtime: {mode: process, entrypoint: bin/peerdb-plugin-postgresql}
  dependencies: []
  connectors:
    - id: postgresql
      displayName: PostgreSQL
      description: PostgreSQL source, destination, and query connector
      legacyDbTypes: [POSTGRES]
      roles: [source, destination, query]
      capabilities:
        - {name: control, version: 1}
        - {name: schema.discovery, version: 1}
        - {name: schema.tables, version: 1}
        - {name: cdc.source, version: 1}
        - {name: cdc.destination, version: 1}
        - {name: cdc.normalize, version: 1}
        - {name: cdc.snapshot, version: 1}
        - {name: qrep.source.rows, version: 1}
        - {name: qrep.destination.rows, version: 1}
        - {name: table.lifecycle.normalized, version: 1}
        - {name: table.lifecycle.create-from-existing, version: 1}
        - {name: table.lifecycle.rename, version: 1}
        - {name: table.lifecycle.rename-soft-delete, version: 1}
        - {name: table.lifecycle.raw, version: 1}
        - {name: query, version: 1}
        - {name: diagnostics.stats, version: 1}
        - {name: diagnostics.version, version: 1}
        - {name: diagnostics.log-retention, version: 1}
        - {name: diagnostics.commit-lag, version: 1}
        - {name: diagnostics.clock-offset, version: 1}
        - {name: diagnostics.database-variant, version: 1}
        - {name: diagnostics.replication-mechanism, version: 1}
        - {name: diagnostics.table-size, version: 1}
      recordFormats: [qvalue-proto-v1, pg-text-v1, pg-copy-v1]
      stability: stable
      config:
        schema: schemas/connection.schema.json
        uiHints: schemas/connection.ui-hints.json
        schemaVersion: 3
        secretJsonPointers: [/password, /ssh/privateKey, /clientTls/privateKey]
        placeholder: false
artifact:
  status: published
  bundles:
    - {platform: linux/amd64, digest: "sha256:<64 lowercase hex characters>"}
    - {platform: linux/arm64, digest: "sha256:<64 lowercase hex characters>"}
~~~

### 6.3 Manifest rules

- `metadata.id` is lowercase reverse-DNS form and is immutable after publication.
- `metadata.version` is Semantic Versioning.
- An ID, version, platform, and bundle digest tuple identifies one immutable artifact.
- A published tuple may never be repointed to different bytes.
- Capability names and revisions come from the Core-owned protocol registry.
- Roles are summary metadata; capabilities are authoritative per connector descriptor.
- `recordFormats` is ordered only for display. Negotiation uses Core policy.
- Configuration uses JSON Schema 2020-12 plus a restricted PeerDB UI schema.
- `secretJsonPointers` must identify every secret accepted by the schema.
- Unknown manifest fields are rejected. Compatible additions require a manifest-schema revision and explicit Core support.
- A future icon field, when added to the schema, will permit only static SVG or PNG served through a sanitizing Core endpoint.
- Native executables must include an SBOM in official releases.

### 6.4 Declarative UI schema

The UI schema may specify:

- Field order and grouping.
- Labels, descriptions, examples, and documentation links.
- Password, multiline, file-to-string, select, number, boolean, and key-value widgets.
- Conditional visibility based on JSON Schema discriminators.
- Connector role and mirror-option sections.
- Safe validation hints and defaults.

It may not specify:

- Executable JavaScript.
- Remote scripts, styles, iframes, or images.
- Arbitrary HTML.
- Network calls from the browser.
- A different API endpoint for credential submission.

Semantic validation still occurs in the plugin through `PluginControlService.Validate`.

---

## 7. Discovery, Resolution, and Cluster Invariants

### 7.1 Plugin roots

Core scans roots in configured priority order, for example:

1. /opt/peerdb/plugins
2. /var/lib/peerdb/plugins
3. An explicitly configured development directory

Development directories are disabled by default in production.

### 7.2 Lockfile

Every deployment has a `plugins.lock.yaml` file containing:

- Plugin ID.
- Exact plugin version.
- Exact artifact SHA-256.
- Manifest SHA-256.
- Exact manifest-declared protocol major and minor. Each flow separately pins the negotiated minor.
- Signature identity or trust-root reference.
- Enabled or disabled status.

The lockfile is the desired deployment inventory. Directory contents alone do not authorize execution.

### 7.3 Worker-pool invariant

All workers polling the same Temporal task queue must have the same required plugin lockfile hash.

At startup, a worker:

1. Loads and verifies the lockfile.
2. Resolves every required artifact.
3. Performs a manifest compatibility check.
4. Publishes its inventory hash in readiness diagnostics.
5. Refuses readiness if a required plugin is missing or incompatible.

This prevents an activity from failing randomly because Temporal scheduled it on a worker with a different connector inventory.

An advanced deployment may use plugin-version-specific task queues later. Protocol v1 uses homogeneous worker pools.

### 7.4 Connector resolution

A ConnectorRef is exact:

~~~protobuf
message ConnectorRef {
  string plugin_id = 1;
  string connector_id = 2;
  string version = 3;
  string artifact_digest = 4;
}
~~~

There is no runtime meaning for latest, compatible, or default inside a saved peer or flow.

When a peer is created without an explicit version, the API resolves the administrator-approved default once and persists the resulting exact ConnectorRef.

### 7.5 Pair planning

At mirror creation, Core:

1. Resolves exact source and destination ConnectorRefs.
2. Loads both descriptors.
3. Validates required roles and capabilities.
4. Intersects supported record formats.
5. Applies Core policy, transformations, and flow options.
6. Selects one deterministic transport plan.
7. Persists that plan with the flow configuration.

Changing installed plugins does not alter an existing plan.

---

## 8. Process and Handshake Protocol

### 8.1 Launch

The supervisor:

1. Creates a mode-0700 runtime directory owned by the PeerDB service user.
2. Chooses a socket path inside that directory.
3. Creates a random 256-bit launch token.
4. Passes the token through an inherited anonymous file descriptor, not a command-line argument.
5. Starts the plugin in a new process group with serve and socket arguments.
6. Waits for the socket with a bounded startup deadline.
7. Calls `PluginControlService.Handshake` with proof derived from the launch token.
8. Verifies the response against the manifest and lockfile.
9. Sends connector configuration only after authentication succeeds.

The socket is mode 0600. TCP listening is disabled for local plugins.

The launch proof is `HMAC-SHA256(launch_token, handshake_nonce)`. The token is
read once from the inherited anonymous file descriptor and never appears in
arguments, environment variables, manifests, logs, or RPC payloads. The
supervisor uses a fresh token and nonce for every process instance.

### 8.2 Handshake

Handshake negotiates:

- Protocol major and minor.
- Plugin ID, version, and build digest.
- Capability revisions.
- Record formats.
- Compression algorithms.
- Maximum inbound and outbound frame sizes.
- Host callback protocol revision.
- Feature flags that are safe to negotiate additively.

Rules:

- Protocol major must match exactly.
- The selected minor is the highest mutually supported minor.
- A plugin may advertise only capabilities declared by its signed manifest.
- A mismatch between binary response and manifest quarantines the artifact.
- Configuration and credentials are never sent to an unauthenticated process.

### 8.3 Process scope

One plugin process may serve many sessions, but:

- Each OpenSession returns a random opaque session ID.
- A session is bound to one peer configuration, role, and Core authorization scope.
- Session methods must reject a flow or peer outside that scope.
- CloseSession is idempotent.
- Idle sessions expire after a host-configured TTL.
- A process crash invalidates every session owned by that process.

### 8.4 Restart policy

The supervisor uses bounded exponential restart backoff with jitter and a circuit breaker.

It may transparently restart a process for a new session or a read-only idempotent call. It must not transparently replay:

- An active CDC or QRep stream.
- A snapshot or transaction lease.
- A destination mutation whose result is unknown.
- A query session.

Those failures return to the activity or client so the correct outer retry boundary can act.

### 8.5 Shutdown

Core sends Drain, rejects new sessions, waits for a configured grace period, sends Shutdown, then terminates the process group if necessary.

On Linux, the child process also uses parent-death semantics so it cannot survive an unexpected Core process exit.

---

## 9. Versioned RPC Surface

Protocol definitions live under `protos/peerdb/plugin/v1` in the Core repository. Generated SDK modules must not import the PeerDB application, Temporal, catalog code, or concrete database drivers.

### 9.1 PluginControlService

| RPC | Shape | Semantics |
|---|---|---|
| Handshake | Unary | Authenticates launch and negotiates protocol features. |
| Describe | Unary | Returns the runtime descriptor; it must match the manifest. |
| Health | Unary | Returns connector-specific health diagnostics; transport readiness uses standard gRPC health. |
| OpenSession | Unary | Opens a scoped connector session from a ConnectorRef and decrypted config. |
| RenewSession | Unary | Renews a long-lived session lease without recreating process-local state. |
| CloseSession | Unary | Idempotently closes a session and releases connections. |
| Validate | Unary | Performs semantic role/flow validation and returns structured field errors. |
| MigrateConfig | Unary | Migrates one configuration schema version to the next without persisting it. |
| Drain | Unary | Stops accepting new sessions while existing operations complete. |
| Shutdown | Unary | Requests graceful process termination. |

The standard gRPC health service is also required.

### 9.2 SchemaService

| RPC | Shape | Semantics |
|---|---|---|
| GetSchemas | Unary | Lists source namespaces visible to the session. |
| GetTables | Unary | Lists tables or collections and mirrorability metadata. |
| GetColumns | Unary | Lists columns, keys, replica identity, and canonical kinds. |
| GetTableSchemas | Unary | Resolves canonical schemas for requested table mappings. |

### 9.3 CDCSourceService

| RPC | Shape | Semantics |
|---|---|---|
| EnsurePullability | Unary | Checks replication prerequisites and source-table eligibility. |
| BeginSnapshot | Unary | Opens an exported snapshot and returns an opaque leased handle. |
| KeepSnapshotAlive | Unary | Renews a snapshot lease and reports source status. |
| FinishSnapshot | Unary | Explicitly commits or rolls back the snapshot handle. |
| SetupReplication | Unary | Creates or attaches replication resources and may return a lease. |
| KeepReplicationAlive | Unary | Renews a process-local replication lease. |
| CloseReplication | Unary | Closes the process-local replication connection without dropping durable resources. |
| CleanupReplication | Unary | Explicitly cleans publication, slot, or equivalent durable resources. |
| Pull | Bidirectional stream | Emits ordered change frames and receives durable consumption acknowledgements. |

### 9.4 CDCDestinationService

| RPC | Shape | Semantics |
|---|---|---|
| NeedsMetadataSetup | Unary | Checks whether target-side metadata is present. |
| SetupMetadata | Unary | Creates target-side metadata idempotently. |
| CreateRawTable | Unary | Creates intermediate storage idempotently. |
| ReplaySchemaDeltas | Unary | Applies ordered source schema changes. |
| Cleanup | Unary | Cleans flow-specific target metadata. |
| GetBatchStatus | Unary | Recovers an in-progress or committed result after an unknown mutation outcome. |
| GetLastSyncBatch | Unary | Returns the last destination batch marker for legacy/checkpoint reconciliation. |
| Push | Bidirectional stream | Accepts change frames and reports durable acknowledgements and batch results. |
| Normalize | Unary | Normalizes through a requested batch and reports the actual range. |

### 9.5 QRepSourceService

| RPC | Shape | Semantics |
|---|---|---|
| GetPartitions | Unary | Returns unsynced partitions after a supplied watermark. |
| GetDefaultPartitionKeys | Unary | Suggests snapshot or QRep partition keys. |
| EstimateTableSize | Unary | Returns an estimate and whether it is exact. |
| HasNewRows | Unary | Reports whether the supplied watermark has advanced. |
| Pull | Server stream | Sends row or object batches and a terminal partition summary. |

### 9.6 QRepDestinationService

| RPC | Shape | Semantics |
|---|---|---|
| IsPartitionSynced | Unary | Checks the destination's idempotency marker. |
| GetPartitionResult | Unary | Recovers the exact committed result for a stable partition mutation key. |
| SetupMetadata | Unary | Creates QRep target metadata idempotently. |
| Push | Client stream | Consumes row or object frames and atomically records partition completion. |
| Consolidate | Unary | Consolidates destination-side partitions. |
| Cleanup | Unary | Cleans QRep resources. |

### 9.7 TableLifecycleService

| RPC | Shape | Semantics |
|---|---|---|
| BeginNormalizedTableSetup | Unary | Opens an opaque target table-setup transaction. |
| SetupNormalizedTable | Unary | Creates or validates one normalized table within the setup handle. |
| FinishNormalizedTableSetup | Unary | Commits a setup handle. |
| AbortNormalizedTableSetup | Unary | Rolls back a setup handle. |
| CreateTablesFromExisting | Unary | Creates replacement tables from existing target tables. |
| RenameTables | Unary | Atomically renames tables according to advertised semantics. |
| RemoveRawTableEntries | Unary | Removes bounded intermediate records for selected tables. |

### 9.8 DiagnosticsService

| RPC | Shape | Semantics |
|---|---|---|
| GetRuntimeInfo | Unary | Returns upstream version, database variant, replication mechanism, and flags. |
| GetStats | Unary | Returns connector-defined activity statistics in canonical fields. |
| GetLogRetention | Unary | Returns source-log retention estimates. |
| GetCommitLag | Unary | Returns server-side commit lag. |
| GetSourceClockOffset | Unary | Returns estimated source-minus-worker clock offset. |

### 9.9 QueryService

| RPC | Shape | Semantics |
|---|---|---|
| OpenConnection | Unary | Opens a scoped query connection and returns server parameters. |
| CloseConnection | Unary | Idempotently closes the query connection. |
| DescribeQuery | Unary | Returns canonical field descriptions without consuming results. |
| Execute | Server stream | Streams field descriptions, rows, command tags, and terminal status. |
| Cancel | Unary | Cancels one operation ID idempotently. |

Query capability descriptors include:

- Dialect identifier.
- Transaction support.
- Read-only enforcement mode.
- Prepared-statement support.
- Maximum parameter and result formats.

Core keeps global row, byte, timeout, and cancellation guardrails even when the plugin also enforces upstream-specific restrictions.

---

## 10. Mapping from Current Interfaces

This table accounts for every interface currently declared in flow/connectors/core.go.

| New service group | Current interfaces | Migration note |
|---|---|---|
| PluginControlService and descriptor | Connector, ValidationConnector, GetFlagsConnector | Close becomes CloseSession; flags become manifest/runtime capabilities rather than connector-specific strings where possible. |
| SchemaService | GetTableSchemaConnector, GetSchemaConnector, TableSizeEstimatorConnector | All schema and size results use canonical protocol messages. |
| CDCSourceService | MirrorSourceValidationConnector, CDCPullConnectorCore, CDCPullConnector, CDCPullPgConnector, SourceClockOffsetConnector, GetLogRetentionConnector, GetServerSideCommitLagConnector, ReplicationMechanismInUseConnector | Generic and Postgres-specialized pull methods become one negotiated stream with explicit record formats. Snapshot and replication live objects become leases. |
| CDCDestinationService | MirrorDestinationValidationConnector, CDCSyncConnectorCore, CDCSyncConnector, CDCSyncPgConnector, CDCNormalizeConnector | Destination specialization is expressed by capabilities and transport formats, not concrete Go types. |
| QRepSourceService | QRepPullConnectorCore, QRepPullConnector, QRepPullObjectsConnector | Row and object paths remain distinct negotiated transports. |
| QRepDestinationService | QRepSyncConnectorCore, QRepSyncConnector, QRepSyncObjectsConnector, QRepSyncPgConnector, QRepConsolidateConnector | PgCopy becomes a negotiated byte format; partition idempotency is explicit. |
| TableLifecycleService | NormalizedTablesConnector, CreateTablesFromExistingConnector, RawTableConnector, RenameTablesConnector, RenameTablesWithSoftDeleteConnector | `any` transaction values become opaque, leased setup handles. |
| DiagnosticsService | StatActivityConnector, GetVersionConnector, DatabaseVariantConnector | Diagnostics return canonical fields plus namespaced extension values. |

Interfaces outside core.go also move:

| Current abstraction | New service |
|---|---|
| switchboard.Upstream | QueryService |
| switchboard.ResultIterator | QueryService.Execute result stream |
| Rust QueryExecutor implementations | QueryService client through the Core query broker |
| QObjectStream HeaderProvider | Serializable ObjectReference authentication policy |
| model.SetupReplicationResult.Conn | ReplicationLease |
| ExportTxSnapshot any transaction | SnapshotLease |
| Normalized table setup any transaction | TableSetupHandle |
| shared.CatalogPool passed to connectors | Core-owned catalog logic or scoped PluginHostService state methods |
| OtelManager passed to connectors | Propagated trace context and plugin process telemetry |

---

## 11. Canonical Data Model

### 11.1 Change record

The protocol defines a language-neutral ChangeRecord containing:

- Operation: insert, update, delete, relation, or logical message.
- Source and destination table identifiers.
- Transaction ID.
- Commit timestamp with nanosecond precision.
- Source checkpoint with numeric and text representations.
- Old values when available.
- New values when available.
- Unchanged TOAST or unavailable-column markers.
- Ordered schema delta when applicable.
- Origin and tracing metadata.

The protocol distinguishes:

- SQL NULL.
- Column absent from an update.
- Value unavailable because the source did not emit it.
- Empty string or empty byte array.

Conflating those states is a correctness bug.

### 11.2 Canonical values

TypedValue is a protobuf oneof with explicitly documented encodings for:

- Signed and unsigned integers through 256 bits.
- IEEE floating-point values, including a policy for NaN and infinity.
- Arbitrary precision numeric as a canonical decimal string, precision, and scale.
- Boolean.
- UTF-8 string and fixed character.
- Raw bytes.
- UUID.
- JSON and structured JSON.
- Date, time, time with timezone, timestamp, and timestamp with timezone.
- Interval.
- Arrays with nullable elements.
- Enum and set values.
- Network, MAC, point, geometry, geography, and HStore values.

Core never serializes the current Go QValue interface directly.

### 11.3 Record formats

Protocol v1 defines these format identities:

| Format | Purpose |
|---|---|
| qvalue-proto-v1 | Canonical typed CDC changes and QRep rows. |
| object-ref-v1 | Serializable object references for object-mode QRep. |
| pg-text-v1 | PostgreSQL text-encoded fields for CDC fast paths. |
| pg-copy-v1 | PostgreSQL COPY byte stream for compatible QRep paths. |
| arrow-ipc-v1 | Optional columnar QRep batches after conformance and performance validation. |

Canonical protobuf formats are mandatory for applicable roles. Optimized formats are optional.

A flow may choose an optimized format only when:

- Both endpoints advertise the exact version.
- Core policy permits it.
- Requested transformations can operate on it.
- Required schema and error semantics are representable.

If a Lua or future Core transformation requires canonical values, pair planning selects the canonical format.

### 11.4 Framing

- The stream-open frame carries the operation context; all later frames inherit it.
- Every data frame has a strictly increasing sequence, record format, compression, declared uncompressed size, and content SHA-256.
- The negotiated maximum frame size is never greater than the Core hard limit.
- Batches should target at most 4 MiB uncompressed unless policy configures a lower value.
- Supported compression is negotiated; zstd is the preferred compressed format.
- Compression bombs are rejected by declared and observed uncompressed-size limits.
- Unknown required payload kinds terminate the operation.

---

## 12. CDC Streaming Semantics

### 12.1 Source stream

`CdcSourceService.Pull` is bidirectional.

Core sends:

- Start with flow, batch, mappings, starting checkpoint, format, limits, and idempotency key.
- DurableAck with the highest checkpoint that the destination has durably accepted.
- CancelStream for graceful cancellation.

The source sends:

- ChangeBatch.
- Schema-change records in the same ordered ChangeRecord sequence as DML.
- SourceProgress.
- Warning.
- End with final checkpoint and counts.
- PluginError.

The source must not treat receipt by Core as durable consumption.

### 12.2 Destination stream

`CdcDestinationService.Push` is bidirectional.

Core sends:

- Start with flow, batch, schema, mappings, format, and idempotency key.
- ChangeBatch or schema-related frame.
- Finish.
- CancelStream.

The destination sends:

- AcceptedSeq for flow control only.
- DurableSeq and durable checkpoint after target durability.
- Warning.
- BatchResult.
- PluginError.

AcceptedSeq must never advance source replication state. Only DurableSeq and its checkpoint may do so.

### 12.3 Host pump and backpressure

Core pumps source frames to the destination through a byte- and record-bounded window.

- Outstanding unacknowledged bytes may not exceed the configured window.
- When the window is full, Core stops reading source data.
- gRPC and the source plugin therefore receive natural backpressure.
- Core sends source DurableAck only after a corresponding destination durable acknowledgement.
- Metrics record current outstanding bytes, oldest unacknowledged age, and stalls.

No queue in the host or plugin may grow without a configured bound.

### 12.4 Commit order

For each CDC batch:

1. Source begins at the last catalog-confirmed checkpoint.
2. Destination receives records under flow_id, batch_id, and idempotency_key.
3. Destination commits data and its target-side idempotency marker.
4. Destination returns DurableSeq, checkpoint, and BatchResult.
5. Core atomically records the destination result, monitoring/canonical schema state, and catalog checkpoint.
6. Core acknowledges the exact sequence and content digest to the source stream; the source may then advance or release its connector-owned replay state.

Steps 5 and 6 are retryable and monotonic. A crash between destination commit and Core acknowledgement may produce a duplicate attempt, never data loss. If the destination response was lost, Core calls GetBatchStatus with the same mutation key before sending more data. The destination must return the prior result for the same key and content digest.

### 12.5 Error and cancellation

- A source error cancels the destination stream and fails the activity.
- A destination error sends Stop to the source, cancels both streams, and fails the activity.
- Core waits for a bounded cancellation grace period, then closes the session or terminates a hung process.
- An uncommitted destination batch is discarded.
- Temporal retries from the last durable checkpoint with the same batch idempotency key where applicable.
- A PluginError marked retryable informs policy but does not bypass Temporal retry configuration.

---

## 13. QRep and Object Streaming Semantics

### 13.1 Partition planning

`QRepSourceService.GetPartitions` is idempotent for:

- Flow ID.
- Run ID.
- Source configuration version.
- Last completed partition or watermark.
- Partition policy.

Partition IDs are stable across a retry of the same run.

### 13.2 Row mode

`QRepSourceService.Pull` in row mode sends:

1. One schema frame.
2. Zero or more row-batch frames.
3. One terminal summary containing row count, byte count, and optional checksum.

Core concurrently sends those frames to `QRepDestinationService.Push`. A destination marks the partition complete only after all rows and the terminal summary have been durably committed.

If the destination already reports the partition as complete, Core does not start the source stream.

### 13.3 Object mode

ObjectReference contains only serializable values:

- URL.
- Object format.
- Size.
- Content checksum when available.
- Expiration time.
- Optional scoped request headers.
- Optional refresh token understood only by the source plugin.

Signed URLs are preferred. Static cloud credentials are not embedded in an ObjectReference.

If headers would reveal credentials to another plugin, Core policy must explicitly permit the transfer. A safer policy is for Core to broker the fetch or ask the source plugin to refresh a signed URL.

The former QObjectStream HeaderProvider callback does not cross the ABI.

### 13.4 Producer and consumer failure

- A destination failure cancels the source stream immediately.
- A source failure aborts an incomplete destination partition.
- The same stable partition ID is retried.
- Completion markers make a committed retry a no-op.

---

## 14. Snapshot and Transaction Leases

### 14.1 Opaque leases

Live connections and transactions remain inside the plugin process. Core receives only opaque, unguessable handles:

- ReplicationLease.
- SnapshotLease.
- TableSetupHandle.
- QuerySession.

A handle is scoped to:

- Plugin process instance.
- Connector session.
- Peer.
- Flow.
- Operation.
- Expiration time.

It is invalid after process restart.

### 14.2 Snapshot lease behavior

`CdcSourceService.BeginSnapshot`:

- Is idempotent by operation id while its process and session live.
- Returns snapshot name, optional staging path, lease ID, and expiry.
- Keeps the exporting transaction in the plugin process.

Core renews the lease through `KeepSnapshotAlive` and Temporal heartbeats. `FinishSnapshot` is idempotent and explicitly commits or rolls back.

### 14.3 Process loss

A plugin crash during a snapshot invalidates the lease. The supervisor must not create a replacement lease under the old handle.

The snapshot activity fails, the Temporal session is abandoned, and the snapshot workflow restarts from a defined safe boundary. Partial destination data is cleaned or overwritten according to existing snapshot mode.

### 14.4 Table setup

BeginTableSetup, SetupNormalizedTable, and FinishTableSetup preserve connectors that need a target transaction.

If a connector can implement atomic batch setup internally, it may still use one handle and commit in FinishTableSetup. Cleanup after an activity cancellation requests rollback. Process loss is treated as rollback unless the plugin reports a durable commit under the idempotency key on retry.

---

## 15. Error Contract

Every RPC failure that originates in a plugin returns PluginError:

~~~protobuf
message PluginError {
  string code = 1;
  ErrorCategory category = 2;
  bool retryable = 3;
  string safe_message = 4;
  string sqlstate = 5;
  string vendor_code = 6;
  map<string, string> safe_details = 7;
  repeated FieldViolation field_violations = 8;
}
~~~

Categories include:

- CONFIGURATION
- AUTHENTICATION
- AUTHORIZATION
- CONNECTION
- RATE_LIMIT
- SOURCE_STATE
- DESTINATION_STATE
- SCHEMA
- DATA
- NORMALIZATION
- IDEMPOTENCY
- UNSUPPORTED
- RESOURCE_EXHAUSTED
- CANCELLED
- INTERNAL

Rules:

- safe_message and safe_details must not contain secrets.
- Raw driver errors may be logged locally only after plugin-side redaction.
- Core maps stable error codes to existing PeerDB exception and API status classes.
- Unknown codes map to INTERNAL without assuming retryability.
- gRPC transport status describes transport failure; PluginError describes connector failure.
- Field violations use JSON Pointer paths into the connector configuration.

---

## 16. Identity, Configuration, and Catalog Migration

### 16.1 New API model

Public API v2 introduces a generic peer definition:

~~~protobuf
message ConnectorRef {
  string id = 1;
  string version = 2;
  bytes artifact_sha256 = 3;
}

message ConnectorConfiguration {
  uint32 schema_version = 1;
  string encoding = 2;
  bytes payload = 3;
}

message PeerV2 {
  string name = 1;
  ConnectorRef connector = 2;
  ConnectorConfiguration configuration = 3;
}
~~~

JSON is the initial connection configuration encoding. The API validates it against the signed manifest schema before invoking semantic plugin validation.

### 16.2 Catalog columns

The peers table gains:

- connector_id TEXT.
- plugin_id TEXT.
- plugin_version TEXT.
- plugin_digest TEXT.
- config_schema_version INTEGER.
- config_encoding TEXT.
- legacy_type INTEGER, or the existing type column retained during migration.

The existing encrypted options payload may remain the encrypted storage column. Encryption and key rotation remain Core responsibilities.

Flows persist:

- Exact source and destination ConnectorRefs.
- Negotiated protocol minor.
- Negotiated record format.
- Capability revisions used by the plan.
- Configuration schema versions.

### 16.3 Legacy mapping

The migration maps current DBType values:

| Legacy value | Connector ID |
|---:|---|
| 0 | bigquery |
| 1 | snowflake |
| 2 | mongodb |
| 3 | postgresql |
| 5 | s3 |
| 6 | sqlserver |
| 7 | mysql |
| 8 | clickhouse |
| 9 | kafka |
| 10 | pubsub |
| 11 | eventhubs |
| 12 | elasticsearch |
| 13 | cockroachdb |

SQL Server remains marked unavailable until a conforming implementation exists.

### 16.4 Dual-read migration

During compatibility:

1. New peers write only the generic connector fields.
2. Existing peers with generic fields use the plugin path.
3. Existing peers with only legacy fields use a Core legacy decoder.
4. A migration command decrypts legacy protobuf config, converts it to canonical JSON, validates it with the pinned plugin, and re-encrypts it.
5. Migration records old and new digests and supports dry-run.
6. Rollback retains the legacy payload until an administrator finalizes migration.

Plugins do not import the legacy Peer oneof solely to decode Core storage. Legacy decoding belongs in Core compatibility code.

### 16.5 Configuration migration

Configuration migration is stepwise:

- A plugin must implement every migration from its oldest supported schema to its current schema.
- MigrateConfig is pure with respect to external systems.
- Core validates each output against the target schema.
- Core never persists an intermediate migration.
- Secrets remain marked and redacted through every step.
- A failed migration leaves the stored configuration unchanged.
- Automatic migration of active peers is disabled by default.

---

## 17. UI Migration

Flow API adds:

- ListConnectorPlugins.
- GetConnectorPlugin.
- GetConnectorConfigurationSchema.
- ValidateConnectorConfiguration.
- ListCompatibleDestinations.
- PlanConnectorPair.

The UI:

- Fetches connector descriptors instead of maintaining a static peer-type list.
- Renders connection forms from signed JSON Schema and UI hints.
- Uses capability roles to populate source and destination selectors.
- Uses connector-provided mirror-option schemas for source and destination options.
- Displays plugin version, stability, deprecation, signature identity, and compatibility.
- Requests semantic validation from Flow API.
- Never receives decrypted saved secrets.

Connector-specific UI branches are removed after their declarative replacements exist. Core-owned workflow options remain Core UI, even if a connector can declare support for them.

Examples:

- ClickHouse engine, staging, and normalization options belong to the ClickHouse descriptor.
- Event Hubs mapping guidance belongs to the Event Hubs descriptor.
- Queue versus table destination behavior is a capability, not a DBType switch.
- BigQuery source and destination deprecation can differ by role in the descriptor.

---

## 18. Nexus and Switchboard Migration

### 18.1 CREATE PEER

Nexus changes its parser from a closed PeerType enum to an arbitrary connector identifier.

Legacy aliases remain valid:

~~~sql
CREATE PEER source FROM POSTGRES WITH (...);
~~~

The canonical form is:

~~~sql
CREATE PEER source FROM "io.peerdb.postgres" WITH (...);
~~~

Nexus:

- Parses options as raw key-value data.
- Resolves aliases through Flow API descriptors.
- Sends generic PeerV2 to Flow API.
- Does not decode connector-specific protobuf messages.
- Returns plugin field violations as SQL errors with safe details.

### 18.2 Catalog reads

Rust catalog code reads generic ConnectorRef and encrypted payload metadata. It does not match connector types or decode connector configuration.

Operations requiring decrypted configuration are delegated to Flow API, which already owns encryption policy.

### 18.3 Query execution

Flow API exposes a streaming Core query broker backed by QueryService.

Nexus and Go Switchboard use that broker for non-catalog peers:

- Nexus remains responsible for PostgreSQL wire behavior.
- Core remains responsible for global query guardrails.
- The plugin owns upstream dialect parsing and connection behavior advertised by its descriptor.
- Query rows and field descriptions use canonical protocol messages.

After parity, Rust peer-postgres, peer-mysql, peer-bigquery, and peer-snowflake executor selection no longer determines connector availability.

Catalog queries remain local and are not routed to plugins.

---

## 19. Core State and Observability

### 19.1 Catalog ownership

Core owns:

- Peer and flow definitions.
- Encrypted configuration.
- CDC and QRep monitoring.
- Canonical source checkpoints.
- Schema mapping and audit history.
- Plugin inventory and migration audit.
- Temporal workflow status.

A destination plugin owns target-side tables and metadata needed for atomic destination idempotency.

### 19.2 Replacing external metadata coupling

Current connector calls into external_metadata and monitoring are migrated in this order:

1. Return progress and results through existing operation responses or streams.
2. Move canonical monitoring writes into Core adapters.
3. Keep target-transaction metadata inside the destination plugin.
4. Use scoped `PluginHostService` state methods only where the plugin must read or atomically update Core-owned connector state.

A generic catalog client is never part of the SDK.

### 19.3 Tracing

Core sends W3C trace context and structured operation context with every call:

- flow_id and flow_name.
- peer_id.
- operation_id.
- Temporal workflow and activity IDs.
- batch or partition ID.
- table identifier when scoped.

Plugins create child spans and export through configured OTLP endpoints. A plugin is not given an OtelManager pointer.

### 19.4 Logs

- Plugin stderr is treated as structured JSON log input.
- Core attaches plugin ID, version, digest, process ID, and active operation metadata.
- stdout is not an RPC channel and should remain unused after startup.
- Both Core and plugin apply manifest secret-path redaction.
- Official plugin conformance tests include secret canaries.

### 19.5 Metrics

Every supervisor exports:

- Process starts, exits, and restart backoff.
- Open sessions and active operations.
- RPC duration and error category.
- Stream frames, records, compressed bytes, and uncompressed bytes.
- Outstanding backpressure window.
- Plugin RSS, CPU, open file descriptors, and child processes when available.
- Quarantine and compatibility failures.

Connector-defined metrics use a namespaced descriptor and bounded label set.

---

## 20. Security Model

### 20.1 Trust statement

A native plugin is trusted connector code with reduced blast radius. A subprocess boundary prevents dependency collisions and many accidental Core crashes; it does not make hostile native code safe by itself.

### 20.2 Artifact trust

Production policy requires:

- SHA-256 pinning.
- Signature verification against configured identities or trust roots.
- Immutable artifact storage.
- SBOM for official plugins.
- License metadata.
- Audit log of install, enable, disable, migrate, and revoke actions.
- Optional allowlist of plugin IDs and publishers.

Unsigned development artifacts require an explicit development-mode flag and are visibly marked.

### 20.3 Process restrictions

Where supported, plugins run with:

- The non-root PeerDB service user or a dedicated plugin user.
- no_new_privs.
- A restrictive seccomp profile.
- Read-only artifact filesystem.
- A private writable temporary directory with quota.
- No host PID or Docker socket access.
- Resource limits for memory, CPU, processes, files, and file descriptors.
- A dedicated process group and parent-death behavior.
- An egress policy appropriate for configured connector endpoints.

Per-plugin containers may be added for high-risk environments while retaining the same protocol.

### 20.4 Credential handling

- Core decrypts a peer configuration only when opening an authorized session.
- Configuration crosses only the authenticated private socket.
- The plugin receives only the peer configuration and operation data it needs.
- Secrets are never placed in command arguments, manifest files, logs, metrics, traces, or health output.
- Config payloads are zeroed where practical after session close.
- Core never forwards one connector's credential to another connector.
- Object-reference headers require explicit policy and short expiry.

### 20.5 Protocol defense

Core enforces:

- Message and decompressed-size limits.
- Stream duration and idle deadlines.
- Schema and enum validation.
- Monotonic sequence and acknowledgement checks.
- Bounded unknown-field handling.
- Per-session authorization.
- Rate limits for control and query calls.
- Crash-loop circuit breaking.

Repeated malformed or unauthorized messages quarantine the process instance and may disable the artifact according to policy.

---

## 21. Versioning and Upgrade Policy

### 21.1 Independent version axes

The architecture has five explicit version axes:

1. Plugin artifact Semantic Version.
2. Core-plugin protocol major and minor.
3. Capability revision.
4. Record-format revision.
5. Connector configuration schema version.

They are not interchangeable.

### 21.2 Protocol compatibility

- Major versions are incompatible.
- Minor versions are additive.
- Required fields are never added in a minor version without a negotiated feature.
- Fields are never renumbered or repurposed.
- Unknown enum values are preserved or rejected according to the message contract.
- Buf breaking-change checks run in Core CI.
- Core supports the current protocol major and at least the previous approved minor range.

### 21.3 Capability compatibility

A new capability revision is selected only when both sides advertise it. Existing capability revisions remain frozen except for backward-compatible protobuf additions and clarified semantics.

### 21.4 Plugin upgrades

Upgrade procedure:

1. Install and verify the new artifact beside the old one.
2. Run conformance and connector health checks.
3. Mark the new version as the default for new peers.
4. Dry-run configuration migration for selected peers.
5. Pause or drain affected flows when required.
6. Persist the new ConnectorRef and migrated configuration atomically.
7. Resume and monitor.
8. Retain the old artifact through the rollback window.

Running flows never follow a changed default automatically.

### 21.5 Revocation

If an artifact is revoked:

- New sessions are denied.
- Existing sessions are either drained or terminated according to severity.
- Affected peers and flows are listed explicitly.
- Core does not silently substitute another version.
- Recovery requires an administrator-approved version change.

---

## 22. Repository and Release Layout

### 22.1 peerdb repository

Core contains:

~~~text
protos/peerdb/plugin/v1/
flow/plugin-sdk/
flow/plugin/
  registry/
  supervisor/
  adapter/
  legacy/
  testhost/
ui/components/ConnectorSchemaForm/
docs/
~~~

The SDK is a small independently consumable module. It contains:

- Generated protobuf services and messages.
- Server scaffolding.
- Manifest types and validation.
- Canonical value and stream helpers.
- Error helpers.
- A conformance testkit.

It does not contain application packages or connector implementations.

### 22.2 peerdb-plugins repository

The official plugin repository contains:

~~~text
plugins/
  postgres/
  mysql/
  mongo/
  bigquery/
  snowflake/
  clickhouse/
  s3/
  kafka/
  pubsub/
  eventhubs/
  elasticsearch/
  cockroachdb/
internal/
  common/
release/
  manifests/
  lockfiles/
~~~

Each plugins directory has:

- Its own command entrypoint.
- Manifest and schemas.
- Connector code.
- Unit tests.
- Core conformance tests.
- Integration and fault-injection tests.
- Release metadata.

Shared code in peerdb-plugins may not import PeerDB application packages.

### 22.3 Release artifacts

CI builds per-platform binaries, generates SBOMs, runs conformance tests, signs artifacts, and publishes:

- One OCI artifact per connector version.
- One immutable manifest.
- Optional curated bundle lockfiles.
- Compatibility and deprecation metadata.

Core releases do not need to rebuild unchanged plugin binaries.

---

## 23. Rollout Plan

Every phase must leave the main branch deployable.

### Phase 0: Baseline and contract inventory

- Freeze behavioral E2E baselines for every connector role.
- Add throughput, memory, and latency benchmarks.
- Add fault-injection points around source emission, destination commit, acknowledgement, and snapshot lease loss.
- Record current public API and catalog compatibility fixtures.

### Phase 1: Protocol, SDK, and runtime

- Add plugin/v1 protobuf definitions.
- Add manifest validation, registry, lockfile, supervisor, and health diagnostics.
- Add a synthetic test plugin with schema and echo-stream capabilities.
- Add Core RPC adapters without changing production connector selection.

### Phase 2: Generic identity and descriptor UI

- Add ConnectorRef and PeerV2.
- Add catalog columns and dual-read compatibility.
- Add descriptor APIs.
- Add generic UI form rendering.
- Make Nexus accept arbitrary connector identifiers.
- Keep legacy DBType aliases.

### Phase 3: In-process compatibility registry

- Register current connectors through descriptor-backed legacy factories.
- Replace DBType routing with connector ID and capability checks.
- Replace Core concrete-type branches with explicit optional capabilities.
- Persist deterministic pair plans.

This phase proves the control-plane design before process extraction.

### Phase 4: Host-state and data-model inversion

- Move monitoring writes to Core adapters.
- Replace CatalogPool and OtelManager parameters.
- Add canonical record values and stream conformance fixtures.
- Replace live transaction and callback objects with handles.
- Remove flow/internal imports from connector code.

### Phase 5: Destination extraction

Extract in this exact order:

1. S3.
2. Elasticsearch.
3. Kafka.
4. Google Pub/Sub.
5. Azure Event Hubs.
6. Snowflake.
7. BigQuery destination role.
8. ClickHouse.

The order begins with small, stateless or mostly append-oriented destinations, then moves to warehouse normalization and staging behavior.

### Phase 6: Object and QRep optimization

- Externalize BigQuery source object mode.
- Externalize ClickHouse object consumption.
- Replace HeaderProvider with ObjectReference policy.
- Validate canonical row and optional Arrow paths.

### Phase 7: Source extraction

Extract in this order:

1. MongoDB.
2. MySQL and MariaDB.
3. CockroachDB validation and query roles.
4. PostgreSQL.

PostgreSQL is last because it owns the broadest surface: logical replication, snapshot leases, PG-to-PG formats, XMIN, publications, slots, WAL diagnostics, pg_dump, query, and destination behavior.

### Phase 8: Query unification

- Route Nexus and Switchboard through QueryService.
- Remove connector-specific Rust executor selection.
- Preserve catalog-local queries.
- Add query crash, cancellation, and guardrail E2E tests.

Query work may start earlier for CockroachDB, but removal of all legacy query paths occurs here.

### Phase 9: Repository split completion

- Move all official connector implementation code and tests to peerdb-plugins.
- Remove concrete connector imports from Core.
- Remove unneeded database driver dependencies from Core go.mod and Cargo workspaces.
- Build Core images with an explicit curated plugin bundle or mounted lockfile.
- Retain legacy config translation through the announced compatibility window.

### Phase 10: Legacy removal

After at least one stable release window:

- Stop creating legacy Peer messages.
- Remove DBType-dependent connector construction.
- Remove old UI forms.
- Remove legacy catalog config decoding after migration tooling reports no remaining peers.
- Keep SQL aliases as descriptor aliases if desired.

---

## 24. Connector Extraction Checklist

A connector is considered extracted only when:

- Its production implementation is absent from Core.
- Its driver dependencies are absent from Core unless independently needed.
- It imports only the published SDK and plugin-repository libraries.
- Its manifest accurately declares every role and capability.
- Its connection and mirror forms are descriptor-driven.
- Its legacy config has a tested translator.
- It passes Core conformance tests.
- It passes connector E2E parity tests.
- It passes process-crash and retry tests.
- It publishes signed artifacts and an SBOM.
- Core has no DBType or concrete-type branch for it.
- Nexus and Switchboard do not instantiate its driver directly.

Moving files without satisfying these items is not extraction.

---

## 25. Failure Modes and Required Behavior

| Failure | Required behavior |
|---|---|
| Invalid manifest | Do not execute. Report exact schema violation. |
| Digest or signature mismatch | Quarantine artifact and fail readiness if required by lockfile. |
| Protocol major mismatch | Do not launch sessions. Report installed and required ranges. |
| Binary identity differs from manifest | Quarantine artifact immediately. |
| Missing plugin on one worker | Worker fails readiness before polling the shared task queue. |
| Plugin fails to start | Apply bounded backoff; fail a required operation with plugin-unavailable details. |
| Idle plugin process crashes | Invalidate sessions, record crash, and restart lazily within circuit-breaker policy. |
| Source crashes during CDC | Cancel destination, fail activity, retry from last durable checkpoint. |
| Destination crashes before commit | Abort batch and retry same batch and idempotency key. |
| Destination commits then crashes before ACK | Retry same batch; destination returns prior committed result. |
| Source emits then crashes before destination durability | Retry from last durable checkpoint; duplicate emission is tolerated. |
| Snapshot plugin crashes | Invalidate lease and restart the snapshot Temporal session from a safe boundary. |
| Core worker crashes | Child process exits through parent-death/process-group policy; Temporal retries activity. |
| Plugin hangs | Deadline, cancel, grace period, process termination, circuit-breaker accounting. |
| Destination is slow | Bounded window fills and stops source reads; memory stays bounded. |
| Plugin sends oversized frame | Terminate operation; repeated violations quarantine process instance. |
| Malformed sequence or acknowledgement | Treat as protocol violation; never advance checkpoint. |
| Catalog unavailable | Host state call fails; plugin operation does not bypass Core state; activity retries. |
| Object URL expires | Source refreshes through scoped operation or partition retries; static credentials are not substituted. |
| Query plugin crashes | Terminate affected client query/session with a safe SQL error; other Core sessions remain alive. |
| Config migration fails | Leave stored encrypted configuration and ConnectorRef unchanged. |
| Upgrade incompatible with active flow | Refuse change and list incompatible capabilities or formats. |
| Artifact revoked | Deny new sessions and require explicit drain or termination policy. |
| Disk or temporary quota exhausted | Return RESOURCE_EXHAUSTED, clean operation temp data, and preserve durable checkpoints. |
| Plugin logs a secret | Redaction catches known paths; conformance fails official plugin; security incident process applies. |

---

## 26. Acceptance Criteria

### 26.1 Extensibility

- A signed synthetic connector can be dropped into the plugin inventory, enabled in the lockfile, and used without rebuilding Go, Rust, or TypeScript application binaries.
- The connector appears in the UI with its icon, roles, connection form, and mirror options.
- Nexus accepts its stable string ID without parser changes.
- No registration switch or numeric enum addition is required.

### 26.2 Functional parity

- Every currently supported connector role passes equivalent CDC, QRep, snapshot, schema, validation, cleanup, and query E2E tests after extraction.
- Existing peers and flows can be read during the compatibility window.
- Migration dry-run and rollback are tested against catalog fixtures from supported prior releases.
- Postgres-to-Postgres and BigQuery-to-ClickHouse optimized paths use negotiated formats rather than concrete connector assertions.

### 26.3 Correctness

- Fault injection at every destination commit and acknowledgement boundary demonstrates no data loss.
- Duplicate attempts are idempotent for CDC batches and QRep partitions.
- Schema deltas remain ordered relative to affected records.
- NULL, absent, unavailable, and unchanged-TOAST states survive round trips.
- Snapshot process loss cannot silently continue under an invalid transaction.
- Checkpoints are monotonic and advance only after destination durability.

### 26.4 Performance

- Canonical batched RPC CDC throughput is at least 95 percent of the in-process baseline for representative workloads.
- Optimized Postgres and object paths are at least 95 percent of their prior baseline.
- Added p95 batch latency is no more than 10 percent under steady state.
- Core plus plugin aggregate CPU is no more than 10 percent above baseline for the same throughput.
- Host memory remains within the configured stream window plus a documented fixed overhead.
- A 24-hour mixed CDC and QRep soak has no unbounded RSS, goroutine, file-descriptor, session, or temporary-file growth.

Any connector unable to meet a general threshold must document and receive an explicit exception with a remediation plan.

### 26.5 Resilience

- Killing a plugin process cannot kill Flow API, a worker, or another plugin process.
- Crash-loop circuit breaking prevents unbounded fork attempts.
- Worker lockfile mismatch is detected before Temporal polling.
- Plugin and Core restarts resume from durable state.
- Cancellation releases connector sessions, leases, sockets, and temporary files within bounded time.

### 26.6 Security

- Production artifacts are digest-pinned and signature-verified.
- Config secrets do not appear in command lines, manifests, logs, traces, metrics, or descriptor APIs.
- Plugins have no catalog DSN and cannot execute arbitrary catalog SQL.
- UDS authentication and per-session authorization tests reject cross-session calls.
- Official artifacts publish SBOMs and pass dependency and vulnerability policy.

### 26.7 Maintainability

- Core imports no concrete connector implementation package.
- Core build files do not include connector driver SDKs solely for connector functionality.
- peerdb-plugins builds against a released SDK without a source checkout of the PeerDB application.
- Buf compatibility checks and plugin conformance suites run in CI.
- The documentation includes a third-party connector tutorial based only on public contracts.

---

## 27. Testing Strategy

### 27.1 Protocol tests

- Golden protobuf fixtures for every canonical value and record kind.
- Unknown-field and minor-version compatibility.
- Frame size, compression, and decompression bounds.
- Sequence, acknowledgement, and idempotency state machines.
- Error-code mapping.

### 27.2 Supervisor tests

- Launch authentication.
- Manifest and binary identity mismatch.
- Startup timeout.
- Graceful drain and forced termination.
- Crash loops and circuit breaking.
- Parent death.
- Session isolation and TTL.
- Resource limit enforcement where available.

### 27.3 Conformance testkit

The public testkit runs against any plugin executable and verifies:

- Manifest/runtime agreement.
- Capability-required methods.
- Config schema and secret paths.
- Open/close idempotency.
- Deadline and cancellation behavior.
- Stream backpressure.
- Malformed host input handling.
- Error envelope safety.
- No logs containing supplied secret canaries.

Capability-specific conformance suites add source, destination, query, and snapshot rules.

### 27.4 Connector E2E tests

Each official plugin runs:

- Real upstream and target containers or approved cloud fixtures.
- Existing connector regression suites adapted to public SDK boundaries.
- Core-to-plugin and plugin-to-Core version matrix tests.
- Upgrade and config migration tests.
- Kill-at-boundary fault injection.
- Performance and soak tests for release candidates.

---

## 28. Rejected Alternatives

### 28.1 Go shared-object plugins

Rejected.

Go's plugin package is not a stable community ABI:

- Host and plugin commonly need the same Go toolchain version.
- Shared package versions and build flags must align closely.
- Type identity across duplicated dependencies is fragile.
- Support is platform-limited.
- Plugins cannot be unloaded safely.
- Dependency and symbol conflicts remain in-process.
- A connector panic, memory corruption, deadlock, or runaway allocation affects Core.
- CGo and native driver dependencies complicate deployment further.

It would reproduce the appearance of Metabase JAR loading without the JVM classloader and compatibility properties that make that model workable there.

### 28.2 Static factory registry only

Rejected as the final architecture.

A string-keyed Go registry would reduce switches but still require recompiling Core, retain dependency conflicts, and prevent independent connector releases. It is useful only as a temporary compatibility phase.

### 28.3 One monolithic external connector process

Rejected.

Combining all connectors in one binary preserves dependency conflicts and couples releases. A crash or upgrade of one connector would affect all connector sessions.

### 28.4 Direct source-to-destination plugin streams

Rejected.

Direct links would:

- Couple independently developed plugins.
- Bypass Core transformations and observability.
- Complicate credentials and trust.
- Make checkpoint and retry ownership ambiguous.
- Prevent consistent backpressure and policy enforcement.

Core remains the broker.

### 28.5 Plugins with direct catalog access

Rejected.

Catalog DSNs and generic SQL would make catalog schema a public ABI, expose unrelated tenant state, and allow plugins to bypass Temporal and Core invariants. Scoped host state is the only permitted reverse interface.

### 28.6 JSON over HTTP for row transport

Rejected.

JSON cannot efficiently or unambiguously preserve the complete type system, absent versus NULL semantics, binary values, very large numerics, and high-throughput batching. JSON remains appropriate for human-authored configuration, not the data plane.

### 28.7 Plugin-provided UI JavaScript

Rejected for protocol v1.

Arbitrary browser bundles expand the supply-chain and cross-site scripting surface, couple plugins to UI internals, and make upgrades difficult. Declarative schema covers connection and mirror forms without executing plugin code in the browser.

### 28.8 WebAssembly as the only runtime

Rejected for protocol v1, retained as a future optional runtime.

WASM offers stronger isolation but current database driver ecosystems, CGo/native TLS requirements, network APIs, and high-throughput streaming support would exclude important connectors or require extensive shims. The manifest may gain a WASM entrypoint type later without changing connector identity.

### 28.9 Always-remote connector services

Rejected as the default.

Remote services add network identity, deployment, latency, availability, and multi-tenant state concerns before the local ABI is proven. The gRPC contract is intentionally compatible with a future authenticated remote transport, but v1 supervision is local.

### 28.10 Transparent automatic plugin upgrades

Rejected.

Changing connector code during a Temporal retry can change data conversion, idempotency, or schema behavior. Exact versions are pinned and upgrades are explicit.

### 28.11 Hot reload

Rejected for protocol v1.

Startup discovery plus side-by-side versions has simpler failure semantics. A future implementation may add installation while running, but an active session remains pinned to its original process and artifact.

---

## 29. Consequences

### 29.1 Positive

- Deprecated or community connectors can evolve outside Core.
- Core becomes smaller and sheds heavy driver dependencies.
- Connector crashes and dependency conflicts are isolated.
- Capability and compatibility become explicit and inspectable.
- UI and SQL control planes no longer need connector-specific releases.
- Version pinning makes retries and upgrades reproducible.
- A public SDK enables external connector development and conformance testing.

### 29.2 Costs

- Streaming RPC adds serialization, copying, and operational complexity.
- Snapshot and transaction lifetime must be modeled explicitly.
- Core needs a robust process supervisor and artifact trust policy.
- Every current connector requires meaningful refactoring before it can move.
- Cluster plugin inventories become a deployment concern.
- Cross-repository compatibility testing becomes mandatory.

These costs are accepted because they replace hidden in-process coupling with explicit, testable contracts.

---

## 30. Implementation Guardrails

The following shortcuts are prohibited:

- Moving connector directories to peerdb-plugins while importing flow/internal through replace directives.
- Passing catalog credentials to avoid designing host state.
- Encoding current Go structs with gob as the RPC payload.
- Implementing a remote object that claims every Go capability and relying on failed RPCs for discovery.
- Advancing a source checkpoint on receipt rather than destination durability.
- Retrying unknown destination mutations with a new idempotency key.
- Resolving a floating plugin version inside an activity.
- Calling plugin RPCs from Temporal workflow code.
- Loading unsigned native code silently in production.
- Adding connector-specific branches to Core after a public capability exists.

Temporary compatibility code must:

- Live under an explicitly named legacy package.
- Have migration telemetry.
- Have an owner and removal milestone.
- Never be required by a newly created generic peer.

---

## 31. Final Definition of Done

The plugin project is complete when a third party can:

1. Implement the public protocol using the published SDK.
2. Declare capabilities and forms in a manifest.
3. Pass the standalone conformance testkit.
4. Publish a signed artifact.
5. Add its exact reference to a PeerDB plugin lockfile.
6. Restart the applicable PeerDB services.
7. Create and operate a peer through UI, API, and Nexus.

No patch to PeerDB Core, no new DBType value, no generated application-code change, and no Core rebuild may be required.

---

## 32. References

- [Metabase driver plugin documentation](https://www.metabase.com/docs/latest/developers-guide/drivers/plugins)
- [Metabase community driver documentation](https://www.metabase.com/docs/latest/developers-guide/community-drivers)
- [Metabase plugin discovery implementation](https://github.com/metabase/metabase/blob/9b9b40a5f900b6dff6247b742e5a5c4049504903/src/metabase/plugins/impl.clj#L74-L235)
- [Metabase lazy driver activation](https://github.com/metabase/metabase/blob/9b9b40a5f900b6dff6247b742e5a5c4049504903/src/metabase/plugins/lazy_loaded_driver.clj#L48-L106)
- [Metabase plugin dependency resolution](https://github.com/metabase/metabase/blob/9b9b40a5f900b6dff6247b742e5a5c4049504903/src/metabase/plugins/dependencies.clj#L18-L113)
- [Metabase classloader implementation and isolation limits](https://github.com/metabase/metabase/blob/9b9b40a5f900b6dff6247b742e5a5c4049504903/src/metabase/classloader/impl.clj#L25-L172)
- [Official Go `plugin` package warnings](https://pkg.go.dev/plugin)
- [HashiCorp go-plugin subprocess RPC model](https://github.com/hashicorp/go-plugin)
- [PeerDB pull request 3204](https://github.com/PeerDB-io/peerdb/pull/3204)
