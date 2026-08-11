# PeerDB connector plugin protocol v1

This directory defines the process boundary between PeerDB and connector
plugins. It is deliberately language-neutral and contains no Go interfaces,
Temporal types, database connections, catalog handles, or connector-specific
objects.

The protocol is experimental until the first connector passes the contract
suite. During that period, incompatible changes may be made without preserving
wire compatibility. Once v1 is declared stable, its protobuf field numbers and
semantics are immutable. Additive RPCs and fields increment the protocol minor
version; incompatible behavior requires a new protobuf package and protocol
major version.

## Process and session model

PeerDB starts a plugin executable and connects over a private Unix domain
socket. The first call must be `Handshake`. The supervisor verifies the
manifest, artifact digest, protocol range, nonce proof, and descriptor before
making the plugin available.

For a local process, the supervisor passes a random 256-bit launch token through
an inherited anonymous file descriptor. `HandshakeResponse.nonce_proof` is
`HMAC-SHA256(launch_token, HandshakeRequest.nonce)`. The token is never placed in
an argument or environment variable. Peer configuration and credentials are not
sent until the proof and runtime descriptor match the verified artifact.

Every runnable plugin also exposes the standard `grpc.health.v1.Health`
service. The custom `Health` RPC returns connector-specific diagnostics;
standard health is the transport/readiness probe used by the supervisor.

One supervised plugin process may serve multiple sessions. Every operation
after discovery is authorized against an opaque `session_id`. Snapshot,
replication, and transaction handles belong to exactly one session and become
invalid if that process exits. A restarted process must never silently recreate
one of those handles.

On an orderly stop, the host calls `Drain`, rejects new sessions, waits until
the returned active-session count reaches zero or the deadline expires, then
calls `Shutdown`. The supervisor terminates the process group after the grace
period if it does not exit. Process death invalidates all sessions and leases.

Plugins are lazy-started and version-pinned. A running flow resolves the exact
plugin ID, plugin version, artifact digest, connector ID, config schema version,
protocol version, and negotiated record format. An upgrade therefore cannot
change the implementation used by an in-flight Temporal retry.

The manifest's protocol minor is the highest minor that artifact was certified
against. The handshake advertises a range and selects one compatible minor in
the same major; the lock pins the certified manifest value, while each flow
pins the selected handshake value.

## CDC delivery invariant

PeerDB remains the broker between source and destination plugins:

1. The source emits a monotonically increasing `ChangeBatch.sequence` and keeps
   that batch replayable.
2. PeerDB forwards it with a stable `MutationKey`; no canonical checkpoint is
   advanced from a progress frame or from receipt alone.
3. The destination atomically commits the data and its idempotency marker, then
   returns a durable `CdcPushAck` or committed result.
4. PeerDB persists the destination result and canonical checkpoint in its own
   catalog.
5. Only after that catalog commit may PeerDB send `CdcCheckpointAck` to the
   source. The source may then release replay state through that checkpoint.

Every acknowledgement repeats the emitted sequence and content SHA-256. A
plugin must reject an acknowledgement that does not match the retained frame.

An acknowledgement means the destination can tolerate replay according to its
connector contract. A disconnect before that acknowledgement causes replay;
it must never cause the source offset to advance. Implementations must bound
the number and total bytes of unacknowledged frames.

The host, not either plugin, owns cross-connector backpressure, retry policy,
checkpoint ordering, Temporal heartbeats, cancellation, and flow-level
observability. Source and destination plugins never connect directly.

## Mutation and replay invariant

CDC batches are keyed by `(flow_name, sync_batch_id)` and QRep writes by
`(flow_name, partition_id)`. The key is stable across process crashes, activity
retries, and reconnects. Destination plugins must commit the mutation and its
result marker atomically and return the stored result when the same key is
replayed. Reusing a key with different content is an idempotency error.

If a destination commits but its response is lost, the host calls
`GetBatchStatus` or `GetPartitionResult` before retrying. A committed result is
used to finish host bookkeeping; an in-progress result is not guessed; a
missing result may be replayed with the same key and content digest. Core never
creates a new key to hide an unknown outcome.

Mutating unary RPCs use `RequestContext.idempotency_key` under the same rule.
The key identifies the logical operation; `request_id` identifies one RPC
attempt. Calls documented as destructive must not be retried after an unknown
outcome unless their operation-specific status can be recovered.

## Data encodings

`RECORD_FORMAT_QVALUE_PROTO_V1` is the correctness baseline for CDC and row
replication. `TypedValue.logical_type` is the closed v1 type registry; scalar
canonicalization and null representation are documented on that message. A
negotiated format may replace the row payload for a session:

- Arrow IPC v1 for high-throughput QRep and snapshot batches;
- PostgreSQL text or COPY v1 for compatible fast paths;
- object-reference v1 for transfers such as BigQuery to ClickHouse.

Negotiation is per session. A plugin must reject an unsupported required format
instead of guessing. Encoded frames are subject to the negotiated maximum frame
size and compression.

Object references must be scoped to the current session and expire quickly.
Signed URLs are preferred. Sensitive headers never travel directly from one
plugin to another: the source returns an opaque authorization handle and policy
ID, and the destination resolves it through the audited host callback.

## Host responsibilities

The host owns PeerDB's catalog, encrypted peer configuration, secret storage,
flow metadata, checkpoints, tracing, and metrics. Plugins do not receive a
catalog DSN, a Temporal client, an `OtelManager`, or unrestricted SQL access.

`PluginHostService` is an authenticated reverse service. Its state methods are
namespaced to the plugin and session; they are not a general catalog API.
Secrets are returned only for manifest-declared JSON pointers and should be
short-lived where possible. Host implementations must redact secret values from
logs, errors, traces, and plugin descriptors.

Configuration migration is explicit and side-effect-free. `MigrateConfig`
performs exactly the requested schema step without opening a database connection
or mutating plugin/host state. Core validates, encrypts, and atomically persists
the returned configuration before changing a pinned connector reference.

## Errors

Operational failures use `PluginError`, either in a streaming terminal frame or
as structured gRPC status details for unary RPCs. `safe_message` and
`safe_details` are suitable for logs and UI. They must not contain credentials,
queries with sensitive literals, row contents, or unredacted vendor responses.

`retryable` is advisory. PeerDB remains responsible for the final Temporal retry
classification and must combine the error category with operation semantics.

## Capability evolution

Connectors advertise named, versioned capabilities in both the signed manifest
and the runtime descriptor. Runtime capabilities must be a subset of the
manifest. Sessions declare required capabilities, and opening the session fails
before side effects if any are unavailable.

Capability names are stable lowercase dotted identifiers. Adding an optional
capability is compatible. Changing an existing capability's behavior requires a
new capability version and a negotiation path in the host.

The repository's conformance suite is the executable definition of these
semantics. A plugin is distributable only after its manifest, handshake,
session isolation, cancellation, backpressure, replay, error redaction, and
declared capabilities pass that suite.
