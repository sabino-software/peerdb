package pluginlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/PeerDB-io/peerdb/flow/connectors/plugins"
)

const inventoryHashVersion = "peerdb-plugin-inventory/v1"

// IssueCode is a stable machine-readable reconciliation outcome.
type IssueCode string

const (
	IssueMissingPlugin     IssueCode = "missing-plugin"
	IssuePlatformMismatch  IssueCode = "platform-mismatch"
	IssueDigestMismatch    IssueCode = "digest-mismatch"
	IssueManifestDigest    IssueCode = "manifest-digest-mismatch"
	IssueProtocolMismatch  IssueCode = "protocol-mismatch"
	IssueTrustMismatch     IssueCode = "trust-mismatch"
	IssueTrustUnverified   IssueCode = "trust-unverified"
	IssueConnectorMismatch IssueCode = "connector-mismatch"
	IssueUnapprovedPlugin  IssueCode = "unapproved-plugin"
)

// Issue explains why desired and discovered runnable inventories differ.
type Issue struct {
	Code      IssueCode
	PluginKey string
	Message   string
}

// Result is an immutable reconciliation snapshot. Any issue makes the worker
// inventory unready; callers may only launch descriptors returned by
// Authorized.
type Result struct {
	authorized    []plugins.Descriptor
	issues        []Issue
	inventoryHash string
}

// VerifiedAttestation is the output expected from a future artifact-signature
// verifier. The identity alone is never sufficient: it is bound to the exact
// plugin key, executable digest, and manifest digest. Callers must not create
// this value from lockfile claims.
type VerifiedAttestation struct {
	PluginKey      string
	ArtifactDigest string
	ManifestDigest string
	TrustIdentity  string
}

// Ready reports whether every enabled lock entry matched and no unapproved
// runnable descriptor was discovered.
func (r *Result) Ready() bool {
	return r != nil && len(r.issues) == 0
}

// Authorized returns matching descriptors in discovery dependency order.
func (r *Result) Authorized() []plugins.Descriptor {
	if r == nil {
		return nil
	}
	return append([]plugins.Descriptor(nil), r.authorized...)
}

func (r *Result) Issues() []Issue {
	if r == nil {
		return nil
	}
	return append([]Issue(nil), r.issues...)
}

// InventoryHash is a stable sha256:<hex> digest of the sorted desired runnable
// identity: plugin ID, exact version, platform, artifact and manifest digests,
// protocol, signer/trust identity, and connector IDs. Source locations,
// generation metadata, document order, and disabled or planned entries are
// deliberately excluded.
func (r *Result) InventoryHash() string {
	if r == nil {
		return ""
	}
	return r.inventoryHash
}

// Reconcile compares an immutable lock with a discovery snapshot. Operational
// drift is returned as deterministic issues rather than an error. Errors are
// reserved for invalid API inputs or an internal canonicalization failure.
func Reconcile(lock *Lock, snapshot *plugins.Snapshot) (*Result, error) {
	return ReconcileWithAttestations(lock, snapshot, nil)
}

// ReconcileWithAttestations additionally consumes identities produced by an
// artifact signature verifier. Until such an attestation is supplied for an
// enabled entry, reconciliation fails closed with IssueTrustUnverified.
func ReconcileWithAttestations(
	lock *Lock,
	snapshot *plugins.Snapshot,
	attestations []VerifiedAttestation,
) (*Result, error) {
	if lock == nil {
		return nil, fmt.Errorf("plugin lock must not be nil")
	}
	if snapshot == nil {
		return nil, fmt.Errorf("plugin snapshot must not be nil")
	}
	attestationsByKey := make(map[string]VerifiedAttestation, len(attestations))
	for index, attestation := range attestations {
		if strings.TrimSpace(attestation.PluginKey) == "" {
			return nil, fmt.Errorf("verified attestation %d has an empty plugin key", index)
		}
		if _, duplicate := attestationsByKey[attestation.PluginKey]; duplicate {
			return nil, fmt.Errorf("verified attestations duplicate plugin key %q", attestation.PluginKey)
		}
		attestationsByKey[attestation.PluginKey] = attestation
	}

	inventoryHash, err := hashRunnableInventory(lock.plugins)
	if err != nil {
		return nil, fmt.Errorf("hash desired plugin inventory: %w", err)
	}
	descriptors := snapshot.Descriptors()
	descriptorsByKey := make(map[string]plugins.Descriptor, len(descriptors))
	for _, descriptor := range descriptors {
		descriptorsByKey[descriptor.Key()] = descriptor
	}

	desiredByKey := make(map[string]Entry)
	for _, entry := range lock.plugins {
		if entry.state == StateLocked && entry.enabled {
			desiredByKey[entry.Key()] = entry
		}
	}
	desiredKeys := make([]string, 0, len(desiredByKey))
	for key := range desiredByKey {
		desiredKeys = append(desiredKeys, key)
	}
	sort.Strings(desiredKeys)

	matched := make(map[string]struct{}, len(desiredKeys))
	issues := make([]Issue, 0)
	for _, key := range desiredKeys {
		entry := desiredByKey[key]
		descriptor, found := descriptorsByKey[key]
		if !found {
			issues = append(issues, Issue{
				Code:      IssueMissingPlugin,
				PluginKey: key,
				Message:   fmt.Sprintf("enabled plugin %q is not ready in the discovered inventory", key),
			})
			continue
		}

		matches := true
		if descriptor.Platform() != entry.platform {
			matches = false
			issues = append(issues, Issue{
				Code:      IssuePlatformMismatch,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q has platform %q, lock requires %q",
					key,
					descriptor.Platform(),
					entry.platform,
				),
			})
		}
		if descriptor.SHA256() != entry.digest {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueDigestMismatch,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q has digest %q, lock requires %q",
					key,
					descriptor.SHA256(),
					entry.digest,
				),
			})
		}
		if descriptor.ManifestSHA256() != entry.manifestDigest {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueManifestDigest,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q has manifest digest %q, lock requires %q",
					key,
					descriptor.ManifestSHA256(),
					entry.manifestDigest,
				),
			})
		}
		manifest := descriptor.Manifest()
		if manifest.Spec.Protocol.Major != entry.protocol.major ||
			manifest.Spec.Protocol.Minor != entry.protocol.minor {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueProtocolMismatch,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q declares protocol %d.%d, lock requires %d.%d",
					key,
					manifest.Spec.Protocol.Major,
					manifest.Spec.Protocol.Minor,
					entry.protocol.major,
					entry.protocol.minor,
				),
			})
		}
		attestation, attested := attestationsByKey[key]
		if !attested {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueTrustUnverified,
				PluginKey: key,
				Message:   fmt.Sprintf("plugin %q has no verified signer/trust attestation", key),
			})
		} else if attestation.ArtifactDigest != entry.digest ||
			attestation.ManifestDigest != entry.manifestDigest ||
			attestation.TrustIdentity != entry.trustIdentity {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueTrustMismatch,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q attestation does not bind the locked artifact, manifest, and trust identity",
					key,
				),
			})
		}
		actualConnectors := descriptorConnectorIDs(descriptor)
		expectedConnectors := sortedStrings(entry.connectors)
		if !slices.Equal(actualConnectors, expectedConnectors) {
			matches = false
			issues = append(issues, Issue{
				Code:      IssueConnectorMismatch,
				PluginKey: key,
				Message: fmt.Sprintf(
					"plugin %q exposes connectors [%s], lock requires [%s]",
					key,
					strings.Join(actualConnectors, ", "),
					strings.Join(expectedConnectors, ", "),
				),
			})
		}
		if matches {
			matched[key] = struct{}{}
		}
	}

	for _, descriptor := range descriptors {
		if _, approved := desiredByKey[descriptor.Key()]; approved {
			continue
		}
		issues = append(issues, Issue{
			Code:      IssueUnapprovedPlugin,
			PluginKey: descriptor.Key(),
			Message:   fmt.Sprintf("ready plugin %q is not enabled by the lock", descriptor.Key()),
		})
	}
	sort.Slice(issues, func(left, right int) bool {
		if issues[left].PluginKey != issues[right].PluginKey {
			return issues[left].PluginKey < issues[right].PluginKey
		}
		if issues[left].Code != issues[right].Code {
			return issues[left].Code < issues[right].Code
		}
		return issues[left].Message < issues[right].Message
	})

	authorized := make([]plugins.Descriptor, 0, len(matched))
	for _, descriptor := range descriptors {
		if _, approved := matched[descriptor.Key()]; approved {
			authorized = append(authorized, descriptor)
		}
	}
	return &Result{
		authorized:    authorized,
		issues:        issues,
		inventoryHash: inventoryHash,
	}, nil
}

type canonicalInventory struct {
	Version string                  `json:"version"`
	Plugins []canonicalInventoryRow `json:"plugins"`
}

type canonicalInventoryRow struct {
	ID             string                   `json:"id"`
	Version        string                   `json:"version"`
	Platform       string                   `json:"platform"`
	Digest         string                   `json:"digest"`
	ManifestDigest string                   `json:"manifestDigest"`
	Protocol       canonicalProtocolVersion `json:"protocol"`
	TrustIdentity  string                   `json:"trustIdentity"`
	Connectors     []string                 `json:"connectors"`
}

type canonicalProtocolVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

func hashRunnableInventory(entries []Entry) (string, error) {
	rows := make([]canonicalInventoryRow, 0, len(entries))
	for _, entry := range entries {
		if entry.state != StateLocked || !entry.enabled {
			continue
		}
		rows = append(rows, canonicalInventoryRow{
			ID:             entry.id,
			Version:        entry.version,
			Platform:       entry.platform,
			Digest:         entry.digest,
			ManifestDigest: entry.manifestDigest,
			Protocol: canonicalProtocolVersion{
				Major: entry.protocol.major,
				Minor: entry.protocol.minor,
			},
			TrustIdentity: entry.trustIdentity,
			Connectors:    sortedStrings(entry.connectors),
		})
	}
	sort.Slice(rows, func(left, right int) bool {
		if rows[left].ID != rows[right].ID {
			return rows[left].ID < rows[right].ID
		}
		return rows[left].Version < rows[right].Version
	})
	canonical, err := json.Marshal(canonicalInventory{
		Version: inventoryHashVersion,
		Plugins: rows,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func descriptorConnectorIDs(descriptor plugins.Descriptor) []string {
	manifest := descriptor.Manifest()
	connectorIDs := make([]string, len(manifest.Spec.Connectors))
	for index, connector := range manifest.Spec.Connectors {
		connectorIDs[index] = connector.ID
	}
	return sortedStrings(connectorIDs)
}

func sortedStrings(values []string) []string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	return copy
}
