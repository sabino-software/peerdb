// Package pluginmanager converts a fully authorized plugin-lock result into
// the narrow manifest specifications accepted by the process supervisor.
//
// It intentionally has no discovery or lockfile bypass: callers cannot build a
// supervisor Spec from an arbitrary descriptor through this package.
package pluginmanager

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PeerDB-io/peerdb/flow/connectors/pluginlock"
	"github.com/PeerDB-io/peerdb/flow/connectors/pluginruntime"
	"github.com/PeerDB-io/peerdb/flow/connectors/plugins"
)

var (
	ErrAdapterRequired = errors.New("plugin manager adapter is required")
	ErrResultRequired  = errors.New("plugin lock result is required")
	ErrResultNotReady  = errors.New("plugin lock result is not ready")
)

// Adapter binds lock reconciliation to one explicit Core version. Keeping the
// Core version on the adapter prevents callers from accidentally authorizing a
// descriptor under one version and launching it under another.
type Adapter struct {
	coreVersion string
}

// New constructs an adapter for a strict semantic Core version.
func New(coreVersion string) (*Adapter, error) {
	if err := plugins.ValidateSemanticVersion(coreVersion); err != nil {
		return nil, fmt.Errorf("Core version: %w", err)
	}
	return &Adapter{coreVersion: coreVersion}, nil
}

// NotReadyError preserves the deterministic reconciliation diagnostics that
// prevented the complete authorized inventory from reaching the supervisor.
type NotReadyError struct {
	issues []pluginlock.Issue
}

func (e *NotReadyError) Error() string {
	parts := make([]string, len(e.issues))
	for index, issue := range e.issues {
		parts[index] = fmt.Sprintf("%s/%s: %s", issue.PluginKey, issue.Code, issue.Message)
	}
	return ErrResultNotReady.Error() + ": " + strings.Join(parts, "; ")
}

func (e *NotReadyError) Unwrap() error {
	return ErrResultNotReady
}

func (e *NotReadyError) Issues() []pluginlock.Issue {
	if e == nil {
		return nil
	}
	return append([]pluginlock.Issue(nil), e.issues...)
}

// BuildSpecs is a convenience wrapper that constructs a version-bound Adapter.
func BuildSpecs(result *pluginlock.Result, coreVersion string) ([]pluginruntime.Spec, error) {
	adapter, err := New(coreVersion)
	if err != nil {
		return nil, err
	}
	return adapter.BuildSpecs(result)
}

// BuildSpecs converts the fully authorized descriptors from result into
// supervisor specifications. The returned order is the discovery dependency
// order preserved by pluginlock.Result.Authorized.
func (a *Adapter) BuildSpecs(result *pluginlock.Result) ([]pluginruntime.Spec, error) {
	if a == nil {
		return nil, ErrAdapterRequired
	}
	if result == nil {
		return nil, ErrResultRequired
	}
	if !result.Ready() {
		return nil, &NotReadyError{issues: result.Issues()}
	}

	descriptors := result.Authorized()
	specs := make([]pluginruntime.Spec, len(descriptors))
	seenKeys := make(map[string]struct{}, len(descriptors))
	for index, descriptor := range descriptors {
		if _, duplicate := seenKeys[descriptor.Key()]; duplicate {
			return nil, fmt.Errorf("authorized descriptor %d duplicates plugin key %q", index, descriptor.Key())
		}
		seenKeys[descriptor.Key()] = struct{}{}
		manifest := descriptor.Manifest()
		supported, err := plugins.SupportsCoreVersion(manifest, a.coreVersion)
		if err != nil {
			return nil, fmt.Errorf("authorized descriptor %d (%s): check Core compatibility: %w", index, descriptor.Key(), err)
		}
		if !supported {
			return nil, fmt.Errorf(
				"authorized descriptor %d (%s): Core version %s is outside manifest interval [%s, %s)",
				index,
				descriptor.Key(),
				a.coreVersion,
				manifest.Spec.CoreVersions.Minimum,
				manifest.Spec.CoreVersions.MaximumExclusive,
			)
		}
		spec, err := descriptorSpec(descriptor, manifest)
		if err != nil {
			return nil, fmt.Errorf("authorized descriptor %d (%s): %w", index, descriptor.Key(), err)
		}
		specs[index] = spec
	}
	return specs, nil
}

func descriptorSpec(descriptor plugins.Descriptor, manifest plugins.Manifest) (pluginruntime.Spec, error) {
	identity, err := pluginruntime.ParseIdentity(
		descriptor.ID(),
		descriptor.Version(),
		descriptor.SHA256(),
	)
	if err != nil {
		return pluginruntime.Spec{}, fmt.Errorf("convert artifact identity: %w", err)
	}
	if !filepath.IsAbs(descriptor.Entrypoint()) {
		return pluginruntime.Spec{}, fmt.Errorf("entrypoint must be absolute: %q", descriptor.Entrypoint())
	}
	platform := descriptor.Platform()
	if strings.TrimSpace(platform) == "" || platform != strings.TrimSpace(platform) ||
		strings.ContainsAny(platform, "\x00\r\n") {
		return pluginruntime.Spec{}, fmt.Errorf("platform is invalid: %q", platform)
	}
	protocol, err := runtimeProtocol(manifest.Spec.Protocol)
	if err != nil {
		return pluginruntime.Spec{}, err
	}

	connectors := make([]pluginruntime.ConnectorCapabilities, len(manifest.Spec.Connectors))
	for connectorIndex, connector := range manifest.Spec.Connectors {
		roles, err := runtimeRoles(connector.ID, connector.Roles)
		if err != nil {
			return pluginruntime.Spec{}, err
		}
		capabilities := make([]pluginruntime.Capability, len(connector.Capabilities))
		for capabilityIndex, capability := range connector.Capabilities {
			if capability.Version < 1 || uint64(capability.Version) > uint64(^uint32(0)) {
				return pluginruntime.Spec{}, fmt.Errorf(
					"connector %q capability %q has runtime-incompatible version %d",
					connector.ID,
					capability.Name,
					capability.Version,
				)
			}
			capabilities[capabilityIndex] = pluginruntime.Capability{
				Name:    capability.Name,
				Version: uint32(capability.Version),
			}
		}
		recordFormats, err := runtimeRecordFormats(connector.ID, connector.RecordFormats)
		if err != nil {
			return pluginruntime.Spec{}, err
		}
		connectors[connectorIndex] = pluginruntime.ConnectorCapabilities{
			ConnectorID:   connector.ID,
			Roles:         roles,
			Capabilities:  capabilities,
			RecordFormats: recordFormats,
		}
	}

	return pluginruntime.Spec{
		Identity:             identity,
		Executable:           descriptor.Entrypoint(),
		Platform:             platform,
		Protocol:             protocol,
		ManifestCapabilities: []pluginruntime.Capability{},
		ManifestConnectors:   connectors,
	}, nil
}

func runtimeProtocol(protocol plugins.ProtocolVersion) (pluginruntime.ProtocolRange, error) {
	if protocol.Major < 1 || uint64(protocol.Major) > uint64(^uint32(0)) {
		return pluginruntime.ProtocolRange{}, fmt.Errorf("protocol major %d is runtime-incompatible", protocol.Major)
	}
	if protocol.Minor < 0 || uint64(protocol.Minor) > uint64(^uint32(0)) {
		return pluginruntime.ProtocolRange{}, fmt.Errorf("protocol minor %d is runtime-incompatible", protocol.Minor)
	}
	return pluginruntime.ProtocolRange{
		Major:        uint32(protocol.Major),
		MinimumMinor: 0,
		MaximumMinor: uint32(protocol.Minor),
	}, nil
}

func runtimeRoles(connectorID string, roles []plugins.Role) ([]pluginruntime.ConnectorRole, error) {
	converted := make([]pluginruntime.ConnectorRole, len(roles))
	for index, role := range roles {
		switch role {
		case plugins.RoleSource:
			converted[index] = pluginruntime.ConnectorRoleSource
		case plugins.RoleDestination:
			converted[index] = pluginruntime.ConnectorRoleDestination
		case plugins.RoleQuery:
			converted[index] = pluginruntime.ConnectorRoleQuery
		default:
			return nil, fmt.Errorf("connector %q has runtime-incompatible role %q", connectorID, role)
		}
	}
	return converted, nil
}

func runtimeRecordFormats(
	connectorID string,
	formats []plugins.RecordFormat,
) ([]pluginruntime.RecordFormat, error) {
	converted := make([]pluginruntime.RecordFormat, len(formats))
	for index, format := range formats {
		switch format {
		case plugins.RecordFormatQValueProto:
			converted[index] = pluginruntime.RecordFormatQValueProtoV1
		case plugins.RecordFormatArrowIPC:
			converted[index] = pluginruntime.RecordFormatArrowIPCV1
		case plugins.RecordFormatPGText:
			converted[index] = pluginruntime.RecordFormatPGTextV1
		case plugins.RecordFormatPGCopy:
			converted[index] = pluginruntime.RecordFormatPGCopyV1
		case plugins.RecordFormatObjectRef:
			converted[index] = pluginruntime.RecordFormatObjectRefV1
		default:
			return nil, fmt.Errorf("connector %q has runtime-incompatible record format %q", connectorID, format)
		}
	}
	return converted, nil
}
