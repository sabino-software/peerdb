package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/PeerDB-io/peerdb/flow/generated/protos/peerdb/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultSocketPollInterval = 10 * time.Millisecond

// HandshakePolicy is the Core-owned side of protocol negotiation. Every field
// except HealthService and SocketPollInterval is sent to the plugin and then
// enforced against its response. Slice order expresses host preference, while
// response sets are compared without relying on plugin-controlled ordering.
type HandshakePolicy struct {
	Protocol             ProtocolRange
	HostVersion          string
	HostInstanceID       string
	Compressions         []Compression
	RecordFormats        []RecordFormat
	MaximumFrameBytes    uint64
	HostCallbackProtocol ProtocolRange
	Features             []string
	HealthService        string
	SocketPollInterval   time.Duration
}

func (p HandshakePolicy) clone() HandshakePolicy {
	p.Compressions = slices.Clone(p.Compressions)
	p.RecordFormats = slices.Clone(p.RecordFormats)
	p.Features = slices.Clone(p.Features)
	return p
}

func (p HandshakePolicy) withDefaults() HandshakePolicy {
	if p.SocketPollInterval <= 0 {
		p.SocketPollInterval = defaultSocketPollInterval
	}
	return p
}

func (p HandshakePolicy) validate() error {
	if err := p.Protocol.validate("host"); err != nil {
		return err
	}
	if err := validateProtocolString("host version", p.HostVersion); err != nil {
		return err
	}
	if err := validateProtocolString("host instance ID", p.HostInstanceID); err != nil {
		return err
	}
	if len(p.Compressions) == 0 {
		return errors.New("host must offer at least one compression")
	}
	seenCompressions := make(map[Compression]struct{}, len(p.Compressions))
	for _, compression := range p.Compressions {
		if err := compression.validate(); err != nil {
			return fmt.Errorf("host compression: %w", err)
		}
		if _, duplicate := seenCompressions[compression]; duplicate {
			return fmt.Errorf("host has duplicate compression %s", compression)
		}
		seenCompressions[compression] = struct{}{}
	}
	if _, hasNone := seenCompressions[CompressionNone]; !hasNone {
		return errors.New("host compression offer must include none")
	}
	if len(p.RecordFormats) == 0 {
		return errors.New("host must offer at least one record format")
	}
	if err := validateRecordFormatSet("host", p.RecordFormats); err != nil {
		return err
	}
	if p.MaximumFrameBytes == 0 {
		return errors.New("host maximum frame size is required")
	}
	if p.MaximumFrameBytes > uint64(maximumInt()) {
		return fmt.Errorf("host maximum frame size %d exceeds platform int capacity", p.MaximumFrameBytes)
	}
	if err := p.HostCallbackProtocol.validate("host callback"); err != nil {
		return err
	}
	if err := validateStringSet("host feature", p.Features); err != nil {
		return err
	}
	if p.HealthService != strings.TrimSpace(p.HealthService) ||
		strings.ContainsAny(p.HealthService, "\x00\r\n") {
		return fmt.Errorf("health service is invalid: %q", p.HealthService)
	}
	if p.SocketPollInterval <= 0 {
		return errors.New("socket poll interval must be positive")
	}
	return nil
}

func validateProtocolString(scope, value string) error {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
		strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s is invalid: %q", scope, value)
	}
	return nil
}

func validateStringSet(scope string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
			strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s is invalid: %q", scope, value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s %q", scope, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func maximumInt() int {
	return int(^uint(0) >> 1)
}

// GRPCDialer connects generated protocol clients exclusively over the private
// Unix-domain socket supplied by Supervisor. It deliberately has no network,
// resolver, or endpoint configuration that a plugin can redirect to TCP.
type GRPCDialer struct {
	policy HandshakePolicy
}

var _ Dialer = (*GRPCDialer)(nil)

func NewGRPCDialer(policy HandshakePolicy) (*GRPCDialer, error) {
	policy = policy.withDefaults().clone()
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("invalid plugin handshake policy: %w", err)
	}
	return &GRPCDialer{policy: policy}, nil
}

func (d *GRPCDialer) Dial(ctx context.Context, socketPath string) (Client, error) {
	if !filepath.IsAbs(socketPath) || strings.ContainsRune(socketPath, '\x00') {
		return nil, fmt.Errorf("plugin socket path must be absolute and NUL-free: %q", socketPath)
	}
	if err := waitForPrivateSocket(ctx, socketPath, d.policy.SocketPollInterval); err != nil {
		return nil, err
	}

	udsDialer := func(ctx context.Context, _ string) (net.Conn, error) {
		if err := verifyPrivateSocket(socketPath); err != nil {
			return nil, err
		}
		var networkDialer net.Dialer
		return networkDialer.DialContext(ctx, "unix", socketPath)
	}
	frameLimit := int(d.policy.MaximumFrameBytes)
	connection, err := grpc.NewClient(
		"passthrough:///peerdb-plugin",
		grpc.WithContextDialer(udsDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(frameLimit),
			grpc.MaxCallSendMsgSize(frameLimit),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create plugin gRPC connection: %w", err)
	}
	return newGRPCControlClient(
		connection,
		pluginv1.NewPluginControlServiceClient(connection),
		healthpb.NewHealthClient(connection),
		d.policy,
	), nil
}

func waitForPrivateSocket(ctx context.Context, socketPath string, pollInterval time.Duration) error {
	for {
		err := verifyPrivateSocket(socketPath)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for plugin socket %q: %w", socketPath, ctx.Err())
		case <-timer.C:
		}
	}
}

func verifyPrivateSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("inspect plugin socket %q: %w", socketPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin socket must not be a symbolic link: %q", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("plugin endpoint is not a Unix-domain socket: %q", socketPath)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		return fmt.Errorf(
			"plugin socket %q has permissions %04o, want 0600",
			socketPath,
			permissions,
		)
	}
	return nil
}

type pluginControlRPC interface {
	Handshake(context.Context, *pluginv1.HandshakeRequest, ...grpc.CallOption) (*pluginv1.HandshakeResponse, error)
	Drain(context.Context, *pluginv1.DrainRequest, ...grpc.CallOption) (*pluginv1.DrainResponse, error)
	Shutdown(context.Context, *pluginv1.ShutdownRequest, ...grpc.CallOption) (*pluginv1.ShutdownResponse, error)
}

type grpcHealthRPC interface {
	Check(context.Context, *healthpb.HealthCheckRequest, ...grpc.CallOption) (*healthpb.HealthCheckResponse, error)
}

type grpcControlClient struct {
	connection io.Closer
	control    pluginControlRPC
	health     grpcHealthRPC
	policy     HandshakePolicy

	mu                 sync.Mutex
	handshakeAttempted bool
	authenticated      bool
	closed             bool
	closeOnce          sync.Once
	closeErr           error
}

var _ Client = (*grpcControlClient)(nil)

func newGRPCControlClient(
	connection io.Closer,
	control pluginControlRPC,
	health grpcHealthRPC,
	policy HandshakePolicy,
) *grpcControlClient {
	return &grpcControlClient{
		connection: connection,
		control:    control,
		health:     health,
		policy:     policy.clone(),
	}
}

func (c *grpcControlClient) Handshake(
	ctx context.Context,
	request HandshakeRequest,
) (HandshakeResponse, error) {
	if len(request.Nonce) != HandshakeNonceSize {
		return HandshakeResponse{}, fmt.Errorf(
			"handshake nonce has %d bytes, want %d",
			len(request.Nonce),
			HandshakeNonceSize,
		)
	}
	if err := request.Expected.validate(); err != nil {
		return HandshakeResponse{}, fmt.Errorf("invalid expected plugin manifest: %w", err)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return HandshakeResponse{}, ErrClosed
	}
	if c.handshakeAttempted {
		c.mu.Unlock()
		return HandshakeResponse{}, errors.New("plugin handshake may be attempted only once per connection")
	}
	c.handshakeAttempted = true
	c.mu.Unlock()

	rawResponse, err := c.control.Handshake(ctx, &pluginv1.HandshakeRequest{
		Protocol:             protocolRangeToProto(c.policy.Protocol),
		HostVersion:          c.policy.HostVersion,
		HostInstanceId:       c.policy.HostInstanceID,
		Compressions:         compressionsToProto(c.policy.Compressions),
		RecordFormats:        recordFormatsToProto(c.policy.RecordFormats),
		MaximumFrameBytes:    c.policy.MaximumFrameBytes,
		Nonce:                slices.Clone(request.Nonce),
		HostCallbackProtocol: protocolRangeToProto(c.policy.HostCallbackProtocol),
		Features:             slices.Clone(c.policy.Features),
	})
	if err != nil {
		return HandshakeResponse{}, err
	}
	response, err := c.validateHandshakeResponse(request.Expected, rawResponse)
	if err != nil {
		return HandshakeResponse{}, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return HandshakeResponse{}, ErrClosed
	}
	c.authenticated = true
	c.mu.Unlock()
	return response, nil
}

func (c *grpcControlClient) validateHandshakeResponse(
	expected Spec,
	response *pluginv1.HandshakeResponse,
) (HandshakeResponse, error) {
	if response == nil {
		return HandshakeResponse{}, errors.New("plugin returned a nil handshake response")
	}
	if len(response.NonceProof) != HandshakeNonceSize {
		return HandshakeResponse{}, fmt.Errorf(
			"plugin nonce proof has %d bytes, want %d",
			len(response.NonceProof),
			HandshakeNonceSize,
		)
	}
	descriptor, err := runtimeDescriptorFromProto(response.Plugin)
	if err != nil {
		return HandshakeResponse{}, err
	}
	if err := validateRuntimeDescriptor(expected, descriptor); err != nil {
		return HandshakeResponse{}, err
	}

	selectedProtocol, err := protocolVersionFromProto("selected protocol", response.Protocol)
	if err != nil {
		return HandshakeResponse{}, err
	}
	expectedProtocol, err := highestMutualProtocol(c.policy.Protocol, descriptor.Protocol)
	if err != nil {
		return HandshakeResponse{}, err
	}
	if selectedProtocol != expectedProtocol {
		return HandshakeResponse{}, fmt.Errorf(
			"%w: plugin selected %d.%d, highest mutual protocol is %d.%d",
			ErrProtocolMismatch,
			selectedProtocol.Major,
			selectedProtocol.Minor,
			expectedProtocol.Major,
			expectedProtocol.Minor,
		)
	}

	compression, err := compressionFromProto(response.Compression)
	if err != nil {
		return HandshakeResponse{}, err
	}
	if !slices.Contains(c.policy.Compressions, compression) {
		return HandshakeResponse{}, fmt.Errorf("plugin selected unoffered compression %s", compression)
	}

	recordFormats, err := recordFormatsFromProto("handshake response", response.RecordFormats)
	if err != nil {
		return HandshakeResponse{}, err
	}
	expectedFormats := intersectRuntimeRecordFormats(c.policy.RecordFormats, descriptor.Connectors)
	if !equalRecordFormatSets(recordFormats, expectedFormats) {
		return HandshakeResponse{}, fmt.Errorf(
			"plugin returned record formats %v, want host/runtime intersection %v",
			recordFormats,
			expectedFormats,
		)
	}

	if response.MaximumFrameBytes == 0 || response.MaximumFrameBytes > c.policy.MaximumFrameBytes {
		return HandshakeResponse{}, fmt.Errorf(
			"plugin selected maximum frame size %d outside host range [1,%d]",
			response.MaximumFrameBytes,
			c.policy.MaximumFrameBytes,
		)
	}
	callbackProtocol, err := protocolVersionFromProto(
		"selected host callback protocol",
		response.HostCallbackProtocol,
	)
	if err != nil {
		return HandshakeResponse{}, err
	}
	if !c.policy.HostCallbackProtocol.contains(callbackProtocol) {
		return HandshakeResponse{}, fmt.Errorf(
			"plugin selected unsupported host callback protocol %d.%d",
			callbackProtocol.Major,
			callbackProtocol.Minor,
		)
	}
	if err := validateStringSet("plugin feature", response.Features); err != nil {
		return HandshakeResponse{}, err
	}
	for _, feature := range response.Features {
		if !slices.Contains(c.policy.Features, feature) {
			return HandshakeResponse{}, fmt.Errorf("plugin selected unoffered feature %q", feature)
		}
	}

	return HandshakeResponse{
		Descriptor:           descriptor,
		NonceProof:           slices.Clone(response.NonceProof),
		Protocol:             selectedProtocol,
		Compression:          compression,
		RecordFormats:        slices.Clone(recordFormats),
		MaximumFrameBytes:    response.MaximumFrameBytes,
		HostCallbackProtocol: callbackProtocol,
		Features:             slices.Clone(response.Features),
	}, nil
}

func (c *grpcControlClient) Health(ctx context.Context) error {
	if err := c.requireAuthenticated(); err != nil {
		return err
	}
	response, err := c.health.Check(ctx, &healthpb.HealthCheckRequest{Service: c.policy.HealthService})
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("standard gRPC health returned a nil response")
	}
	if response.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("standard gRPC health status is %s, want SERVING", response.Status)
	}
	return nil
}

func (c *grpcControlClient) Drain(ctx context.Context) error {
	if err := c.requireAuthenticated(); err != nil {
		return err
	}
	requestContext, deadline := lifecycleRequestContext(ctx, "plugin.drain")
	_, err := c.control.Drain(ctx, &pluginv1.DrainRequest{
		Context:  requestContext,
		Deadline: deadline,
		Reason:   "PeerDB supervisor drain",
	})
	return err
}

func (c *grpcControlClient) Shutdown(ctx context.Context) error {
	if err := c.requireAuthenticated(); err != nil {
		return err
	}
	requestContext, _ := lifecycleRequestContext(ctx, "plugin.shutdown")
	_, err := c.control.Shutdown(ctx, &pluginv1.ShutdownRequest{
		Context: requestContext,
		Reason:  "PeerDB supervisor shutdown",
	})
	return err
}

func (c *grpcControlClient) requireAuthenticated() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if !c.authenticated {
		return errors.New("plugin connection is not authenticated")
	}
	return nil
}

func (c *grpcControlClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.authenticated = false
		c.mu.Unlock()
		if c.connection != nil {
			c.closeErr = c.connection.Close()
		}
	})
	return c.closeErr
}

func lifecycleRequestContext(
	ctx context.Context,
	operation string,
) (*pluginv1.RequestContext, *timestamppb.Timestamp) {
	var deadline *timestamppb.Timestamp
	if value, ok := ctx.Deadline(); ok {
		deadline = timestamppb.New(value)
	}
	return &pluginv1.RequestContext{
		Operation: operation,
		Deadline:  deadline,
	}, deadline
}

func runtimeDescriptorFromProto(plugin *pluginv1.PluginDescriptor) (RuntimeDescriptor, error) {
	if plugin == nil {
		return RuntimeDescriptor{}, errors.New("plugin handshake omitted its descriptor")
	}
	if plugin.Artifact == nil {
		return RuntimeDescriptor{}, errors.New("plugin descriptor omitted artifact identity")
	}
	identity, err := ParseIdentity(plugin.Id, plugin.Version, plugin.Artifact.Digest)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("invalid runtime plugin identity: %w", err)
	}
	protocol, err := protocolRangeFromProto("plugin descriptor", plugin.Protocol)
	if err != nil {
		return RuntimeDescriptor{}, err
	}
	connectors := make([]ConnectorCapabilities, len(plugin.Connectors))
	for index, rawConnector := range plugin.Connectors {
		connector, err := connectorCapabilitiesFromProto(rawConnector)
		if err != nil {
			return RuntimeDescriptor{}, fmt.Errorf("plugin connector %d: %w", index, err)
		}
		connectors[index] = connector
	}
	return RuntimeDescriptor{
		Identity:   identity,
		Platform:   plugin.Artifact.Platform,
		Protocol:   protocol,
		Connectors: connectors,
	}, nil
}

func connectorCapabilitiesFromProto(
	connector *pluginv1.ConnectorDescriptor,
) (ConnectorCapabilities, error) {
	if connector == nil {
		return ConnectorCapabilities{}, errors.New("descriptor is nil")
	}
	roles := make([]ConnectorRole, len(connector.Roles))
	for index, rawRole := range connector.Roles {
		role, err := connectorRoleFromProto(rawRole)
		if err != nil {
			return ConnectorCapabilities{}, err
		}
		roles[index] = role
	}
	capabilities := make([]Capability, len(connector.Capabilities))
	for index, rawCapability := range connector.Capabilities {
		if rawCapability == nil {
			return ConnectorCapabilities{}, fmt.Errorf("capability %d is nil", index)
		}
		capabilities[index] = Capability{
			Name:    rawCapability.Name,
			Version: rawCapability.Version,
		}
	}
	recordFormats, err := recordFormatsFromProto(
		"connector "+connector.Id,
		connector.RecordFormats,
	)
	if err != nil {
		return ConnectorCapabilities{}, err
	}
	result := ConnectorCapabilities{
		ConnectorID:   connector.Id,
		Roles:         roles,
		Capabilities:  capabilities,
		RecordFormats: recordFormats,
	}
	if err := result.validate("runtime"); err != nil {
		return ConnectorCapabilities{}, err
	}
	return result, nil
}

func protocolRangeFromProto(scope string, value *pluginv1.ProtocolRange) (ProtocolRange, error) {
	if value == nil {
		return ProtocolRange{}, fmt.Errorf("%s omitted protocol range", scope)
	}
	result := ProtocolRange{
		Major:        value.Major,
		MinimumMinor: value.MinimumMinor,
		MaximumMinor: value.MaximumMinor,
	}
	if err := result.validate(scope); err != nil {
		return ProtocolRange{}, err
	}
	return result, nil
}

func protocolVersionFromProto(scope string, value *pluginv1.ProtocolVersion) (ProtocolVersion, error) {
	if value == nil || value.Major == 0 {
		return ProtocolVersion{}, fmt.Errorf("%s is missing or invalid", scope)
	}
	return ProtocolVersion{Major: value.Major, Minor: value.Minor}, nil
}

func highestMutualProtocol(host, plugin ProtocolRange) (ProtocolVersion, error) {
	if host.Major != plugin.Major {
		return ProtocolVersion{}, fmt.Errorf(
			"%w: host major %d differs from plugin major %d",
			ErrProtocolMismatch,
			host.Major,
			plugin.Major,
		)
	}
	minimumMinor := max(host.MinimumMinor, plugin.MinimumMinor)
	maximumMinor := min(host.MaximumMinor, plugin.MaximumMinor)
	if minimumMinor > maximumMinor {
		return ProtocolVersion{}, fmt.Errorf(
			"%w: host minor range [%d,%d] does not overlap plugin range [%d,%d]",
			ErrProtocolMismatch,
			host.MinimumMinor,
			host.MaximumMinor,
			plugin.MinimumMinor,
			plugin.MaximumMinor,
		)
	}
	return ProtocolVersion{Major: host.Major, Minor: maximumMinor}, nil
}

func protocolRangeToProto(value ProtocolRange) *pluginv1.ProtocolRange {
	return &pluginv1.ProtocolRange{
		Major:        value.Major,
		MinimumMinor: value.MinimumMinor,
		MaximumMinor: value.MaximumMinor,
	}
}

func connectorRoleFromProto(value pluginv1.ConnectorRole) (ConnectorRole, error) {
	switch value {
	case pluginv1.ConnectorRole_CONNECTOR_ROLE_SOURCE:
		return ConnectorRoleSource, nil
	case pluginv1.ConnectorRole_CONNECTOR_ROLE_DESTINATION:
		return ConnectorRoleDestination, nil
	case pluginv1.ConnectorRole_CONNECTOR_ROLE_QUERY:
		return ConnectorRoleQuery, nil
	default:
		return 0, fmt.Errorf("unknown or unspecified connector role %d", value)
	}
}

func compressionFromProto(value pluginv1.Compression) (Compression, error) {
	switch value {
	case pluginv1.Compression_COMPRESSION_NONE:
		return CompressionNone, nil
	case pluginv1.Compression_COMPRESSION_GZIP:
		return CompressionGZIP, nil
	case pluginv1.Compression_COMPRESSION_ZSTD:
		return CompressionZSTD, nil
	default:
		return 0, fmt.Errorf("unknown or unspecified compression %d", value)
	}
}

func compressionToProto(value Compression) pluginv1.Compression {
	switch value {
	case CompressionNone:
		return pluginv1.Compression_COMPRESSION_NONE
	case CompressionGZIP:
		return pluginv1.Compression_COMPRESSION_GZIP
	case CompressionZSTD:
		return pluginv1.Compression_COMPRESSION_ZSTD
	default:
		return pluginv1.Compression_COMPRESSION_UNSPECIFIED
	}
}

func compressionsToProto(values []Compression) []pluginv1.Compression {
	result := make([]pluginv1.Compression, len(values))
	for index, value := range values {
		result[index] = compressionToProto(value)
	}
	return result
}

func recordFormatFromProto(value pluginv1.RecordFormat) (RecordFormat, error) {
	switch value {
	case pluginv1.RecordFormat_RECORD_FORMAT_QVALUE_PROTO_V1:
		return RecordFormatQValueProtoV1, nil
	case pluginv1.RecordFormat_RECORD_FORMAT_ARROW_IPC_V1:
		return RecordFormatArrowIPCV1, nil
	case pluginv1.RecordFormat_RECORD_FORMAT_PG_TEXT_V1:
		return RecordFormatPGTextV1, nil
	case pluginv1.RecordFormat_RECORD_FORMAT_PG_COPY_V1:
		return RecordFormatPGCopyV1, nil
	case pluginv1.RecordFormat_RECORD_FORMAT_OBJECT_REF_V1:
		return RecordFormatObjectRefV1, nil
	default:
		return 0, fmt.Errorf("unknown or unspecified record format %d", value)
	}
}

func recordFormatToProto(value RecordFormat) pluginv1.RecordFormat {
	switch value {
	case RecordFormatQValueProtoV1:
		return pluginv1.RecordFormat_RECORD_FORMAT_QVALUE_PROTO_V1
	case RecordFormatArrowIPCV1:
		return pluginv1.RecordFormat_RECORD_FORMAT_ARROW_IPC_V1
	case RecordFormatPGTextV1:
		return pluginv1.RecordFormat_RECORD_FORMAT_PG_TEXT_V1
	case RecordFormatPGCopyV1:
		return pluginv1.RecordFormat_RECORD_FORMAT_PG_COPY_V1
	case RecordFormatObjectRefV1:
		return pluginv1.RecordFormat_RECORD_FORMAT_OBJECT_REF_V1
	default:
		return pluginv1.RecordFormat_RECORD_FORMAT_UNSPECIFIED
	}
}

func recordFormatsFromProto(
	scope string,
	values []pluginv1.RecordFormat,
) ([]RecordFormat, error) {
	result := make([]RecordFormat, len(values))
	for index, value := range values {
		format, err := recordFormatFromProto(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", scope, err)
		}
		result[index] = format
	}
	if err := validateRecordFormatSet(scope, result); err != nil {
		return nil, err
	}
	return result, nil
}

func recordFormatsToProto(values []RecordFormat) []pluginv1.RecordFormat {
	result := make([]pluginv1.RecordFormat, len(values))
	for index, value := range values {
		result[index] = recordFormatToProto(value)
	}
	return result
}

func intersectRuntimeRecordFormats(
	host []RecordFormat,
	connectors []ConnectorCapabilities,
) []RecordFormat {
	runtimeFormats := make(map[RecordFormat]struct{})
	for _, connector := range connectors {
		for _, format := range connector.RecordFormats {
			runtimeFormats[format] = struct{}{}
		}
	}
	result := make([]RecordFormat, 0, len(host))
	for _, format := range host {
		if _, ok := runtimeFormats[format]; ok {
			result = append(result, format)
		}
	}
	return result
}

func equalRecordFormatSets(left, right []RecordFormat) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}
