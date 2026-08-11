package pluginruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	pluginv1 "github.com/PeerDB-io/peerdb/flow/generated/protos/peerdb/plugin/v1"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestGRPCControlClientNegotiatesAndMapsLifecycle(t *testing.T) {
	spec := grpcTestSpec()
	control := &fakeControlRPC{response: grpcTestResponse(spec)}
	health := &fakeHealthRPC{response: &healthpb.HealthCheckResponse{
		Status: healthpb.HealthCheckResponse_SERVING,
	}}
	closer := &fakeCloser{}
	client := newGRPCControlClient(closer, control, health, grpcTestPolicy())

	if err := client.Health(context.Background()); err == nil {
		t.Fatal("Health succeeded before Handshake")
	}
	response, err := client.Handshake(context.Background(), HandshakeRequest{
		Nonce:    make([]byte, HandshakeNonceSize),
		Expected: spec,
	})
	if err != nil {
		t.Fatalf("Handshake returned an error: %v", err)
	}
	if response.Protocol != (ProtocolVersion{Major: 1, Minor: 4}) ||
		response.Descriptor.Identity != spec.Identity ||
		response.Descriptor.Platform != spec.Platform {
		t.Fatalf("unexpected negotiated response: %+v", response)
	}
	if control.handshakeRequest == nil ||
		control.handshakeRequest.HostInstanceId != "worker-1" ||
		control.handshakeRequest.MaximumFrameBytes != 1<<20 {
		t.Fatalf("handshake request did not carry host policy: %+v", control.handshakeRequest)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health returned an error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Drain(ctx); err != nil {
		t.Fatalf("Drain returned an error: %v", err)
	}
	if control.drainRequest == nil || control.drainRequest.Context == nil ||
		control.drainRequest.Context.Operation != "plugin.drain" ||
		control.drainRequest.Deadline == nil {
		t.Fatalf("Drain request omitted lifecycle context: %+v", control.drainRequest)
	}
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned an error: %v", err)
	}
	if control.shutdownRequest == nil || control.shutdownRequest.Context == nil ||
		control.shutdownRequest.Context.Operation != "plugin.shutdown" {
		t.Fatalf("Shutdown request omitted lifecycle context: %+v", control.shutdownRequest)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if err := client.Close(); err != nil || closer.calls != 1 {
		t.Fatalf("Close idempotency: error=%v calls=%d", err, closer.calls)
	}
}

func TestGRPCControlClientRejectsInvalidNegotiation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pluginv1.HandshakeResponse)
		want   error
	}{
		{
			name: "not highest mutual protocol",
			mutate: func(response *pluginv1.HandshakeResponse) {
				response.Protocol.Minor = 3
			},
			want: ErrProtocolMismatch,
		},
		{
			name: "platform mismatch",
			mutate: func(response *pluginv1.HandshakeResponse) {
				response.Plugin.Artifact.Platform = "other/architecture"
			},
			want: ErrPlatformMismatch,
		},
		{
			name: "role escalation",
			mutate: func(response *pluginv1.HandshakeResponse) {
				response.Plugin.Connectors[0].Roles = append(
					response.Plugin.Connectors[0].Roles,
					pluginv1.ConnectorRole_CONNECTOR_ROLE_DESTINATION,
				)
			},
			want: ErrRoleEscalation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := grpcTestSpec()
			rawResponse := grpcTestResponse(spec)
			test.mutate(rawResponse)
			client := newGRPCControlClient(
				&fakeCloser{},
				&fakeControlRPC{response: rawResponse},
				&fakeHealthRPC{},
				grpcTestPolicy(),
			)
			_, err := client.Handshake(context.Background(), HandshakeRequest{
				Nonce:    make([]byte, HandshakeNonceSize),
				Expected: spec,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Handshake error = %v, want errors.Is(%v)", err, test.want)
			}
		})
	}
}

func TestBackoffUsesBoundedJitter(t *testing.T) {
	supervisor := &Supervisor{options: Options{
		InitialBackoff: 8 * time.Second,
		MaximumBackoff: 10 * time.Second,
		Random:         &deterministicReader{},
	}}
	first := supervisor.backoff(1)
	if first < 4*time.Second || first > 8*time.Second {
		t.Fatalf("first backoff = %s, want [4s,8s]", first)
	}
	capped := supervisor.backoff(8)
	if capped < 5*time.Second || capped > 10*time.Second {
		t.Fatalf("capped backoff = %s, want [5s,10s]", capped)
	}
}

func grpcTestPolicy() HandshakePolicy {
	return HandshakePolicy{
		Protocol:             ProtocolRange{Major: 1, MinimumMinor: 2, MaximumMinor: 5},
		HostVersion:          "1.0.0",
		HostInstanceID:       "worker-1",
		Compressions:         []Compression{CompressionZSTD, CompressionNone},
		RecordFormats:        []RecordFormat{RecordFormatArrowIPCV1, RecordFormatQValueProtoV1},
		MaximumFrameBytes:    1 << 20,
		HostCallbackProtocol: ProtocolRange{Major: 1, MinimumMinor: 0, MaximumMinor: 2},
		Features:             []string{"trace-context"},
	}
}

func grpcTestSpec() Spec {
	identity := testIdentity(21)
	return Spec{
		Identity:   identity,
		Executable: filepath.Join(os.TempDir(), "plugins", "test"),
		Platform:   "test/architecture",
		Protocol:   ProtocolRange{Major: 1, MinimumMinor: 0, MaximumMinor: 4},
		ManifestConnectors: []ConnectorCapabilities{
			{
				ConnectorID:   "postgresql",
				Roles:         []ConnectorRole{ConnectorRoleSource},
				Capabilities:  []Capability{{Name: "cdc.source", Version: 1}},
				RecordFormats: []RecordFormat{RecordFormatQValueProtoV1, RecordFormatArrowIPCV1},
			},
		},
	}
}

func grpcTestResponse(spec Spec) *pluginv1.HandshakeResponse {
	connector := spec.ManifestConnectors[0]
	return &pluginv1.HandshakeResponse{
		Protocol: &pluginv1.ProtocolVersion{Major: 1, Minor: 4},
		Plugin: &pluginv1.PluginDescriptor{
			Id:      spec.Identity.ID,
			Version: spec.Identity.Version,
			Protocol: &pluginv1.ProtocolRange{
				Major:        1,
				MinimumMinor: 1,
				MaximumMinor: 4,
			},
			Artifact: &pluginv1.ArtifactIdentity{
				Digest:   spec.Identity.Digest(),
				Platform: spec.Platform,
			},
			Connectors: []*pluginv1.ConnectorDescriptor{
				{
					Id: connector.ConnectorID,
					Roles: []pluginv1.ConnectorRole{
						pluginv1.ConnectorRole_CONNECTOR_ROLE_SOURCE,
					},
					Capabilities: []*pluginv1.Capability{
						{Name: "cdc.source", Version: 1},
					},
					RecordFormats: []pluginv1.RecordFormat{
						pluginv1.RecordFormat_RECORD_FORMAT_QVALUE_PROTO_V1,
						pluginv1.RecordFormat_RECORD_FORMAT_ARROW_IPC_V1,
					},
				},
			},
		},
		Compression: pluginv1.Compression_COMPRESSION_ZSTD,
		RecordFormats: slices.Clone([]pluginv1.RecordFormat{
			pluginv1.RecordFormat_RECORD_FORMAT_QVALUE_PROTO_V1,
			pluginv1.RecordFormat_RECORD_FORMAT_ARROW_IPC_V1,
		}),
		MaximumFrameBytes:    512 << 10,
		NonceProof:           make([]byte, HandshakeNonceSize),
		HostCallbackProtocol: &pluginv1.ProtocolVersion{Major: 1, Minor: 1},
		Features:             []string{"trace-context"},
	}
}

type fakeControlRPC struct {
	response         *pluginv1.HandshakeResponse
	handshakeRequest *pluginv1.HandshakeRequest
	drainRequest     *pluginv1.DrainRequest
	shutdownRequest  *pluginv1.ShutdownRequest
}

func (c *fakeControlRPC) Handshake(
	_ context.Context,
	request *pluginv1.HandshakeRequest,
	_ ...grpc.CallOption,
) (*pluginv1.HandshakeResponse, error) {
	c.handshakeRequest = request
	return c.response, nil
}

func (c *fakeControlRPC) Drain(
	_ context.Context,
	request *pluginv1.DrainRequest,
	_ ...grpc.CallOption,
) (*pluginv1.DrainResponse, error) {
	c.drainRequest = request
	return &pluginv1.DrainResponse{}, nil
}

func (c *fakeControlRPC) Shutdown(
	_ context.Context,
	request *pluginv1.ShutdownRequest,
	_ ...grpc.CallOption,
) (*pluginv1.ShutdownResponse, error) {
	c.shutdownRequest = request
	return &pluginv1.ShutdownResponse{}, nil
}

type fakeHealthRPC struct {
	response *healthpb.HealthCheckResponse
}

func (h *fakeHealthRPC) Check(
	context.Context,
	*healthpb.HealthCheckRequest,
	...grpc.CallOption,
) (*healthpb.HealthCheckResponse, error) {
	return h.response, nil
}

type fakeCloser struct {
	calls int
}

func (c *fakeCloser) Close() error {
	c.calls++
	return nil
}
