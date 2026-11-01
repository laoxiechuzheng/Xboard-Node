//go:build with_quic

package singbox

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	quicHY2 "github.com/sagernet/sing-quic/hysteria2"
	quicTUIC "github.com/sagernet/sing-quic/tuic"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// quicUserClient is the part of the HY2 and TUIC clients the test uses.
type quicUserClient interface {
	DialConn(ctx context.Context, destination singM.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

// TestQUICUserUpdatesKeepRemainingUsersConnections drives real HY2 and TUIC
// clients through SingBox. HY2 and TUIC keep users in stable slots and a
// retired slot keeps the removed UUID as its name, so every kind of user
// update is exercised against a user that stays: only a removed user, or the
// old UUID of a reset user, may lose its live streams.
func TestQUICUserUpdatesKeepRemainingUsersConnections(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			cert := hysteria2EphemeralCert(t)
			tcpTarget, udpTarget := hysteria2LocalEchoes(t)
			reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.LocalAddr().(*net.UDPAddr).Port
			if err := reservation.Close(); err != nil {
				t.Fatal(err)
			}
			node := &model.NodeSpec{NodeID: 7, Protocol: protocol, ServerPort: port, ServerName: "hy2.test"}
			server := New(config.KernelConfig{
				LogLevel: "none", IdleTimeout: -1,
				// Only the test permits loopback echo destinations.
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct", "udp_timeout": "30s"}},
			})
			removed := model.UserSpec{ID: 51, UUID: "00000000-0000-4000-8000-000000000051"}
			kept := model.UserSpec{ID: 52, UUID: "00000000-0000-4000-8000-000000000052"}
			reset := model.UserSpec{ID: 53, UUID: "00000000-0000-4000-8000-000000000053"}
			added := model.UserSpec{ID: 54, UUID: "00000000-0000-4000-8000-000000000054"}
			if err := server.Start(node, []model.UserSpec{removed, kept, reset}, cert); err != nil {
				t.Fatalf("start native %s inbound: %v", protocol, err)
			}
			t.Cleanup(server.Stop)

			keptClient := quicTestUserClient(t, server.ctx, protocol, port, kept.UUID, cert)
			keptTCP := hysteria2OpenTCP(t, server.ctx, keptClient, tcpTarget)
			keptUDP := hysteria2OpenUDP(t, server.ctx, keptClient, udpTarget)
			removedTCP := hysteria2OpenTCP(t, server.ctx, quicTestUserClient(t, server.ctx, protocol, port, removed.UUID, cert), tcpTarget)
			resetTCP := hysteria2OpenTCP(t, server.ctx, quicTestUserClient(t, server.ctx, protocol, port, reset.UUID, cert), tcpTarget)
			stillServed := func(step string) {
				t.Helper()
				t.Logf("kept user's live TCP and UDP after %s", step)
				hysteria2TCPEcho(t, keptTCP)
				hysteria2UDPEcho(t, keptUDP, udpTarget)
			}

			// Adding a user fills a new slot.
			if n, err := server.AddUsers([]model.UserSpec{added}); err != nil || n != 1 {
				t.Fatalf("AddUsers = (%d, %v), want (1, nil)", n, err)
			}
			stillServed("adding a user")
			hysteria2TCPEcho(t, removedTCP)
			hysteria2TCPEcho(t, resetTCP)

			// Limits only: the tracker gets a new map, the inbound is untouched.
			limited := kept
			limited.SpeedLimit, limited.DeviceLimit = 100, 3
			if a, r, err := server.UpdateUsers([]model.UserSpec{removed, limited, reset, added}); err != nil || a != 0 || r != 0 {
				t.Fatalf("limits-only update = (%d, %d, %v), want (0, 0, nil)", a, r, err)
			}
			stillServed("a limits-only update")

			// Removing another user retires its slot.
			if n, err := server.RemoveUsers([]model.UserSpec{removed}); err != nil || n != 1 {
				t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
			}
			hysteria2AssertCut(t, removedTCP)
			stillServed("removing another user")
			hysteria2TCPEcho(t, resetTCP)

			// Reordering moves no user to another slot.
			if a, r, err := server.UpdateUsers([]model.UserSpec{added, reset, limited}); err != nil || a != 0 || r != 0 {
				t.Fatalf("reorder = (%d, %d, %v), want (0, 0, nil)", a, r, err)
			}
			stillServed("reordering users")

			// A UUID reset of another user: only that user's old UUID is cut.
			renewed := model.UserSpec{ID: reset.ID, UUID: "00000000-0000-4000-8000-0000000000c3"}
			if a, r, err := server.UpdateUsers([]model.UserSpec{added, renewed, limited}); err != nil || a != 1 || r != 1 {
				t.Fatalf("UUID reset = (%d, %d, %v), want (1, 1, nil)", a, r, err)
			}
			hysteria2AssertCut(t, resetTCP)
			stillServed("another user's UUID reset")
			hysteria2TCPEcho(t, hysteria2OpenTCP(t, server.ctx, quicTestUserClient(t, server.ctx, protocol, port, renewed.UUID, cert), tcpTarget))

			// A user-only Reload keeps the listener, the tracker and the slots.
			if err := server.Reload(node, []model.UserSpec{limited, renewed, added}, cert); err != nil {
				t.Fatalf("user-only reload: %v", err)
			}
			stillServed("a user-only reload")
			// New streams on the kept user's existing QUIC session still work.
			hysteria2OpenTCP(t, server.ctx, keptClient, tcpTarget)
		})
	}
}

// quicTestUserClient returns an HY2 or TUIC client that verifies the test
// certificate and authenticates as uuid (the panel's password for both).
func quicTestUserClient(t *testing.T, ctx context.Context, protocol string, port int, uuid string, cert kernel.TLSCert) quicUserClient {
	t.Helper()
	logger := singLog.NewNOPFactory().NewLogger("quic-user-test")
	tlsConfig, err := boxTLS.NewClient(ctx, logger, "127.0.0.1", option.OutboundTLSOptions{
		Enabled: true, ServerName: "hy2.test", ALPN: []string{"h3"}, Certificate: []string{string(cert.CertPEM)},
	})
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	serverAddress := singM.ParseSocksaddrHostPort("127.0.0.1", uint16(port))
	if protocol == "hysteria2" {
		client, err := quicHY2.NewClient(quicHY2.ClientOptions{
			Context: ctx, Dialer: N.SystemDialer, Logger: logger, ServerAddress: serverAddress,
			Password: uuid, TLSConfig: tlsConfig,
		})
		if err != nil {
			t.Fatalf("create HY2 client: %v", err)
		}
		t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
		return client
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(raw) != 16 {
		t.Fatal("invalid test UUID")
	}
	var id [16]byte
	copy(id[:], raw)
	client, err := quicTUIC.NewClient(quicTUIC.ClientOptions{
		Context: ctx, Dialer: N.SystemDialer, ServerAddress: serverAddress,
		TLSConfig: tlsConfig, UUID: id, Password: uuid,
	})
	if err != nil {
		t.Fatalf("create TUIC client: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
	return client
}
