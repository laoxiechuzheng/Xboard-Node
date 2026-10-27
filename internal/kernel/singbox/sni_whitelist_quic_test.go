//go:build with_quic

package singbox

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	quicHY2 "github.com/sagernet/sing-quic/hysteria2"
	quicTUIC "github.com/sagernet/sing-quic/tuic"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestQUICSNIWhitelist drives real HY2 and TUIC clients that skip certificate
// verification (skip-cert-verify) through SingBox.Start. Only whitelisted SNI
// values may complete the QUIC handshake; rejected attempts must never be
// authenticated, routed, counted for billing or audited.
func TestQUICSNIWhitelist(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			cert := hysteria2EphemeralCert(t)
			tcpTarget, _ := hysteria2LocalEchoes(t)
			reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.LocalAddr().(*net.UDPAddr).Port
			if err := reservation.Close(); err != nil {
				t.Fatal(err)
			}
			capture := &hysteria2AuditCapture{}
			node := &model.NodeSpec{NodeID: 7, Protocol: protocol, ServerPort: port, ServerName: "hy2.test"}
			if protocol == "hysteria2" {
				node.Obfs, node.ObfsPassword = "salamander", "test-only-obfs-password"
			}
			server := New(config.KernelConfig{
				LogLevel: "none", AuditSink: capture, IdleTimeout: -1,
				SNIWhitelist: config.ServerNameList{"iosapps.itunes.apple.com", "www.apple.com"},
				// Only the test permits loopback echo destinations.
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			user := model.UserSpec{ID: 42, UUID: "00000000-0000-4000-8000-000000000042"}
			if err := server.Start(node, []model.UserSpec{user}, cert); err != nil {
				t.Fatalf("start native %s inbound: %v", protocol, err)
			}
			t.Cleanup(server.Stop)

			// "" is a client connecting by IP without sni; "hy2.test" is the
			// certificate's own name, which is not whitelisted either.
			for _, serverName := range []string{"apple.com", "evil.example.com", "hy2.test", ""} {
				if conn, err := sniWhitelistDial(t, server.ctx, protocol, port, serverName, user.UUID, node.ObfsPassword, tcpTarget); err == nil {
					_ = conn.Close()
					t.Fatalf("SNI %q completed the %s handshake", serverName, protocol)
				}
			}
			if traffic, alive, count := server.connTracker.GetUserTraffic(); len(traffic) != 0 || len(alive) != 0 || count != 0 {
				t.Fatal("rejected handshakes were counted as user traffic")
			}
			if events := capture.snapshot(); len(events) != 0 {
				t.Fatal("rejected handshakes were audited")
			}

			for _, serverName := range []string{"iosapps.itunes.apple.com", "WWW.Apple.com"} {
				conn, err := sniWhitelistDial(t, server.ctx, protocol, port, serverName, user.UUID, node.ObfsPassword, tcpTarget)
				if err != nil {
					t.Fatalf("whitelisted SNI %q was rejected: %v", serverName, err)
				}
				hysteria2TCPEcho(t, conn)
			}
			traffic, _, _ := server.connTracker.GetUserTraffic()
			if traffic[42][0] <= 0 || traffic[42][1] <= 0 {
				t.Fatal("whitelisted traffic was not counted for the user")
			}
			if events := capture.snapshot(); len(events) != 2 || events[0].UserID != 42 || events[1].UserID != 42 {
				t.Fatalf("audit events = %+v, want two events of user 42", events)
			}
		})
	}
}

// sniWhitelistDial opens a proxied TCP stream with certificate verification
// disabled, so only the server-side SNI check can refuse it.
func sniWhitelistDial(t *testing.T, ctx context.Context, protocol string, port int, serverName, password, obfsPassword string, target singM.Socksaddr) (net.Conn, error) {
	t.Helper()
	logger := singLog.NewNOPFactory().NewLogger("sni-test")
	tlsConfig, err := boxTLS.NewClient(ctx, logger, "127.0.0.1", option.OutboundTLSOptions{
		Enabled: true, ServerName: serverName, Insecure: true, ALPN: []string{"h3"},
	})
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cancel)
	serverAddress := singM.ParseSocksaddrHostPort("127.0.0.1", uint16(port))
	switch protocol {
	case "hysteria2":
		client, err := quicHY2.NewClient(quicHY2.ClientOptions{
			Context: ctx, Dialer: N.SystemDialer, Logger: logger, ServerAddress: serverAddress,
			Password: password, SalamanderPassword: obfsPassword, TLSConfig: tlsConfig,
		})
		if err != nil {
			t.Fatalf("create HY2 client: %v", err)
		}
		t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
		return client.DialConn(dialCtx, target)
	default:
		raw, err := hex.DecodeString(strings.ReplaceAll(password, "-", ""))
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid test UUID")
		}
		var uuid [16]byte
		copy(uuid[:], raw)
		client, err := quicTUIC.NewClient(quicTUIC.ClientOptions{
			Context: ctx, Dialer: N.SystemDialer, ServerAddress: serverAddress,
			TLSConfig: tlsConfig, UUID: uuid, Password: password,
		})
		if err != nil {
			t.Fatalf("create TUIC client: %v", err)
		}
		t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
		return client.DialConn(dialCtx, target)
	}
}
