//go:build with_quic

package singbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	quicHysteria "github.com/sagernet/sing-quic/hysteria"
	quicHY2 "github.com/sagernet/sing-quic/hysteria2"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// TestHysteria2QUICNativeAudit sends real authenticated QUIC TCP streams and
// fragmented UDP datagrams through SingBox.Start, the native HY2 inbound,
// its router, the tracker and an in-memory audit sink. No external service,
// certificate file, production credential or additional dependency is used.
func TestHysteria2QUICNativeAudit(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		version  int
	}{
		{"hysteria", 2}, {"hysteria2", 0}, {"hy2", 0},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
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
			capture := &hysteria2AuditCapture{}
			node := &model.NodeSpec{
				NodeID: 7, Protocol: tc.protocol, Version: tc.version, ServerPort: port,
				ServerName: "hy2.test", Obfs: "salamander", ObfsPassword: "test-only-obfs-password",
			}
			server := New(config.KernelConfig{
				LogLevel: "none", AuditSink: capture, IdleTimeout: -1,
				// Only the test permits loopback echo destinations; production
				// private-address routing restrictions remain unchanged.
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct", "udp_timeout": "30s"}},
			})
			userA := model.UserSpec{ID: 42, UUID: "00000000-0000-4000-8000-000000000042"}
			userB := model.UserSpec{ID: 43, UUID: "00000000-0000-4000-8000-000000000043"}
			userC := model.UserSpec{ID: 44, UUID: "00000000-0000-4000-8000-000000000044"}
			if err := server.Start(node, []model.UserSpec{userA, userB}, cert); err != nil {
				t.Fatalf("start native HY2 inbound: %v", err)
			}
			t.Cleanup(server.Stop)
			manager := service.FromContext[adapter.InboundManager](server.ctx)
			inbound, ok := manager.Get("hysteria2-in")
			if !ok || inbound.Type() != "hysteria2" {
				t.Fatal("panel alias did not start a native HY2 inbound")
			}
			tracker := server.connTracker
			if tracker.auditProtocol != "hysteria2" {
				t.Fatal("kernel did not normalize its audit protocol")
			}
			clientA, sourceA := hysteria2LocalClient(t, server.ctx, port, userA.UUID, node.ObfsPassword, cert)
			clientB, sourceB := hysteria2LocalClient(t, server.ctx, port, userB.UUID, node.ObfsPassword, cert)
			// ListenPacket authenticates HTTP/3 over QUIC but sends no target
			// datagrams yet. Transport handshakes must never become audit events.
			for _, client := range []*quicHY2.Client{clientA, clientB} {
				idle, err := client.ListenPacket(server.ctx)
				if err != nil {
					t.Fatalf("authenticate idle HY2 transport: %v", err)
				}
				t.Cleanup(func() { _ = idle.Close() })
			}
			hysteria2AssertEvents(t, capture, nil, tcpTarget, udpTarget)
			if tc.protocol == "hysteria" {
				// Exercise the pinned client's real keepalive timer once, not
				// a synthetic RoutedConnection/PacketConnection callback.
				time.Sleep(quicHysteria.DefaultKeepAlivePeriod + time.Second)
				hysteria2AssertEvents(t, capture, nil, tcpTarget, udpTarget)
			}
			if traffic, alive, count := tracker.GetUserTraffic(); len(traffic) != 0 || len(alive) != 0 || count != 0 {
				t.Fatal("idle QUIC handshakes/keepalives were counted as user target traffic")
			}
			oldA := hysteria2OpenTCP(t, server.ctx, clientA, tcpTarget)
			oldB := hysteria2OpenTCP(t, server.ctx, clientB, tcpTarget)
			oldUDP := hysteria2OpenUDP(t, server.ctx, clientB, udpTarget)
			// Both copy directions update the UDP idle timer. Exercise the
			// packet-read-waiter fast path as well as downstream writes.
			for i := 0; i < 16; i++ {
				hysteria2UDPEcho(t, oldUDP, udpTarget)
			}
			want := []hysteria2WantEvent{{42, userA.UUID, "tcp"}, {43, userB.UUID, "tcp"}, {43, userB.UUID, "udp"}}
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			if sourceA.sourceIP() != "127.0.0.1" || sourceB.sourceIP() != "127.0.0.1" {
				t.Fatal("QUIC client did not bind the expected loopback source")
			}

			// The fork stores authenticated users as indices. Removing A and
			// prepending C must not turn B's already authenticated session into C.
			if added, removed, err := server.UpdateUsers([]model.UserSpec{userC, userB}); err != nil || added != 1 || removed != 1 {
				t.Fatalf("hot update = (%d, %d, %v), want (1, 1, nil)", added, removed, err)
			}
			hysteria2AssertSameInbound(t, manager, inbound, server, tracker)
			hysteria2TCPEcho(t, oldA)
			hysteria2TCPEcho(t, oldB)
			hysteria2UDPEcho(t, oldUDP, udpTarget)
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			hysteria2OpenTCP(t, server.ctx, clientB, tcpTarget)
			hysteria2OpenUDP(t, server.ctx, clientB, udpTarget)
			want = append(want, hysteria2WantEvent{43, userB.UUID, "tcp"}, hysteria2WantEvent{43, userB.UUID, "udp"})
			clientC, _ := hysteria2LocalClient(t, server.ctx, port, userC.UUID, node.ObfsPassword, cert)
			hysteria2OpenTCP(t, server.ctx, clientC, tcpTarget)
			hysteria2OpenUDP(t, server.ctx, clientC, udpTarget)
			want = append(want, hysteria2WantEvent{44, userC.UUID, "tcp"}, hysteria2WantEvent{44, userC.UUID, "udp"})
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			retired, err := clientA.DialConn(server.ctx, tcpTarget)
			if err != nil {
				t.Fatalf("open stream on existing QUIC session: %v", err)
			}
			defer retired.Close()
			_ = retired.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := retired.Write([]byte("retired-session-payload")); err == nil {
				_, err = retired.Read(make([]byte, 32))
				if err == nil {
					t.Fatal("removed HY2 identity opened a newly routed TCP stream")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("removed identity timed out instead of being rejected")
				}
			}
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			retiredUDP, err := clientA.ListenPacket(server.ctx)
			if err != nil {
				t.Fatalf("open UDP session on existing QUIC transport: %v", err)
			}
			t.Cleanup(func() { _ = retiredUDP.Close() })
			if err := retiredUDP.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := retiredUDP.WriteTo([]byte("retired-session-payload"), udpTarget.UDPAddr()); err != nil {
				t.Fatal(err)
			}
			if _, _, err := retiredUDP.ReadFrom(make([]byte, 64)); err == nil {
				t.Fatal("removed HY2 identity opened a newly routed UDP session")
			}
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			freshRetired, _ := hysteria2LocalClient(t, server.ctx, port, userA.UUID, node.ObfsPassword, cert)
			if rejected, err := freshRetired.ListenPacket(server.ctx); err == nil {
				_ = rejected.Close()
				t.Fatal("removed HY2 credential authenticated a new QUIC transport")
			}
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)

			// User-only Reload must preserve the listener and tracker as well.
			if err := server.Reload(node, []model.UserSpec{userB, userC}, cert); err != nil {
				t.Fatalf("user-only reload: %v", err)
			}
			hysteria2AssertSameInbound(t, manager, inbound, server, tracker)
			if _, _, err := server.UpdateUsers([]model.UserSpec{userC, userB}); err != nil {
				t.Fatalf("reorder existing users: %v", err)
			}
			hysteria2OpenTCP(t, server.ctx, clientB, tcpTarget)
			hysteria2OpenUDP(t, server.ctx, clientB, udpTarget)
			want = append(want, hysteria2WantEvent{43, userB.UUID, "tcp"}, hysteria2WantEvent{43, userB.UUID, "udp"})
			hysteria2AssertEvents(t, capture, want, tcpTarget, udpTarget)
			traffic, _, _ := tracker.GetUserTraffic()
			if traffic[42][0] <= 0 || traffic[42][1] <= 0 || traffic[43][0] <= 0 || traffic[43][1] <= 0 || traffic[44][0] <= 0 || traffic[44][1] <= 0 {
				t.Fatal("native HY2 traffic was not counted for the original accounts")
			}
		})
	}
}

type hysteria2WantEvent struct {
	uid     int
	uuid    string
	network string
}

func hysteria2AssertEvents(t *testing.T, capture *hysteria2AuditCapture, want []hysteria2WantEvent, tcpTarget, udpTarget singM.Socksaddr) {
	t.Helper()
	events := capture.snapshot()
	if len(events) != len(want) {
		t.Fatalf("native HY2 audit events = %d, want %d (missing or duplicate events)", len(events), len(want))
	}
	for i, event := range events {
		target := tcpTarget.String()
		if want[i].network == "udp" {
			target = udpTarget.String()
		}
		if event.UserID != want[i].uid || event.UUID != want[i].uuid || event.NodeID != 7 || event.Core != "singbox" || event.Protocol != "hysteria2" || event.Network != want[i].network || event.SourceIP != "127.0.0.1" || event.Target != target {
			t.Fatalf("incorrect native HY2 audit event %d: %+v", i, event)
		}
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"password", "PRIVATE KEY", "CERTIFICATE", "hy2-test-payload", "retired-session-payload"} {
		if bytes.Contains(encoded, []byte(sensitive)) {
			t.Fatal("audit contains a credential, certificate or traffic payload")
		}
	}
}

func hysteria2AssertSameInbound(t *testing.T, manager adapter.InboundManager, before adapter.Inbound, server *SingBox, tracker *ConnTracker) {
	t.Helper()
	after, ok := manager.Get("hysteria2-in")
	if !ok || after != before || server.connTracker != tracker {
		t.Fatal("user hot update replaced the listener or reinstalled the tracker")
	}
}

func hysteria2EphemeralCert(t *testing.T) kernel.TLSCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"hy2.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return kernel.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

type hysteria2SourceDialer struct {
	N.DefaultDialer
	mu     sync.Mutex
	source net.Addr
}

func (d *hysteria2SourceDialer) DialContext(ctx context.Context, network string, destination singM.Socksaddr) (net.Conn, error) {
	conn, err := d.DefaultDialer.DialContext(ctx, network, destination)
	if err == nil && network == "udp" {
		d.mu.Lock()
		d.source = conn.LocalAddr()
		d.mu.Unlock()
	}
	return conn, err
}

func (d *hysteria2SourceDialer) sourceIP() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return singM.SocksaddrFromNet(d.source).Unwrap().Addr.String()
}

func hysteria2LocalClient(t *testing.T, ctx context.Context, port int, password, obfsPassword string, cert kernel.TLSCert) (*quicHY2.Client, *hysteria2SourceDialer) {
	t.Helper()
	logger := singLog.NewNOPFactory().NewLogger("hy2-test")
	tls, err := boxTLS.NewClient(ctx, logger, "127.0.0.1", option.OutboundTLSOptions{
		Enabled: true, ServerName: "hy2.test", Certificate: []string{string(cert.CertPEM)},
	})
	if err != nil {
		t.Fatalf("in-memory client TLS: %v", err)
	}
	dialer := &hysteria2SourceDialer{}
	client, err := quicHY2.NewClient(quicHY2.ClientOptions{
		Context:            ctx,
		Dialer:             dialer,
		Logger:             logger,
		ServerAddress:      singM.ParseSocksaddrHostPort("127.0.0.1", uint16(port)),
		Password:           password,
		SalamanderPassword: obfsPassword,
		TLSConfig:          tls,
	})
	if err != nil {
		t.Fatalf("create HY2 client: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
	return client, dialer
}

func hysteria2OpenTCP(t *testing.T, ctx context.Context, client *quicHY2.Client, target singM.Socksaddr) net.Conn {
	t.Helper()
	conn, err := client.DialConn(ctx, target)
	if err != nil {
		t.Fatalf("HY2 TCP dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hysteria2TCPEcho(t, conn)
	return conn
}

func hysteria2TCPEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("hy2-test-payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("HY2 TCP write: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("HY2 TCP read: %v", err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("HY2 TCP payload mismatch")
	}
}

func hysteria2OpenUDP(t *testing.T, ctx context.Context, client *quicHY2.Client, target singM.Socksaddr) net.PacketConn {
	t.Helper()
	conn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("HY2 UDP dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hysteria2UDPEcho(t, conn, target)
	return conn
}

func hysteria2UDPEcho(t *testing.T, conn net.PacketConn, target singM.Socksaddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat("hy2-test-payload", 256))
	if n, err := conn.WriteTo(payload, target.UDPAddr()); err != nil || n != len(payload) {
		t.Fatalf("HY2 UDP write = (%d, %v)", n, err)
	}
	response := make([]byte, len(payload)+1)
	n, source, err := conn.ReadFrom(response)
	if err != nil {
		t.Fatalf("HY2 UDP read: %v", err)
	}
	if !bytes.Equal(response[:n], payload) || source.String() != target.String() {
		t.Fatal("HY2 UDP payload or response address mismatch")
	}
}

func hysteria2LocalEchoes(t *testing.T) (singM.Socksaddr, singM.Socksaddr) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []net.Conn
	var copies sync.WaitGroup
	tcpDone, udpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			copies.Add(1)
			go func(conn net.Conn) {
				defer copies.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 65535)
		for {
			n, source, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(buffer[:n], source); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
		<-tcpDone
		<-udpDone
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		copies.Wait()
	})
	return singM.SocksaddrFromNet(tcp.Addr()).Unwrap(), singM.SocksaddrFromNet(udp.LocalAddr()).Unwrap()
}
