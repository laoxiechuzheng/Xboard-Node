package singbox

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	coreTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	singM "github.com/sagernet/sing/common/metadata"

	anytls "github.com/anytls/sing-anytls"
)

// TestAnyTLSSNIWhitelist drives a real AnyTLS client that skips certificate
// verification through SingBox.Start. Only whitelisted SNI values may finish
// the TLS handshake; rejected attempts must never be authenticated, routed,
// counted for billing or audited.
func TestAnyTLSSNIWhitelist(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	key, certificate, err := coreTLS.GenerateCertificate(nil, nil, time.Now, "anytls.test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	capture := &hysteria2AuditCapture{}
	instance := New(config.KernelConfig{
		Type: "singbox", LogLevel: "none", AuditSink: capture,
		SNIWhitelist: config.ServerNameList{"iosapps.itunes.apple.com", "www.apple.com"},
		// Only the test permits loopback echo destinations.
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	user := model.UserSpec{ID: 42, UUID: "00000000-0000-4000-8000-000000000042"}
	err = instance.Start(&model.NodeSpec{Protocol: "anytls", NodeID: 9, ServerPort: port, TLS: 1}, []model.UserSpec{user}, kernel.TLSCert{CertPEM: certificate, KeyPEM: key})
	if err != nil {
		t.Fatalf("start AnyTLS kernel: %v", err)
	}
	t.Cleanup(instance.Stop)

	// "" is a client connecting by IP without sni; "anytls.test" is the
	// certificate's own name, which is not whitelisted either.
	for _, serverName := range []string{"apple.com", "evil.example.com", "anytls.test", ""} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if conn, err := anyTLSWhitelistDial(ctx, port, serverName); err == nil {
			conn.Close()
			cancel()
			t.Fatalf("SNI %q completed the AnyTLS TLS handshake", serverName)
		}
		cancel()
	}
	if traffic, alive, count, err := instance.GetUserTraffic(context.Background()); err != nil || len(traffic) != 0 || len(alive) != 0 || count != 0 {
		t.Fatalf("rejected handshakes were counted as user traffic: %v %v %d %v", traffic, alive, count, err)
	}
	if events := capture.snapshot(); len(events) != 0 {
		t.Fatal("rejected handshakes were audited")
	}

	for _, serverName := range []string{"iosapps.itunes.apple.com", "WWW.Apple.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		client, err := anytls.NewClient(ctx, anytls.ClientConfig{
			Password: user.UUID,
			Logger:   log.NewNOPFactory().Logger(),
			DialOut:  func(ctx context.Context) (net.Conn, error) { return anyTLSWhitelistDial(ctx, port, serverName) },
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		stream, err := client.CreateProxy(ctx, singM.SocksaddrFromNet(echo.Addr()))
		if err != nil {
			client.Close()
			cancel()
			t.Fatalf("whitelisted SNI %q was rejected: %v", serverName, err)
		}
		stream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err = stream.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		var response [4]byte
		if _, err = io.ReadFull(stream, response[:]); err != nil {
			t.Fatal(err)
		}
		if string(response[:]) != "ping" {
			t.Fatalf("echo = %q, want ping", response)
		}
		stream.Close()
		client.Close()
		cancel()
	}

	// Receiving the echo can precede the server's byte-count callbacks.
	deadline := time.Now().Add(2 * time.Second)
	for {
		traffic, _, _, err := instance.GetUserTraffic(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		events := capture.snapshot()
		if traffic[42][0] > 0 && traffic[42][1] > 0 && len(events) == 2 && events[0].UserID == 42 && events[1].UserID == 42 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("whitelisted traffic not settled: traffic=%v audit=%+v", traffic, events)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// anyTLSWhitelistDial completes a TLS handshake with certificate verification
// disabled, so only the server-side SNI check can refuse it.
func anyTLSWhitelistDial(ctx context.Context, port int, serverName string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err = secure.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return secure, nil
}
