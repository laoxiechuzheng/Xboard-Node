package singbox

import (
	"context"
	"crypto/tls"
	"encoding/hex"
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

func TestAnyTLSForceProxyProtocolTracksRealClient(t *testing.T) {
	for _, test := range []struct {
		name      string
		force     bool
		header    string
		headerHex string
		wantIP    string
	}{
		{name: "disabled_direct", wantIP: "127.0.0.1"},
		{name: "enabled_direct", force: true, wantIP: "127.0.0.1"},
		{name: "v1_ipv4", force: true, header: "PROXY TCP4 203.0.113.9 198.51.100.8 54321 443\r\n", wantIP: "203.0.113.9"},
		{name: "v1_ipv6", force: true, header: "PROXY TCP6 2001:db8::9 2001:db8::8 54321 443\r\n", wantIP: "2001:db8::9"},
		{name: "v2_ipv4", force: true, headerHex: "0d0a0d0a000d0a515549540a2111000ccb007109c6336408d43101bb", wantIP: "203.0.113.9"},
		{name: "v2_ipv6", force: true, headerHex: "0d0a0d0a000d0a515549540a2121002420010db800000000000000000000000920010db8000000000000000000000008d43101bb", wantIP: "2001:db8::9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { echo.Close() })
			go func() {
				conn, err := echo.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				io.Copy(conn, conn)
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
			instance := New(config.KernelConfig{
				Type: "singbox", LogLevel: "none", ForceProxyProtocol: test.force,
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			user := model.UserSpec{ID: 7, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}
			err = instance.Start(&model.NodeSpec{Protocol: "anytls", NodeID: 9, ServerPort: port, TLS: 1}, []model.UserSpec{user}, kernel.TLSCert{CertPEM: certificate, KeyPEM: key})
			if err != nil {
				t.Fatalf("start AnyTLS kernel: %v", err)
			}
			t.Cleanup(instance.Stop)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			header := []byte(test.header)
			if test.headerHex != "" {
				header, err = hex.DecodeString(test.headerHex)
				if err != nil {
					t.Fatal(err)
				}
			}
			client, err := anytls.NewClient(ctx, anytls.ClientConfig{
				Password: user.UUID,
				Logger:   log.NewNOPFactory().Logger(),
				DialOut: func(ctx context.Context) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
					if err != nil {
						return nil, err
					}
					if deadline, ok := ctx.Deadline(); ok {
						conn.SetDeadline(deadline)
					}
					if len(header) > 0 {
						if _, err = conn.Write(header); err != nil {
							conn.Close()
							return nil, err
						}
					}
					secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "anytls.test"})
					if err = secure.HandshakeContext(ctx); err != nil {
						conn.Close()
						return nil, err
					}
					return secure, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			stream, err := client.CreateProxy(ctx, singM.SocksaddrFromNet(echo.Addr()))
			if err != nil {
				t.Fatalf("open authenticated AnyTLS stream: %v", err)
			}
			t.Cleanup(func() { stream.Close() })
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
			// Receiving the echo can precede the server's byte-count callbacks.
			pollCtx, pollCancel := context.WithTimeout(ctx, 2*time.Second)
			defer pollCancel()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				traffic, alive, count, err := instance.GetUserTraffic(pollCtx)
				if err != nil {
					t.Fatal(err)
				}
				if count == 1 && len(alive[user.ID]) == 1 && alive[user.ID][test.wantIP] && traffic[user.ID][0] >= 4 && traffic[user.ID][1] >= 4 {
					break
				}
				select {
				case <-pollCtx.Done():
					t.Fatalf("tracked traffic did not settle: count=%d alive=%v traffic=%v, want %s", count, alive, traffic, test.wantIP)
				case <-ticker.C:
				}
			}
		})
	}
}
