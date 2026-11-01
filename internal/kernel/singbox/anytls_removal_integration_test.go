package singbox

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	coreTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	singM "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	anytls "github.com/anytls/sing-anytls"
)

// peerClosedConn records when the server closes the client's TCP connection.
type peerClosedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *peerClosedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.once.Do(func() { close(c.closed) })
	}
	return n, err
}

type anyTLSRemovalClient struct {
	client *anytls.Client
	mu     sync.Mutex
	dialed []*peerClosedConn
}

func (c *anyTLSRemovalClient) firstConn(t *testing.T) *peerClosedConn {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.dialed) == 0 {
		t.Fatal("client never dialed")
	}
	return c.dialed[0]
}

func newAnyTLSRemovalClient(t *testing.T, port int, password string) *anyTLSRemovalClient {
	t.Helper()
	c := &anyTLSRemovalClient{}
	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password,
		Logger:   log.NewNOPFactory().Logger(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, err
			}
			secure := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "anytls.test"})
			if err = secure.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			// Watch the TLS layer: a server close arrives as close_notify,
			// which the TLS reader reports as EOF.
			watched := &peerClosedConn{Conn: secure, closed: make(chan struct{})}
			c.mu.Lock()
			c.dialed = append(c.dialed, watched)
			c.mu.Unlock()
			return watched, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.client = client
	t.Cleanup(func() { client.Close() })
	return c
}

func (c *anyTLSRemovalClient) open(t *testing.T, target net.Addr) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := c.client.CreateProxy(ctx, singM.SocksaddrFromNet(target))
	if err != nil {
		t.Fatalf("open AnyTLS stream: %v", err)
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

func anyTLSEcho(stream net.Conn, payload string) error {
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	defer stream.SetDeadline(time.Time{})
	if _, err := stream.Write([]byte(payload)); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	_, err := io.ReadFull(stream, response)
	return err
}

func waitPeerClosed(t *testing.T, what string, conn *peerClosedConn) {
	t.Helper()
	select {
	case <-conn.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: server kept the authenticated AnyTLS session open", what)
	}
}

// TestAnyTLSRemovedUserLosesSessionAndStreams drives real AnyTLS clients
// through SingBox: removing a user (or resetting its UUID) must close its live
// streams and the authenticated session they ride on, refuse new streams on an
// idle pooled session, and leave other users alone.
func TestAnyTLSRemovedUserLosesSessionAndStreams(t *testing.T) {
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
				conn.SetDeadline(time.Now().Add(20 * time.Second))
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
	instance := New(config.KernelConfig{
		Type: "singbox", LogLevel: "none",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	removed := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000001"}
	kept := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000002"}
	reset := model.UserSpec{ID: 3, UUID: "00000000-0000-4000-8000-000000000003"}
	users := []model.UserSpec{removed, kept, reset}
	err = instance.Start(&model.NodeSpec{Protocol: "anytls", NodeID: 9, ServerPort: port, TLS: 1}, users, kernel.TLSCert{CertPEM: certificate, KeyPEM: key})
	if err != nil {
		t.Fatalf("start AnyTLS kernel: %v", err)
	}
	t.Cleanup(instance.Stop)

	removedClient := newAnyTLSRemovalClient(t, port, removed.UUID)
	keptClient := newAnyTLSRemovalClient(t, port, kept.UUID)
	resetClient := newAnyTLSRemovalClient(t, port, reset.UUID)

	removedStream := removedClient.open(t, echo.Addr())
	keptStream := keptClient.open(t, echo.Addr())
	if err := anyTLSEcho(removedStream, "a1"); err != nil {
		t.Fatalf("removed user before removal: %v", err)
	}
	if err := anyTLSEcho(keptStream, "b1"); err != nil {
		t.Fatalf("kept user before removal: %v", err)
	}
	// The reset user's session is authenticated, then left idle in the pool.
	idle := resetClient.open(t, echo.Addr())
	if err := anyTLSEcho(idle, "c1"); err != nil {
		t.Fatalf("reset user before reset: %v", err)
	}
	idle.Close()
	time.Sleep(100 * time.Millisecond)

	// Live stream: removal closes it and the session under it.
	if n, err := instance.RemoveUsers([]model.UserSpec{removed}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	waitPeerClosed(t, "removed user", removedClient.firstConn(t))
	if err := anyTLSEcho(removedStream, "a2"); err == nil {
		t.Fatal("live stream of a removed user still works")
	}
	if err := anyTLSEcho(keptStream, "b2"); err != nil {
		t.Fatalf("kept user's live stream was disrupted: %v", err)
	}

	// Idle session: after a UUID reset, a new stream on the session that
	// authenticated with the old UUID is refused and the session closed.
	resetUser := model.UserSpec{ID: reset.ID, UUID: "00000000-0000-4000-8000-0000000000c3"}
	if _, _, err := instance.UpdateUsers([]model.UserSpec{kept, resetUser}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	stale := resetClient.open(t, echo.Addr())
	if err := anyTLSEcho(stale, "c2"); err == nil {
		t.Fatal("new stream on a session authenticated with the old UUID was served")
	}
	waitPeerClosed(t, "old UUID", resetClient.firstConn(t))

	if err := anyTLSEcho(keptStream, "b3"); err != nil {
		t.Fatalf("kept user's live stream was disrupted: %v", err)
	}
	fresh := newAnyTLSRemovalClient(t, port, resetUser.UUID).open(t, echo.Addr())
	if err := anyTLSEcho(fresh, "c3"); err != nil {
		t.Fatalf("new UUID after reset: %v", err)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	return port
}

func startAnyTLSRemovalKernel(t *testing.T, instance *SingBox, port int, users []model.UserSpec) {
	t.Helper()
	key, certificate, err := coreTLS.GenerateCertificate(nil, nil, time.Now, "anytls.test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	err = instance.Start(&model.NodeSpec{Protocol: "anytls", NodeID: 9, ServerPort: port, TLS: 1}, users, kernel.TLSCert{CertPEM: certificate, KeyPEM: key})
	if err != nil {
		t.Fatalf("start AnyTLS kernel: %v", err)
	}
}

// A UDP-over-TCP stream rides on the AnyTLS session as a packet connection:
// removing its user must close that session too.
func TestAnyTLSRemovedUserLosesUDPOverTCPSession(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFrom(b)
			if err != nil {
				return
			}
			echo.WriteTo(b[:n], addr)
		}
	}()

	port := freeTCPPort(t)
	instance := New(config.KernelConfig{
		Type: "singbox", LogLevel: "none",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	removed := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000011"}
	kept := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000012"}
	startAnyTLSRemovalKernel(t, instance, port, []model.UserSpec{removed, kept})
	t.Cleanup(instance.Stop)

	client := newAnyTLSRemovalClient(t, port, removed.UUID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.client.CreateProxy(ctx, uot.RequestDestination(uot.Version))
	if err != nil {
		t.Fatalf("open UoT stream: %v", err)
	}
	t.Cleanup(func() { stream.Close() })
	packets := uot.NewLazyConn(stream, uot.Request{IsConnect: true, Destination: singM.SocksaddrFromNet(echo.LocalAddr())})
	packets.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := packets.Write([]byte("u1")); err != nil {
		t.Fatalf("UoT write: %v", err)
	}
	response := make([]byte, 16)
	if n, err := packets.Read(response); err != nil || string(response[:n]) != "u1" {
		t.Fatalf("UoT echo before removal = %q, %v", response[:n], err)
	}
	packets.SetDeadline(time.Time{})

	if n, err := instance.RemoveUsers([]model.UserSpec{removed}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	waitPeerClosed(t, "removed user's UoT session", client.firstConn(t))
}

// A full restart replaces the box; the old one keeps serving live
// connections while it drains. Users the restart removed must lose them at
// once, users that stay keep them.
func TestSingBoxRestartCutsRemovedUsersOnDrainingBox(t *testing.T) {
	instance := New(config.KernelConfig{Type: "singbox", LogLevel: "none"})
	removed := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000021"}
	kept := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000022"}
	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), []model.UserSpec{removed, kept})
	t.Cleanup(instance.Stop)

	oldTracker := instance.connTracker
	removedConn := &closeFlagConn{}
	keptConn := &closeFlagConn{}
	oldTracker.RoutedConnection(context.Background(), removedConn, removalMetadata("anytls", removed.UUID), nil, nil)
	keptWrapped := oldTracker.RoutedConnection(context.Background(), keptConn, removalMetadata("anytls", kept.UUID), nil, nil)
	// Let the old box finish draining once the test is done.
	t.Cleanup(func() { keptWrapped.Close() })

	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), []model.UserSpec{kept})
	if instance.connTracker == oldTracker {
		t.Fatal("restart did not replace the tracker")
	}
	waitClosed(t, "removed user's connection on the draining box", removedConn.closed.Load)
	stayOpen(t, "kept user's connection on the draining box", keptConn.closed.Load)
	stale := &closeFlagConn{}
	oldTracker.RoutedConnection(context.Background(), stale, removalMetadata("anytls", removed.UUID), nil, nil)
	if !stale.closed.Load() {
		t.Fatal("draining box served a new stream of the removed user")
	}
}
