package xray

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/uuid"
)

// vlessDial opens a plain VLESS (no flow, no TLS) TCP request to target and
// consumes the response header lazily on the first echo.
type vlessTestConn struct {
	stdnet.Conn
	headerRead bool
}

func vlessDial(t *testing.T, port int, id string, target *stdnet.TCPAddr) *vlessTestConn {
	t.Helper()
	parsed, err := uuid.ParseString(id)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := stdnet.DialTimeout("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	request := []byte{0} // version
	request = append(request, parsed.Bytes()...)
	request = append(request, 0, 1) // no addons, TCP
	request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
	request = append(request, 1) // IPv4
	request = append(request, target.IP.To4()...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	return &vlessTestConn{Conn: conn}
}

func (c *vlessTestConn) echo(payload string) error {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(payload)); err != nil {
		return err
	}
	if !c.headerRead {
		var header [2]byte // version, addons length (0)
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return err
		}
		c.headerRead = true
	}
	response := make([]byte, len(payload))
	_, err := io.ReadFull(c, response)
	return err
}

// waitCut fails unless the server closes the connection soon.
func (c *vlessTestConn) waitCut(t *testing.T, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var b [64]byte
	for {
		_, err := c.Read(b[:])
		if err == nil {
			continue
		}
		if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
			t.Fatalf("%s: connection still open after removal", what)
		}
		return
	}
}

// TestXrayRemovedUserConnectionsAreCut drives real VLESS connections through
// Xray.Start: RemoveUsers, a UUID change via UpdateUsers and
// CloseUserConnections must close the affected live connections (which run
// through LimitDispatcher.DispatchLink, as VLESS Vision/REALITY do) and leave
// everybody else connected.
func TestXrayRemovedUserConnectionsAreCut(t *testing.T) {
	echo, err := stdnet.Listen("tcp", "127.0.0.1:0")
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
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	target := echo.Addr().(*stdnet.TCPAddr)

	reservation, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*stdnet.TCPAddr).Port
	reservation.Close()

	x := New(config.KernelConfig{
		Type: "xray", LogLevel: "none",
		// Only the test permits loopback echo destinations.
		CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}},
	})
	t.Cleanup(func() { stopAndRecycle(t, x) })
	removed := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	kept := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
	reset := model.UserSpec{ID: 3, UUID: "33333333-3333-4333-8333-333333333333"}
	node := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port}
	if err := x.Start(node, []model.UserSpec{removed, kept, reset}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}

	removedConn := vlessDial(t, port, removed.UUID, target)
	keptConn := vlessDial(t, port, kept.UUID, target)
	resetConn := vlessDial(t, port, reset.UUID, target)
	for name, conn := range map[string]*vlessTestConn{"removed": removedConn, "kept": keptConn, "reset": resetConn} {
		if err := conn.echo("hello"); err != nil {
			t.Fatalf("%s user before removal: %v", name, err)
		}
	}

	if n, err := x.RemoveUsers([]model.UserSpec{removed}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	removedConn.waitCut(t, "removed user")
	if err := keptConn.echo("still"); err != nil {
		t.Fatalf("kept user disrupted by removal: %v", err)
	}

	resetUser := model.UserSpec{ID: reset.ID, UUID: "33333333-3333-4333-8333-3333333333c3"}
	if _, _, err := x.UpdateUsers([]model.UserSpec{kept, resetUser}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	resetConn.waitCut(t, "old UUID")
	if err := keptConn.echo("again"); err != nil {
		t.Fatalf("kept user disrupted by UUID reset: %v", err)
	}
	if err := vlessDial(t, port, reset.UUID, target).echo("old"); err == nil {
		t.Fatal("old UUID can still connect")
	}
	if err := vlessDial(t, port, resetUser.UUID, target).echo("new"); err != nil {
		t.Fatalf("new UUID cannot connect: %v", err)
	}

	if err := x.CloseUserConnections(context.Background(), kept.UUID); err != nil {
		t.Fatal(err)
	}
	keptConn.waitCut(t, "CloseUserConnections")
	if err := vlessDial(t, port, kept.UUID, target).echo("back"); err != nil {
		t.Fatalf("user must be able to reconnect after CloseUserConnections: %v", err)
	}
}
