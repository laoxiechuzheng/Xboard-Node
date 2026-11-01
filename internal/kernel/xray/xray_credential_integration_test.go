package xray

import (
	"io"
	stdnet "net"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

// ssTestConn is a Shadowsocks AEAD client built from xray's own codec.
type ssTestConn struct {
	conn stdnet.Conn
	user *protocol.MemoryUser
	w    buf.Writer
	r    buf.Reader
}

func ssDial(t *testing.T, node *model.NodeSpec, u model.UserSpec, target *stdnet.TCPAddr) *ssTestConn {
	t.Helper()
	mu, err := toMemoryUser("shadowsocks", node, u)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := stdnet.DialTimeout("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(node.ServerPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	w, err := shadowsocks.WriteTCPRequest(&protocol.RequestHeader{
		Version: shadowsocks.Version,
		Command: protocol.RequestCommandTCP,
		Address: net.IPAddress(target.IP.To4()),
		Port:    net.Port(target.Port),
		User:    mu,
	}, conn)
	if err != nil {
		t.Fatal(err)
	}
	return &ssTestConn{conn: conn, user: mu, w: w}
}

func (c *ssTestConn) echo(payload string) error {
	c.conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.conn.SetDeadline(time.Time{})
	b := buf.New()
	b.WriteString(payload)
	if err := c.w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return err
	}
	if c.r == nil {
		r, err := shadowsocks.ReadTCPResponse(c.user, c.conn)
		if err != nil {
			return err
		}
		c.r = r
	}
	for got := 0; got < len(payload); {
		mb, err := c.r.ReadMultiBuffer()
		if err != nil {
			return err
		}
		got += int(mb.Len())
		buf.ReleaseMulti(mb)
	}
	return nil
}

// waitConnCut fails unless the server closes conn within 3s.
func waitConnCut(t *testing.T, conn stdnet.Conn, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var b [256]byte
	for {
		_, err := conn.Read(b[:])
		if err == nil {
			continue
		}
		if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
			t.Fatalf("%s: connection still open 3s after the UUID reset", what)
		}
		return
	}
}

// A UUID reset on a Shadowsocks AEAD node cuts the old password's live
// connection, as it does for VLESS; the new UUID and other users keep working.
func TestXrayShadowsocksUUIDResetCutsLiveConnection(t *testing.T) {
	target := startTCPEcho(t)
	x := newRemovalTestXray(t)
	node := &model.NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm", ListenIP: "127.0.0.1", ServerPort: freeTCPPort(t)}
	reset := model.UserSpec{ID: 3, UUID: removalUUID1}
	kept := model.UserSpec{ID: 2, UUID: removalUUID2}
	if err := x.Start(node, []model.UserSpec{reset, kept}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	resetConn := ssDial(t, node, reset, target)
	keptConn := ssDial(t, node, kept, target)
	for name, conn := range map[string]*ssTestConn{"reset": resetConn, "kept": keptConn} {
		if err := conn.echo("hello"); err != nil {
			t.Fatalf("%s user before the reset: %v", name, err)
		}
	}

	resetUser := model.UserSpec{ID: reset.ID, UUID: removalUUID3}
	if _, _, err := x.UpdateUsers([]model.UserSpec{kept, resetUser}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	waitConnCut(t, resetConn.conn, "old shadowsocks password")
	if err := keptConn.echo("still"); err != nil {
		t.Fatalf("kept user disrupted by the reset: %v", err)
	}
	if err := ssDial(t, node, reset, target).echo("old"); err == nil {
		t.Fatal("old UUID can still connect")
	}
	if err := ssDial(t, node, resetUser, target).echo("new"); err != nil {
		t.Fatalf("new UUID cannot connect: %v", err)
	}
}

// The same on a Shadowsocks 2022 multi-user node. The new UUID is added
// through the UserManager, so it also proves the hitlessly added key matches
// what clients derive from the config.
func TestXrayShadowsocks2022UUIDResetCutsLiveConnection(t *testing.T) {
	target := startTCPEcho(t)
	x := newRemovalTestXray(t)
	node := ss2022Node(freeTCPPort(t))
	reset := model.UserSpec{ID: 3, UUID: removalUUID1}
	kept := model.UserSpec{ID: 2, UUID: removalUUID2}
	if err := x.Start(node, []model.UserSpec{reset, kept}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	echo := func(conn stdnet.Conn, payload string) error {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		defer conn.SetDeadline(time.Time{})
		if _, err := conn.Write([]byte(payload)); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, len(payload)))
		return err
	}
	resetConn := ss2022Dial(t, node, reset, target)
	keptConn := ss2022Dial(t, node, kept, target)
	for name, conn := range map[string]stdnet.Conn{"reset": resetConn, "kept": keptConn} {
		if err := echo(conn, "hello"); err != nil {
			t.Fatalf("%s user before the reset: %v", name, err)
		}
	}

	resetUser := model.UserSpec{ID: reset.ID, UUID: removalUUID3}
	if _, _, err := x.UpdateUsers([]model.UserSpec{kept, resetUser}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	waitConnCut(t, resetConn, "old shadowsocks 2022 key")
	if err := echo(keptConn, "still"); err != nil {
		t.Fatalf("kept user disrupted by the reset: %v", err)
	}
	if err := echo(ss2022Dial(t, node, reset, target), "old"); err == nil {
		t.Fatal("old UUID can still connect")
	}
	if err := echo(ss2022Dial(t, node, resetUser, target), "new"); err != nil {
		t.Fatalf("new UUID added through the UserManager cannot connect: %v", err)
	}
}
