package xray

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	stdnet "net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	singM "github.com/sagernet/sing/common/metadata"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func testSelfSignedCert(t *testing.T, name string) kernel.TLSCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return kernel.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// startStreamingTarget drains whatever a client sends and streams one byte
// every 50ms back until the write fails: a long download.
func startStreamingTarget(t *testing.T) *stdnet.TCPAddr {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				go io.Copy(io.Discard, conn)
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := conn.Write([]byte{'d'}); err != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}()
		}
	}()
	return ln.Addr().(*stdnet.TCPAddr)
}

// trojanDial opens a Trojan TCP request to target and waits for the download
// to start; halfClose then ends the client's upload (TLS close_notify).
func trojanDial(t *testing.T, port int, password string, target *stdnet.TCPAddr, halfClose bool) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&stdnet.Dialer{Timeout: 3 * time.Second}, "tcp",
		stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true, ServerName: "trojan.test", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	sum := sha256.Sum224([]byte(password))
	request := []byte(hex.EncodeToString(sum[:]))
	request = append(request, '\r', '\n', 1 /* CONNECT */, 1 /* IPv4 */)
	request = append(request, target.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
	request = append(request, '\r', '\n', 'u')
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		t.Fatalf("download did not start: %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	if halfClose {
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

// waitDownloadCut fails unless the download stops within 3s. The target
// streams continuously, so the DownlinkOnly inactivity timer (5s) never fires
// and only a revocation can end the connection.
func waitDownloadCut(t *testing.T, conn *tls.Conn, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var b [64]byte
	n := 0
	for {
		k, err := conn.Read(b[:])
		n += k
		if err == nil {
			continue
		}
		if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
			t.Fatalf("%s: connection still downloading 3s after revocation (%d bytes meanwhile)", what, n)
		}
		return
	}
}

// Trojan dispatches through the pipe path and closes the uplink as soon as
// the client half-closes; the download keeps running and must still be cut
// by a removal, a UUID reset or CloseUserConnections.
func TestXrayTrojanHalfClosedDownloadIsRevoked(t *testing.T) {
	cert := testSelfSignedCert(t, "trojan.test")
	cases := []struct {
		name      string
		halfClose bool
		revoke    func(t *testing.T, x *Xray, victim model.UserSpec)
	}{
		{"RemoveUsers/full_duplex", false, func(t *testing.T, x *Xray, v model.UserSpec) {
			if _, err := x.RemoveUsers([]model.UserSpec{v}); err != nil {
				t.Fatal(err)
			}
		}},
		{"RemoveUsers/half_closed", true, func(t *testing.T, x *Xray, v model.UserSpec) {
			if _, err := x.RemoveUsers([]model.UserSpec{v}); err != nil {
				t.Fatal(err)
			}
		}},
		{"AddUsersNewUUID/half_closed", true, func(t *testing.T, x *Xray, v model.UserSpec) {
			if _, err := x.AddUsers([]model.UserSpec{{ID: v.ID, UUID: removalUUID3}}); err != nil {
				t.Fatal(err)
			}
		}},
		{"CloseUserConnections/half_closed", true, func(t *testing.T, x *Xray, v model.UserSpec) {
			if err := x.CloseUserConnections(context.Background(), v.UUID); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := startStreamingTarget(t)
			port := freeTCPPort(t)
			x := newRemovalTestXray(t)
			victim := model.UserSpec{ID: 1, UUID: removalUUID1}
			kept := model.UserSpec{ID: 2, UUID: removalUUID2}
			node := &model.NodeSpec{Protocol: "trojan", ListenIP: "127.0.0.1", ServerPort: port, TLS: 1, ServerName: "trojan.test"}
			if err := x.Start(node, []model.UserSpec{victim, kept}, cert); err != nil {
				t.Fatalf("start xray: %v", err)
			}
			ld := x.limitDispatcher
			conn := trojanDial(t, port, victim.UUID, target, tc.halfClose)
			if tc.halfClose {
				// Give the inbound time to close the uplink; the download
				// keeps flowing and the link stays indexed.
				time.Sleep(200 * time.Millisecond)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var b [4]byte
				if _, err := io.ReadFull(conn, b[:]); err != nil {
					t.Fatalf("download stopped after the half-close: %v", err)
				}
				conn.SetReadDeadline(time.Time{})
			}
			if got := linkStateOf(ld, victim.ID); got.indexed != 1 {
				t.Fatalf("live link state = %+v, want indexed", got)
			}
			tc.revoke(t, x, victim)
			waitDownloadCut(t, conn, tc.name)
		})
	}
}

// startOneShotEcho serves one 5-byte echo per connection and then closes it,
// so every proxied connection ends normally from the remote side.
func startOneShotEcho(t *testing.T) *stdnet.TCPAddr {
	t.Helper()
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
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				b := make([]byte, 5)
				if _, err := io.ReadFull(conn, b); err != nil {
					return
				}
				conn.Write(b)
			}()
		}
	}()
	return echo.Addr().(*stdnet.TCPAddr)
}

// waitDispatcherIdle waits for every link of the dispatcher to be released
// and its connection count and alive IPs to return to zero.
func waitDispatcherIdle(t *testing.T, ld *LimitDispatcher) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ld.mu.RLock()
		links := len(ld.links)
		ld.mu.RUnlock()
		alive, count := ld.GetConnectionState()
		if links == 0 && count == 0 && len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("dispatcher not idle after the connections ended: users with links=%d connCount=%d aliveIPs=%v", links, count, alive)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const finishedConns = 5

// Plain VLESS (DispatchLink) releases its links when they end.
func TestXrayVLESSFinishedConnectionsLeaveIndex(t *testing.T) {
	target := startOneShotEcho(t)
	port := freeTCPPort(t)
	x := newRemovalTestXray(t)
	user := model.UserSpec{ID: 1, UUID: removalUUID1}
	if err := x.Start(vlessNode(port), []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	for i := 0; i < finishedConns; i++ {
		c := vlessDial(t, port, user.UUID, target)
		if err := c.echo("hello"); err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
		c.Close()
	}
	waitDispatcherIdle(t, x.limitDispatcher)
}

func ss2022Node(port int) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm",
		ServerKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		ListenIP:  "127.0.0.1", ServerPort: port,
	}
}

// ss2022Dial opens an SS2022 multi-user connection to target with the key the
// node configures for u.
func ss2022Dial(t *testing.T, node *model.NodeSpec, u model.UserSpec, target *stdnet.TCPAddr) stdnet.Conn {
	t.Helper()
	userKey, _ := ss2022UserKey(node.Cipher, u.UUID)
	method, err := shadowaead_2022.NewWithPassword(node.Cipher, node.ServerKey+":"+userKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stdnet.DialTimeout("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(node.ServerPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	return method.DialEarlyConn(raw, singM.ParseSocksaddrHostPort("127.0.0.1", uint16(target.Port)))
}

// SS2022's sing bridge never closes the link's Writer: finished connections
// are released when their connection context ends instead of staying
// indexed, counted and reported alive forever.
func TestXraySS2022FinishedConnectionsLeaveIndex(t *testing.T) {
	target := startOneShotEcho(t)
	x := newRemovalTestXray(t)
	node := ss2022Node(freeTCPPort(t))
	user := model.UserSpec{ID: 7, UUID: "77777777-7777-4777-8777-777777777777"}
	if err := x.Start(node, []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	for i := 0; i < finishedConns; i++ {
		conn := ss2022Dial(t, node, user, target)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
			t.Fatalf("echo %d: %q %v", i, got, err)
		}
		// The remote closed after echoing: drain to EOF, then close.
		io.Copy(io.Discard, conn)
		conn.Close()
	}
	waitDispatcherIdle(t, x.limitDispatcher)
}
