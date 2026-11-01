// The socks and http inbounds of the sing-box fork swap their authenticator
// in UpdateUsers without synchronisation while accepted connections read it,
// a data race of the library this test drives on purpose (users change while
// clients connect), so it is left out of race builds. The gate it checks is
// also covered by TestConnTrackerRefusesEmptyUserOnAuthenticatingInbounds.

//go:build !race

package singbox

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// recordingEchoServer echoes every connection and remembers all bytes it
// received, so a test can prove a payload never reached the target.
type recordingEchoServer struct {
	addr     *net.TCPAddr
	mu       sync.Mutex
	received bytes.Buffer
}

func newRecordingEchoServer(t *testing.T) *recordingEchoServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	s := &recordingEchoServer{addr: listener.Addr().(*net.TCPAddr)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				b := make([]byte, 1024)
				for {
					n, err := conn.Read(b)
					if n > 0 {
						s.mu.Lock()
						s.received.Write(b[:n])
						s.mu.Unlock()
						if _, werr := conn.Write(b[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func (s *recordingEchoServer) saw(payload string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.received.Bytes(), []byte(payload))
}

func tunnelEcho(conn net.Conn, payload string) error {
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if string(response) != payload {
		return fmt.Errorf("echo = %q, want %q", response, payload)
	}
	return nil
}

// socks5Dial opens a SOCKS5 CONNECT tunnel to target. An empty user offers
// only the "no authentication" method.
func socks5Dial(port int, target *net.TCPAddr, user, pass string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fail := func(err error) (net.Conn, error) { conn.Close(); return nil, err }
	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		return fail(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fail(fmt.Errorf("method reply: %w", err))
	}
	if reply[1] != method {
		return fail(fmt.Errorf("server refused auth method %#x (reply %#x)", method, reply[1]))
	}
	if user != "" {
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := conn.Write(auth); err != nil {
			return fail(err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return fail(fmt.Errorf("auth reply: %w", err))
		}
		if reply[1] != 0x00 {
			return fail(fmt.Errorf("auth failed: %#x", reply[1]))
		}
	}
	ip := target.IP.To4()
	request := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(target.Port >> 8), byte(target.Port)}
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fail(fmt.Errorf("connect reply: %w", err))
	}
	if response[1] != 0x00 {
		return fail(fmt.Errorf("connect refused: %#x", response[1]))
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// httpConnectDial opens an HTTP CONNECT tunnel to target. An empty user sends
// no Proxy-Authorization header.
func httpConnectDial(port int, target *net.TCPAddr, user, pass string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if user != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	request += "\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT status %d", response.StatusCode)
	}
	if reader.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("unexpected buffered bytes after CONNECT")
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// sing's auth.NewAuthenticator returns nil for an empty user list, and the
// SOCKS/HTTP handshakes then skip authentication. Once the last panel user is
// gone the node must still relay nothing for anonymous clients, and serve the
// user again once it is re-added.
func TestSocksAndHTTPRefuseAnonymousAfterLastUserRemoved(t *testing.T) {
	type dialer func(port int, target *net.TCPAddr, user, pass string) (net.Conn, error)
	type cycle struct {
		clear func(*SingBox, model.UserSpec) error
		add   func(*SingBox, model.UserSpec) error
	}
	protocols := map[string]dialer{"socks": socks5Dial, "http": httpConnectDial}
	cycles := map[string]cycle{
		"UpdateUsers": {
			clear: func(s *SingBox, _ model.UserSpec) error {
				_, _, err := s.UpdateUsers([]model.UserSpec{})
				return err
			},
			add: func(s *SingBox, u model.UserSpec) error {
				_, _, err := s.UpdateUsers([]model.UserSpec{u})
				return err
			},
		},
		"RemoveUsers": {
			clear: func(s *SingBox, u model.UserSpec) error {
				if n, err := s.RemoveUsers([]model.UserSpec{u}); err != nil || n != 1 {
					return fmt.Errorf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
				}
				return nil
			},
			add: func(s *SingBox, u model.UserSpec) error {
				if n, err := s.AddUsers([]model.UserSpec{u}); err != nil || n != 1 {
					return fmt.Errorf("AddUsers = (%d, %v), want (1, nil)", n, err)
				}
				return nil
			},
		},
	}
	for protocol, dial := range protocols {
		for cycleName, c := range cycles {
			t.Run(protocol+"/"+cycleName, func(t *testing.T) {
				target := newRecordingEchoServer(t)
				port := freeTCPPort(t)
				instance := New(config.KernelConfig{
					Type: "singbox", LogLevel: "none",
					CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
				})
				user := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000031"}
				if err := instance.Start(&model.NodeSpec{Protocol: protocol, NodeID: 9, ServerPort: port}, []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
					t.Fatalf("start %s kernel: %v", protocol, err)
				}
				t.Cleanup(instance.Stop)

				authenticatedWorks := func(stage string) {
					t.Helper()
					conn, err := dial(port, target.addr, user.UUID, user.UUID)
					if err != nil {
						t.Fatalf("authenticated client %s: %v", stage, err)
					}
					defer conn.Close()
					if err := tunnelEcho(conn, "authed-"+stage); err != nil {
						t.Fatalf("authenticated echo %s: %v", stage, err)
					}
				}
				// The anonymous client may get past the handshake (the inbound
				// no longer authenticates); what matters is that nothing it sends
				// reaches the target.
				anonymousRefused := func(stage string) {
					t.Helper()
					payload := "anonymous-" + stage
					conn, err := dial(port, target.addr, "", "")
					if err != nil {
						return
					}
					defer conn.Close()
					if err := tunnelEcho(conn, payload); err == nil {
						t.Fatalf("anonymous client was relayed %s", stage)
					}
					time.Sleep(100 * time.Millisecond)
					if target.saw(payload) {
						t.Fatalf("anonymous payload reached the target %s", stage)
					}
				}

				anonymousRefused("with a user")
				authenticatedWorks("with a user")

				if err := c.clear(instance, user); err != nil {
					t.Fatalf("clear users: %v", err)
				}
				anonymousRefused("after the last user was removed")

				if err := c.add(instance, user); err != nil {
					t.Fatalf("re-add user: %v", err)
				}
				authenticatedWorks("after re-adding the user")
				anonymousRefused("after re-adding the user")
			})
		}
	}
}
