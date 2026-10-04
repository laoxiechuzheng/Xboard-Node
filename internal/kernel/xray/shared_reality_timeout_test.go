package xray

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/hkdf"
)

type sharedTimeoutPipeConn struct {
	net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
	readStarted chan struct{}
	readOnce    sync.Once
}

func (c *sharedTimeoutPipeConn) Read(p []byte) (int, error) {
	if c.readStarted != nil {
		c.readOnce.Do(func() { close(c.readStarted) })
	}
	return c.Conn.Read(p)
}

func (c *sharedTimeoutPipeConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

// net.Pipe has no half-close; REALITY requires the CloseWriteConn interface.
func (c *sharedTimeoutPipeConn) CloseWrite() error { return c.Close() }

func sharedTimeoutAuthenticatedHello(t *testing.T, serverKey *ecdh.PrivateKey, id [8]byte) []byte {
	t.Helper()
	client := utls.UClient(nil, &utls.Config{ServerName: "cover.test"}, utls.HelloChrome_120)
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatalf("build timeout fixture ClientHello: %v", err)
	}
	hello := client.HandshakeState.Hello
	keys := client.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.Ecdhe == nil || len(hello.Raw) < 71 || hello.Raw[38] != 32 {
		t.Fatal("timeout fixture lacks the X25519 key or 32-byte REALITY session ID")
	}
	key, err := keys.Ecdhe.ECDH(serverKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, hello.Random[:20], []byte("REALITY")), key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	raw := bytes.Clone(hello.Raw)
	clear(raw[39:71])
	var plain [16]byte
	plain[0] = 1
	binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
	copy(plain[8:], id[:])
	copy(raw[39:71], aead.Seal(nil, hello.Random[20:], plain[:], raw))
	return append([]byte{22, 3, 1, byte(len(raw) >> 8), byte(len(raw))}, raw...)
}

func sharedTimeoutWait(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func sharedTimeoutAssertPeerClosed(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
			return
		}
		t.Errorf("set %s close-check deadline: %v", name, err)
		return
	}
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n != 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed)) {
		t.Errorf("%s peer did not observe connection closure: n=%d err=%v", name, n, err)
	}
}

// This exercises native REALITY cover I/O and group cancellation, not an
// authorization bypass. A valid authenticated hello keeps the cover read
// blocked after the client-hello worker exits; the cover never sends a reply.
func TestSharedRealityHandshakeCancellationClosesCover(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			record := sharedTimeoutAuthenticatedHello(t, key, id)
			rawPipe, client := net.Pipe()
			coverPipe, coverPeer := net.Pipe()
			raw := &sharedTimeoutPipeConn{Conn: rawPipe, closed: make(chan struct{})}
			cover := &sharedTimeoutPipeConn{
				Conn: coverPipe, closed: make(chan struct{}), readStarted: make(chan struct{}),
			}
			var groupCtx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				groupCtx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			} else {
				groupCtx, cancel = context.WithCancel(context.Background())
			}
			dialed := make(chan struct{})
			var dispatched atomic.Bool
			lease := &sharedRealityLease{
				active: true,
				ids:    [][8]byte{id},
				config: &goreality.Config{
					Type: "tcp", Dest: "cover.test:443",
					PrivateKey: key.Bytes(), ServerNames: map[string]bool{"cover.test": true},
					ShortIds: map[[8]byte]bool{id: true}, SessionTicketsDisabled: true,
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						close(dialed)
						return cover, nil
					},
				},
				handler: func(conn stat.Connection) {
					dispatched.Store(true)
					conn.Close()
				},
			}
			group := &sharedRealityGroup{
				direct: true, ctx: groupCtx, cancel: cancel,
				handshakes: make(chan struct{}, 1),
			}
			lease.group = group
			lease.original = group
			group.snapshot.Store(&sharedRealitySnapshot{targets: map[[8]byte]*sharedRealityLease{id: lease}, direct: lease})
			group.handshakes <- struct{}{}
			group.pending.Store(raw, true)
			handled := make(chan struct{})
			written := make(chan struct{})
			forwarded := make(chan struct{})
			var writeErr, forwardErr error
			t.Cleanup(func() {
				cancel()
				raw.Close()
				client.Close()
				cover.Close()
				coverPeer.Close()
				for _, worker := range []struct {
					name string
					done <-chan struct{}
				}{
					{name: "group.handle", done: handled},
					{name: "client writer", done: written},
					{name: "cover reader", done: forwarded},
				} {
					select {
					case <-worker.done:
					case <-time.After(2 * time.Second):
						t.Errorf("%s did not exit after cleanup closed all pipes", worker.name)
					}
				}
			})
			go func() {
				defer close(handled)
				group.handle(raw)
			}()
			go func() {
				defer close(written)
				var n int
				n, writeErr = client.Write(record)
				if writeErr == nil && n != len(record) {
					writeErr = io.ErrShortWrite
				}
			}()
			go func() {
				defer close(forwarded)
				mirrored := make([]byte, len(record))
				_, forwardErr = io.ReadFull(coverPeer, mirrored)
				if forwardErr == nil && !bytes.Equal(mirrored, record) {
					forwardErr = fmt.Errorf("native REALITY did not mirror the original ClientHello")
				}
			}()
			sharedTimeoutWait(t, dialed, "the cover dial")
			sharedTimeoutWait(t, written, "the ClientHello write")
			sharedTimeoutWait(t, forwarded, "the mirrored ClientHello")
			if writeErr != nil || forwardErr != nil {
				t.Fatalf("fixture did not deliver its authenticated hello: write=%v forward=%v", writeErr, forwardErr)
			}
			sharedTimeoutWait(t, cover.readStarted, "the native REALITY cover read")
			select {
			case <-handled:
				t.Fatal("handshake returned before cancellation despite the silent cover")
			default:
			}
			if mode == "cancel" {
				cancel()
			}
			sharedTimeoutWait(t, groupCtx.Done(), "group context termination")
			wantErr := context.Canceled
			if mode == "deadline" {
				wantErr = context.DeadlineExceeded
			}
			if !errors.Is(groupCtx.Err(), wantErr) {
				t.Fatalf("group context ended with %v, want %v", groupCtx.Err(), wantErr)
			}
			select {
			case <-handled:
			case <-time.After(2 * time.Second):
				t.Error("group.handle remained blocked in native REALITY after context termination")
			}
			if got := len(group.handshakes); got != 0 {
				t.Errorf("handshake semaphore retains %d token(s) after cancellation, want 0", got)
			}
			if _, pending := group.pending.Load(raw); pending {
				t.Error("canceled handshake remains in the pending connection registry")
			}
			select {
			case <-cover.closed:
			default:
				t.Error("group cancellation did not close the blocked cover connection")
			}
			sharedTimeoutAssertPeerClosed(t, client, "client")
			sharedTimeoutAssertPeerClosed(t, coverPeer, "cover")
			if dispatched.Load() {
				t.Error("an incomplete handshake reached the logical node callback")
			}
		})
	}
}
