package xray

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	goreality "github.com/xtls/reality"
	"golang.org/x/crypto/cryptobyte"
)

func TestSharedRealityReplaySpliceConcurrentWithRead(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	peer.Close()
	prefix := bytes.Repeat([]byte("client-hello-replay"), 2048)
	conn := &sharedReplayConn{Conn: raw, prefix: bytes.NewReader(prefix)}
	done := make(chan error, 1)
	go func() {
		read, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(read, prefix) {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	for {
		conn.Splice()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if !conn.Splice() || conn.RawConn() != raw {
				t.Fatal("consumed replay did not restore the original socket for splice")
			}
			return
		default:
			runtime.Gosched()
		}
	}
}

func sharedHelloTestFixture(t testing.TB, optionalX25519 bool) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303)
		b.AddBytes(bytes.Repeat([]byte{7}, 32))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("cover.test")) })
				})
			})
			b.AddUint16(51)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x11ec)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(make([]byte, sharedMLKEMKeySize))
						b.AddBytes(bytes.Repeat([]byte{9}, 32))
					})
					if optionalX25519 {
						b.AddUint16(29)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(bytes.Repeat([]byte{11}, 32)) })
					}
				})
			})
		})
	})
	raw, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSharedRealityHelloFragmentsReplayUnchanged(t *testing.T) {
	for _, optional := range []bool{false, true} {
		raw := sharedHelloTestFixture(t, optional)
		var records []byte
		for offset := 0; offset < len(raw); {
			end := min(offset+71, len(raw))
			length := end - offset
			records = append(records, 22, 3, 1, byte(length>>8), byte(length))
			records = append(records, raw[offset:end]...)
			offset = end
		}
		replay, hello, err := readSharedClientHello(bytes.NewReader(records))
		if err != nil {
			t.Fatal(err)
		}
		wantKeyByte := byte(9)
		if optional {
			wantKeyByte = 11
		}
		if !bytes.Equal(replay, records) || !bytes.Equal(hello.raw, raw) || hello.serverName != "cover.test" || !bytes.Equal(hello.publicKey, bytes.Repeat([]byte{wantKeyByte}, 32)) {
			t.Fatal("fragmented ClientHello changed its transcript, replay or the pinned key-share selection")
		}
	}
}

func TestSharedRealityHelloRejectsInvalidRecordBeforePayloadRead(t *testing.T) {
	for _, header := range [][]byte{
		{23, 3, 1, 0, 1}, {22, 2, 1, 0, 1}, {22, 3, 1, 0, 0}, {22, 3, 1, 0xff, 0xff},
	} {
		_, _, err := readSharedClientHello(bytes.NewReader(header))
		if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
			t.Fatalf("invalid record was not rejected before reading its payload: %v", err)
		}
	}
}

func sharedHelloKeySharesFixture(t testing.TB, shares ...utls.KeyShare) []byte {
	t.Helper()
	hello := &utls.PubClientHelloMsg{
		Vers:               0x0303,
		Random:             bytes.Repeat([]byte{7}, 32),
		SessionId:          bytes.Repeat([]byte{13}, 32),
		CipherSuites:       []uint16{0x1301},
		CompressionMethods: []uint8{0},
		ServerName:         "cover.test",
		SupportedCurves:    []utls.CurveID{29, 0x11ec},
		SupportedVersions:  []uint16{0x0304},
		KeyShares:          shares,
	}
	raw, err := hello.Marshal()
	if err != nil {
		t.Fatalf("marshal key-share fixture: %v", err)
	}
	return raw
}

func TestSharedRealityHelloKeySharePriority(t *testing.T) {
	x25519 := utls.KeyShare{Group: 29, Data: bytes.Repeat([]byte{11}, 32)}
	secondX25519 := utls.KeyShare{Group: 29, Data: bytes.Repeat([]byte{17}, 32)}
	// The pinned REALITY module takes the final 32 bytes of a 1216-byte share.
	hybrid := utls.KeyShare{Group: 0x11ec, Data: append(make([]byte, 1184), bytes.Repeat([]byte{9}, 32)...)}
	secondHybrid := utls.KeyShare{Group: 0x11ec, Data: append(make([]byte, 1184), bytes.Repeat([]byte{19}, 32)...)}
	grease := utls.KeyShare{Group: 0x0a0a, Data: []byte{0}}
	shortX25519 := utls.KeyShare{Group: 29, Data: bytes.Repeat([]byte{15}, 31)}
	shortHybrid := utls.KeyShare{Group: 0x11ec, Data: make([]byte, 1215)}
	for _, tc := range []struct {
		name     string
		shares   []utls.KeyShare
		wantByte byte
	}{
		{name: "x25519_only", shares: []utls.KeyShare{x25519}, wantByte: 11},
		{name: "x25519_before_hybrid", shares: []utls.KeyShare{x25519, hybrid}, wantByte: 11},
		{name: "hybrid_before_x25519", shares: []utls.KeyShare{hybrid, x25519}, wantByte: 11},
		{name: "hybrid_fallback", shares: []utls.KeyShare{hybrid}, wantByte: 9},
		{name: "grease_before_x25519", shares: []utls.KeyShare{grease, x25519}, wantByte: 11},
		{name: "invalid_x25519_length_falls_back", shares: []utls.KeyShare{shortX25519, hybrid}, wantByte: 9},
		{name: "first_x25519_wins", shares: []utls.KeyShare{x25519, secondX25519}, wantByte: 11},
		{name: "first_x25519_after_hybrid_wins", shares: []utls.KeyShare{hybrid, x25519, secondX25519}, wantByte: 11},
		{name: "invalid_x25519_before_first_valid", shares: []utls.KeyShare{shortX25519, x25519, secondX25519, hybrid}, wantByte: 11},
		{name: "duplicate_hybrid_before_x25519", shares: []utls.KeyShare{hybrid, secondHybrid, x25519}, wantByte: 11},
		{name: "first_hybrid_fallback_wins", shares: []utls.KeyShare{hybrid, secondHybrid}, wantByte: 9},
		{name: "invalid_hybrid_before_first_usable", shares: []utls.KeyShare{shortHybrid, hybrid, secondHybrid}, wantByte: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := sharedHelloKeySharesFixture(t, tc.shares...)
			original := bytes.Clone(raw)
			hello, err := parseSharedClientHello(raw)
			if err != nil {
				t.Fatalf("valid %s ClientHello rejected: %v", tc.name, err)
			}
			if !bytes.Equal(hello.publicKey, bytes.Repeat([]byte{tc.wantByte}, 32)) {
				t.Fatalf("selected key share = %x, want 32 bytes of %02x", hello.publicKey, tc.wantByte)
			}
			if hello.serverName != "cover.test" || !bytes.Equal(hello.random, bytes.Repeat([]byte{7}, 32)) ||
				!bytes.Equal(hello.sessionID, bytes.Repeat([]byte{13}, 32)) {
				t.Fatalf("parsed ClientHello fields changed: SNI=%q random=%x session=%x", hello.serverName, hello.random, hello.sessionID)
			}
			if !bytes.Equal(raw, original) || !bytes.Equal(hello.raw, original) {
				t.Fatal("key-share selection mutated the REALITY authentication transcript")
			}
		})
	}
}

func TestSharedRealityHelloRejectsEmptyTrailingKeyShare(t *testing.T) {
	// REALITY unmarshals the whole key-share list before choosing an ECDH key.
	raw := sharedHelloKeySharesFixture(t,
		utls.KeyShare{Group: 0x11ec, Data: append(make([]byte, 1184), bytes.Repeat([]byte{9}, 32)...)},
		utls.KeyShare{Group: 29, Data: bytes.Repeat([]byte{11}, 32)},
		utls.KeyShare{Group: 0x0a0a},
	)
	if _, err := parseSharedClientHello(raw); err == nil {
		t.Fatal("an empty trailing key share was ignored after selecting a usable key")
	}
}

func TestSharedRealityHelloRejectsMissingUsableKeyShare(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shares []utls.KeyShare
	}{
		{name: "empty"},
		{name: "grease_only", shares: []utls.KeyShare{{Group: 0x0a0a, Data: []byte{0}}}},
		{name: "short_x25519", shares: []utls.KeyShare{{Group: 29, Data: make([]byte, 31)}}},
		{name: "short_hybrid", shares: []utls.KeyShare{{Group: 0x11ec, Data: make([]byte, 1215)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSharedClientHello(sharedHelloKeySharesFixture(t, tc.shares...)); err == nil {
				t.Fatal("ClientHello without a usable X25519 or hybrid key share was accepted")
			}
		})
	}
}

func TestSharedRealityHelloChrome120(t *testing.T) {
	rawConn, peer := net.Pipe()
	t.Cleanup(func() {
		rawConn.Close()
		peer.Close()
	})
	client := utls.UClient(rawConn, &utls.Config{ServerName: "cover.test"}, utls.HelloChrome_120)
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatalf("build pinned Chrome 120 fingerprint: %v", err)
	}
	clientHello := client.HandshakeState.Hello
	var wantKey []byte
	for _, share := range clientHello.KeyShares {
		if share.Group == 0x11ec {
			t.Fatal("Chrome 120 fixture unexpectedly contains an ML-KEM hybrid key share")
		}
		if share.Group == 29 && len(share.Data) == 32 {
			wantKey = bytes.Clone(share.Data)
		}
	}
	if wantKey == nil || len(clientHello.SessionId) != 32 {
		t.Fatal("Chrome 120 fixture lacks the X25519 key or 32-byte REALITY session ID")
	}
	original := bytes.Clone(clientHello.Raw)
	record := append([]byte{22, 3, 1, byte(len(original) >> 8), byte(len(original))}, original...)
	replay, hello, err := readSharedClientHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("pinned Chrome 120 ClientHello rejected by the shared entry: %v", err)
	}
	if !bytes.Equal(hello.publicKey, wantKey) || hello.serverName != "cover.test" ||
		!bytes.Equal(hello.random, clientHello.Random) || !bytes.Equal(hello.sessionID, clientHello.SessionId) {
		t.Fatal("Chrome 120 parsing changed its X25519 key, SNI, random or session ID")
	}
	if !bytes.Equal(replay, record) || !bytes.Equal(hello.raw, original) || !bytes.Equal(clientHello.Raw, original) {
		t.Fatal("Chrome 120 ClientHello or TLS replay was modified")
	}
}

func TestSharedRealityHelloAuthenticatedChrome120(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	unknownID := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	target := &sharedRealityLease{config: &goreality.Config{
		PrivateKey: serverKey.Bytes(), ServerNames: map[string]bool{"cover.test": true},
		ShortIds: map[[8]byte]bool{id: true},
	}}
	other := &sharedRealityLease{config: &goreality.Config{
		PrivateKey: otherKey.Bytes(), ServerNames: map[string]bool{"cover.test": true},
		ShortIds: map[[8]byte]bool{otherID: true},
	}}
	targets := map[[8]byte]*sharedRealityLease{id: target, otherID: other}
	record := sharedTimeoutAuthenticatedHello(t, serverKey, id)
	tampered := bytes.Clone(record)
	tampered[5+39] ^= 1
	for _, tc := range []struct {
		name       string
		record     []byte
		wantReject bool
	}{
		{name: "registered_short_id", record: record},
		{name: "unknown_short_id", record: sharedTimeoutAuthenticatedHello(t, serverKey, unknownID), wantReject: true},
		{name: "wrong_key_for_short_id", record: sharedTimeoutAuthenticatedHello(t, otherKey, id), wantReject: true},
		{name: "tampered_session_id", record: tampered, wantReject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, client := net.Pipe()
			written := make(chan struct{})
			var writeErr error
			t.Cleanup(func() {
				raw.Close()
				client.Close()
				select {
				case <-written:
				case <-time.After(2 * time.Second):
					t.Error("Chrome 120 writer did not exit after cleanup closed the pipe")
				}
			})
			payload := []byte("post-client-hello-payload")
			go func() {
				defer close(written)
				wire := append(bytes.Clone(tc.record), payload...)
				var n int
				n, writeErr = client.Write(wire)
				if writeErr == nil && n != len(wire) {
					writeErr = io.ErrShortWrite
				}
			}()
			if err := raw.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			input, selected, err := selectSharedRealityTarget(raw, targets)
			if tc.wantReject {
				if err == nil || input != nil || selected != nil {
					t.Fatalf("invalid authenticated Chrome 120 hello selected a node: input=%T target=%p err=%v", input, selected, err)
				}
				return
			}
			if err != nil || selected != target {
				t.Fatalf("authenticated Chrome 120 selected target %p with err=%v, want %p", selected, err, target)
			}
			if input.LocalAddr().String() != raw.LocalAddr().String() || input.RemoteAddr().String() != raw.RemoteAddr().String() {
				t.Fatal("shared entry replaced the original connection addresses")
			}
			replay := make([]byte, len(tc.record))
			if _, err := io.ReadFull(input, replay); err != nil || !bytes.Equal(replay, tc.record) {
				t.Fatalf("authenticated ClientHello replay changed: err=%v", err)
			}
			gotPayload := make([]byte, len(payload))
			if _, err := io.ReadFull(input, gotPayload); err != nil || !bytes.Equal(gotPayload, payload) {
				t.Fatalf("live socket bytes following the replay changed: got=%q err=%v", gotPayload, err)
			}
			sharedTimeoutWait(t, written, "the authenticated Chrome 120 writer")
			if writeErr != nil {
				t.Fatalf("write authenticated Chrome 120 hello: %v", writeErr)
			}
		})
	}
}

func FuzzParseSharedRealityClientHello(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 71))
	f.Add(sharedHelloTestFixture(f, false))
	f.Add(sharedHelloTestFixture(f, true))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > sharedHelloLimit {
			return
		}
		parseSharedClientHello(raw)
	})
}
