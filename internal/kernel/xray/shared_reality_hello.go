package xray

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const (
	sharedHelloLimit   = 64 * 1024
	sharedRecordLimit  = 16 * 1024
	sharedMLKEMKeySize = 1184
)

type sharedClientHello struct {
	raw        []byte
	random     []byte
	sessionID  []byte
	serverName string
	publicKey  []byte
}

// Short IDs are encrypted in the REALITY ClientHello. Authenticate the same
// transcript as the pinned REALITY library, then replay it unmodified into the
// selected node's original handshake; this is not TLS termination.
func selectSharedRealityTarget(conn net.Conn, targets map[[8]byte]*sharedRealityLease) (net.Conn, *sharedRealityLease, error) {
	replay, hello, err := readSharedClientHello(conn)
	if err != nil {
		return nil, nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(hello.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("shared REALITY invalid key share")
	}
	aad := bytes.Clone(hello.raw)
	clear(aad[39:71])
	tried := make(map[[32]byte]bool)
	for _, target := range targets {
		if !target.config.ServerNames[hello.serverName] {
			continue
		}
		keyID := sha256.Sum256(target.config.PrivateKey)
		if tried[keyID] {
			continue
		}
		tried[keyID] = true
		key, err := ecdh.X25519().NewPrivateKey(target.config.PrivateKey)
		if err != nil {
			continue
		}
		authKey, err := key.ECDH(peer)
		if err != nil {
			continue
		}
		if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")), authKey); err != nil {
			continue
		}
		block, err := aes.NewCipher(authKey)
		if err != nil {
			continue
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plain, err := aead.Open(nil, hello.random[20:], hello.sessionID, aad)
		if err != nil || len(plain) != 16 {
			continue
		}
		var id [8]byte
		copy(id[:], plain[8:])
		selected := targets[id]
		if selected != nil && selected.config.ServerNames[hello.serverName] && bytes.Equal(selected.config.PrivateKey, target.config.PrivateKey) {
			return &sharedReplayConn{Conn: conn, prefix: bytes.NewReader(replay)}, selected, nil
		}
	}
	return nil, nil, fmt.Errorf("shared REALITY ClientHello has no authenticated logical node")
}

func readSharedClientHello(conn io.Reader) ([]byte, *sharedClientHello, error) {
	var replay, handshake []byte
	for records := 0; records < 32; records++ {
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, nil, err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || length == 0 || length > sharedRecordLimit || len(replay)+length+5 > sharedHelloLimit {
			return nil, nil, fmt.Errorf("shared REALITY invalid or oversized TLS record")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, nil, err
		}
		replay = append(replay, header[:]...)
		replay = append(replay, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		length = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || length+4 > sharedHelloLimit || length < 67 {
			return nil, nil, fmt.Errorf("shared REALITY invalid ClientHello length")
		}
		if len(handshake) >= length+4 {
			hello, err := parseSharedClientHello(handshake[:length+4])
			return replay, hello, err
		}
	}
	return nil, nil, fmt.Errorf("shared REALITY too many ClientHello fragments")
}

func parseSharedClientHello(raw []byte) (*sharedClientHello, error) {
	invalid := fmt.Errorf("shared REALITY malformed or unsupported ClientHello")
	if len(raw) < 71 {
		return nil, invalid
	}
	hello := &sharedClientHello{raw: raw}
	input := cryptobyte.String(raw[4:])
	var version uint16
	var session, cipherSuites, compression, extensions cryptobyte.String
	if !input.ReadUint16(&version) || version != 0x0303 || !input.ReadBytes(&hello.random, 32) ||
		!input.ReadUint8LengthPrefixed(&session) || len(session) != 32 ||
		!input.ReadUint16LengthPrefixed(&cipherSuites) || len(cipherSuites) == 0 || len(cipherSuites)%2 != 0 ||
		!input.ReadUint8LengthPrefixed(&compression) || !input.ReadUint16LengthPrefixed(&extensions) || !input.Empty() {
		return nil, invalid
	}
	hello.sessionID = session
	seen := make(map[uint16]bool)
	var hybrid, x25519 []byte
	for !extensions.Empty() {
		var kind uint16
		var extension cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&extension) || seen[kind] {
			return nil, invalid
		}
		seen[kind] = true
		switch kind {
		case 0: // server_name
			var names cryptobyte.String
			if !extension.ReadUint16LengthPrefixed(&names) || !extension.Empty() {
				return nil, invalid
			}
			for !names.Empty() {
				var nameKind uint8
				var name cryptobyte.String
				if !names.ReadUint8(&nameKind) || !names.ReadUint16LengthPrefixed(&name) {
					return nil, invalid
				}
				if nameKind == 0 {
					if hello.serverName != "" || len(name) == 0 {
						return nil, invalid
					}
					hello.serverName = string(name)
				}
			}
		case 51: // key_share: match the pinned REALITY library's ordering
			var shares cryptobyte.String
			if !extension.ReadUint16LengthPrefixed(&shares) || !extension.Empty() {
				return nil, invalid
			}
			for !shares.Empty() {
				var group uint16
				var share cryptobyte.String
				if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&share) || len(share) == 0 {
					return nil, invalid
				}
				if group == 29 && len(share) == 32 {
					if x25519 == nil {
						x25519 = share
					}
				} else if group == 0x11ec && len(share) == sharedMLKEMKeySize+32 && hybrid == nil {
					hybrid = share[sharedMLKEMKeySize:]
				}
			}
		}
	}
	if (x25519 == nil && hybrid == nil) || hello.serverName == "" {
		return nil, invalid
	}
	hello.publicKey = x25519
	if hello.publicKey == nil {
		hello.publicKey = hybrid
	}
	return hello, nil
}

type sharedReplayConn struct {
	net.Conn
	prefixMu sync.Mutex
	prefix   *bytes.Reader
}

func (c *sharedReplayConn) Read(p []byte) (int, error) {
	c.prefixMu.Lock()
	if c.prefix.Len() > 0 {
		n, err := c.prefix.Read(p)
		c.prefixMu.Unlock()
		return n, err
	}
	c.prefixMu.Unlock()
	return c.Conn.Read(p)
}

func (c *sharedReplayConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Conn.Close()
}

// Xray's existing wrapper interface restores the original TCP socket for
// Vision/splice only after the replay prefix has been consumed.
func (*sharedReplayConn) TcpMaskConn()        {}
func (c *sharedReplayConn) RawConn() net.Conn { return c.Conn }
func (c *sharedReplayConn) Splice() bool {
	c.prefixMu.Lock()
	defer c.prefixMu.Unlock()
	return c.prefix.Len() == 0
}
