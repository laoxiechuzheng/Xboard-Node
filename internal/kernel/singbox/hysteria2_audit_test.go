package singbox

import (
	"context"
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type hysteria2AuditCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *hysteria2AuditCapture) Record(event audit.Event) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *hysteria2AuditCapture) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Event(nil), c.events...)
}

type hysteria2TestPacketConn struct {
	N.PacketConn
	closed bool
}

func (c *hysteria2TestPacketConn) Close() error { c.closed = true; return nil }

// These tests simulate router callbacks; the with_quic integration test sends
// real authenticated HY2 traffic through the native inbound and router.
func TestConnTrackerHysteria2AuditMetadata(t *testing.T) {
	for _, tc := range []struct {
		network string
		source  string
		target  string
		wantIP  string
	}{
		{"tcp", "203.0.113.9:12345", "example.org:443", "203.0.113.9"},
		{"udp", "[2001:db8::9]:54321", "[2001:db8::53]:53", "2001:db8::9"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			capture := &hysteria2AuditCapture{}
			tracker := NewConnTracker(0)
			tracker.SetUserMap(map[string]int{"user-b": 42})
			tracker.SetAuditSink(capture, 7, "hysteria")
			metadata := adapter.InboundContext{InboundType: "hysteria2", User: "user-b", Source: singM.ParseSocksaddr(tc.source), Destination: singM.ParseSocksaddr(tc.target)}
			if tc.network == "tcp" {
				conn := tracker.RoutedConnection(context.Background(), &testConn{}, metadata, nil, nil)
				defer conn.Close()
			} else {
				conn := tracker.RoutedPacketConnection(context.Background(), &hysteria2TestPacketConn{}, metadata, nil, nil)
				defer conn.Close()
			}
			events := capture.snapshot()
			if len(events) != 1 {
				t.Fatalf("events = %d, want 1", len(events))
			}
			event := events[0]
			if event.UserID != 42 || event.UUID != "user-b" || event.NodeID != 7 || event.Core != "singbox" || event.Protocol != "hysteria2" || event.Network != tc.network || event.SourceIP != tc.wantIP || event.Target != tc.target {
				t.Fatalf("incorrect HY2 audit metadata: %+v", event)
			}
		})
	}
}

func TestConnTrackerHysteria2UnknownUsersCannotBecomeAnotherAccount(t *testing.T) {
	for _, identity := range []string{"", "unknown", "0", "invalid", "obfs-test-password", "removed"} {
		t.Run(identity, func(t *testing.T) {
			capture := &hysteria2AuditCapture{}
			tracker := NewConnTracker(0)
			tracker.SetUserMap(map[string]int{"known": 42, "": 43, "invalid": 0})
			tracker.SetAuditSink(capture, 7, "hysteria2")
			metadata := adapter.InboundContext{InboundType: "hysteria2", User: identity, Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
			tcp := &testConn{}
			tracker.RoutedConnection(context.Background(), tcp, metadata, nil, nil)
			udp := &hysteria2TestPacketConn{}
			tracker.RoutedPacketConnection(context.Background(), udp, metadata, nil, nil)
			if len(capture.snapshot()) != 0 || tracker.ActiveCount() != 0 {
				t.Fatal("unidentified HY2 connection was attributed to an account")
			}
			if !tcp.closed || !udp.closed {
				t.Fatal("unidentified HY2 connection must fail closed")
			}
		})
	}
}

func TestConnTrackerHysteria2MapSnapshotAndAccountReuse(t *testing.T) {
	capture := &hysteria2AuditCapture{}
	tracker := NewConnTracker(0)
	users := map[string]int{"user-a": 42, "user-b": 43}
	tracker.SetUserMap(users)
	tracker.SetAuditSink(capture, 7, "hysteria2")
	users["user-a"] = 43
	metadata := adapter.InboundContext{InboundType: "hysteria2", User: "user-a", Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
	old := tracker.RoutedConnection(context.Background(), &testConn{}, metadata, nil, nil)
	defer old.Close()
	if events := capture.snapshot(); len(events) != 1 || events[0].UserID != 42 {
		t.Fatal("caller mutation changed the authentication snapshot")
	}
	tracker.SetUserMap(map[string]int{"user-b": 43})
	tracker.SetUserMap(map[string]int{"user-a": 43, "user-b": 43})
	newConn := &testConn{}
	tracker.RoutedConnection(context.Background(), newConn, metadata, nil, nil)
	if !newConn.closed || len(capture.snapshot()) != 1 {
		t.Fatal("a retired UUID was reassigned to a different account")
	}
	if _, err := old.Write([]byte("old-session")); err != nil {
		t.Fatal(err)
	}
	traffic, _, _ := tracker.GetUserTraffic()
	if traffic[42][1] != 11 || traffic[43][1] != 0 {
		t.Fatal("an already tracked connection changed account after a hot update")
	}
}

func TestConnTrackerHysteria2UDPCountersMatchTCPDirection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"known": 42})
	metadata := adapter.InboundContext{InboundType: "hysteria2", User: "known", Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
	conn := tracker.RoutedPacketConnection(context.Background(), &hysteria2TestPacketConn{}, metadata, nil, nil).(*trackedPacketConn)
	defer conn.Close()
	_, reads := conn.UnwrapPacketReader()
	_, writes := conn.UnwrapPacketWriter()
	for _, count := range reads {
		count(5)
	}
	for _, count := range writes {
		count(3)
	}
	traffic, _, _ := tracker.GetUserTraffic()
	if traffic[42] != [2]int64{5, 3} {
		t.Fatalf("UDP upload/download = %v, want [5 3]", traffic[42])
	}
}
