package singbox

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singM "github.com/sagernet/sing/common/metadata"
)

func TestTUICUserSlotsPreserveAuthenticatedSessionIdentity(t *testing.T) {
	const uuidA, uuidB, uuidC = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	previous := []option.TUICUser{{Name: uuidA, UUID: uuidA, Password: uuidA}, {Name: uuidB, UUID: uuidB, Password: uuidB}}
	want := []option.TUICUser{{Name: uuidB, UUID: uuidB, Password: uuidB}, {Name: uuidC, UUID: uuidC, Password: uuidC}}
	slots := stableTUICUsers(previous, want)
	if len(slots) != 3 || slots[0].Name != uuidA || slots[1].Name != uuidB || slots[2].Name != uuidC {
		t.Fatalf("removing or adding users must not reuse a live TUIC authentication index: %+v", slots)
	}
	if slots[0].UUID == uuidA || slots[0].UUID == uuidB || slots[0].UUID == uuidC || slots[0].UUID == "" || slots[0].Password == "" || slots[0].Password == uuidA {
		t.Fatalf("retired slot must carry credentials nobody can present: %+v", slots[0])
	}
	if slots[1] != want[0] || slots[2] != want[1] {
		t.Fatal("active slots changed")
	}
	if previous[0].UUID != uuidA || len(want) != 2 {
		t.Fatal("stable slot preparation mutated its inputs")
	}
	restored := stableTUICUsers(slots, previous)
	if restored[0] != previous[0] || restored[1] != previous[1] || restored[2].Name != uuidC || restored[2].UUID == uuidC {
		t.Fatalf("reactivating users must restore their original slots and disable removed credentials: %+v", restored)
	}
}

func TestRandomUUIDIsVersion4(t *testing.T) {
	id := randomUUID()
	if len(id) != 36 || id[14] != '4' || (id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b') || id == randomUUID() {
		t.Fatalf("unexpected UUID %q", id)
	}
}

func TestConnTrackerTUICUnknownUsersFailClosed(t *testing.T) {
	capture := &hysteria2AuditCapture{}
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"known": 42})
	tracker.SetAuditSink(capture, 7, "tuic")
	for _, identity := range []string{"", "retired"} {
		metadata := adapter.InboundContext{InboundType: "tuic", User: identity, Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
		tcp := &testConn{}
		tracker.RoutedConnection(context.Background(), tcp, metadata, nil, nil)
		udp := &hysteria2TestPacketConn{}
		tracker.RoutedPacketConnection(context.Background(), udp, metadata, nil, nil)
		if !tcp.closed || !udp.closed || len(capture.snapshot()) != 0 {
			t.Fatalf("unknown TUIC user %q was served or audited", identity)
		}
	}
	metadata := adapter.InboundContext{InboundType: "tuic", User: "known", Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
	tracker.RoutedPacketConnection(context.Background(), &hysteria2TestPacketConn{}, metadata, nil, nil)
	if events := capture.snapshot(); len(events) != 1 || events[0].UserID != 42 || events[0].Protocol != "tuic" {
		t.Fatalf("known TUIC user must be audited with its own protocol: %+v", events)
	}
}

// sing-box's copy loop reads the client side (upload) and writes to it
// (download); the count functions handed out by UnwrapPacket* must match.
func TestTrackedPacketConnUnwrapCountersFollowClientDirection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"known": 42})
	metadata := adapter.InboundContext{InboundType: "vless", User: "known", Source: singM.ParseSocksaddr("203.0.113.9:12345"), Destination: singM.ParseSocksaddr("example.org:443")}
	conn := tracker.RoutedPacketConnection(context.Background(), &hysteria2TestPacketConn{}, metadata, nil, nil).(*trackedPacketConn)
	defer conn.Close()
	_, reads := conn.UnwrapPacketReader()
	_, writes := conn.UnwrapPacketWriter()
	for _, count := range reads {
		count(7)
	}
	for _, count := range writes {
		count(2)
	}
	traffic, _, _ := tracker.GetUserTraffic()
	if traffic[42] != [2]int64{7, 2} {
		t.Fatalf("upload/download = %v, want [7 2]", traffic[42])
	}
}
