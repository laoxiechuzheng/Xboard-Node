package singbox

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// closeFlagConn is a net.Conn whose Close may be observed from another
// goroutine (removal closes connections in the background).
type closeFlagConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeFlagConn) Close() error { c.closed.Store(true); return nil }

type closeFlagPacketConn struct {
	N.PacketConn
	closed atomic.Bool
}

func (c *closeFlagPacketConn) Close() error { c.closed.Store(true); return nil }

func removalMetadata(inboundType, user string) adapter.InboundContext {
	return adapter.InboundContext{
		InboundType: inboundType,
		User:        user,
		Source:      singM.ParseSocksaddr("203.0.113.9:12345"),
		Destination: singM.ParseSocksaddr("example.org:443"),
	}
}

func waitClosed(t *testing.T, what string, closed func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !closed() {
		if time.Now().After(deadline) {
			t.Fatalf("%s was not closed", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stayOpen fails if a connection gets closed within a short grace period, so
// background kicks that wrongly target it are caught.
func stayOpen(t *testing.T, what string, closed func() bool) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if closed() {
		t.Fatalf("%s was closed but its user is still current", what)
	}
}

func TestConnTrackerRemovingUserClosesItsLiveConnections(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})

	removedTCP := &closeFlagConn{}
	removedUDP := &closeFlagPacketConn{}
	keptTCP := &closeFlagConn{}
	keptUDP := &closeFlagPacketConn{}
	tracker.RoutedConnection(context.Background(), removedTCP, removalMetadata("anytls", "uuid-1"), nil, nil)
	tracker.RoutedPacketConnection(context.Background(), removedUDP, removalMetadata("vless", "uuid-1"), nil, nil)
	tracker.RoutedConnection(context.Background(), keptTCP, removalMetadata("anytls", "uuid-2"), nil, nil)
	tracker.RoutedPacketConnection(context.Background(), keptUDP, removalMetadata("vless", "uuid-2"), nil, nil)

	tracker.SetUserMap(map[string]int{"uuid-2": 2})

	waitClosed(t, "removed user's TCP connection", removedTCP.closed.Load)
	waitClosed(t, "removed user's UDP connection", removedUDP.closed.Load)
	stayOpen(t, "remaining user's TCP connection", keptTCP.closed.Load)
	stayOpen(t, "remaining user's UDP connection", keptUDP.closed.Load)

	_, alive, count := tracker.GetUserTraffic()
	if alive[1] != nil || count != 2 {
		t.Fatalf("after removal alive=%v count=%d, want only user 2's two connections", alive, count)
	}
	tracker.usersMu.RLock()
	_, indexed := tracker.userConns["uuid-1"]
	tracker.usersMu.RUnlock()
	if indexed {
		t.Fatal("closed connections of the removed user are still indexed")
	}

	// Publishing the same map again must not touch the remaining user.
	tracker.SetUserMap(map[string]int{"uuid-2": 2})
	stayOpen(t, "remaining user's TCP connection", keptTCP.closed.Load)
}

// A subscription reset keeps the user ID but replaces the UUID: connections
// made with the old UUID must go, the new UUID must work.
func TestConnTrackerUUIDResetClosesOldCredentialConnections(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"old-uuid": 7})
	oldConn := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), oldConn, removalMetadata("vless", "old-uuid"), nil, nil)

	tracker.SetUserMap(map[string]int{"new-uuid": 7})
	waitClosed(t, "old-UUID connection", oldConn.closed.Load)

	newConn := &closeFlagConn{}
	wrapped := tracker.RoutedConnection(context.Background(), newConn, removalMetadata("vless", "new-uuid"), nil, nil)
	if _, ok := wrapped.(*trackedConn); !ok || newConn.closed.Load() {
		t.Fatal("connection with the new UUID was refused")
	}
	stale := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), stale, removalMetadata("vless", "old-uuid"), nil, nil)
	if !stale.closed.Load() {
		t.Fatal("new stream with the old UUID was served")
	}
}

// Every inbound that authenticates users must refuse a user that is not in
// the map: for AnyTLS this is a new stream of an already authenticated
// session of a removed user.
func TestConnTrackerRefusesUnknownUserOnEveryAuthenticatingInbound(t *testing.T) {
	capture := &hysteria2AuditCapture{}
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"known": 42})
	tracker.SetAuditSink(capture, 7, "anytls")
	for _, inboundType := range []string{"anytls", "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "mieru", "socks", "http", "naive"} {
		tcp := &closeFlagConn{}
		udp := &closeFlagPacketConn{}
		tracker.RoutedConnection(context.Background(), tcp, removalMetadata(inboundType, "removed"), nil, nil)
		tracker.RoutedPacketConnection(context.Background(), udp, removalMetadata(inboundType, "removed"), nil, nil)
		if !tcp.closed.Load() || !udp.closed.Load() {
			t.Fatalf("%s: unknown user was served (tcp closed=%v, udp closed=%v)", inboundType, tcp.closed.Load(), udp.closed.Load())
		}
	}
	if events := capture.snapshot(); len(events) != 0 {
		t.Fatalf("refused connections were audited: %+v", events)
	}
	if _, _, count := tracker.GetUserTraffic(); count != 0 {
		t.Fatalf("refused connections were counted: %d", count)
	}
}

// Inbounds without user authentication leave metadata.User empty; they must
// keep working exactly as before.
func TestConnTrackerServesConnectionsWithoutUser(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"known": 42})
	for _, inboundType := range []string{"", "vless", "anytls", "shadowsocks", "direct"} {
		tcp := &closeFlagConn{}
		udp := &closeFlagPacketConn{}
		tracker.RoutedConnection(context.Background(), tcp, removalMetadata(inboundType, ""), nil, nil)
		tracker.RoutedPacketConnection(context.Background(), udp, removalMetadata(inboundType, ""), nil, nil)
		if tcp.closed.Load() || udp.closed.Load() {
			t.Fatalf("%q: connection without a user was refused", inboundType)
		}
	}
	// Removing users must not touch connections that have no user.
	anonymous := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), anonymous, removalMetadata("vless", ""), nil, nil)
	tracker.SetUserMap(nil)
	stayOpen(t, "connection without a user", anonymous.closed.Load)
}

func TestConnTrackerCloseByUUIDClosesOnlyThatUser(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	target := &closeFlagConn{}
	targetUDP := &closeFlagPacketConn{}
	other := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), target, removalMetadata("trojan", "uuid-1"), nil, nil)
	tracker.RoutedPacketConnection(context.Background(), targetUDP, removalMetadata("trojan", "uuid-1"), nil, nil)
	tracker.RoutedConnection(context.Background(), other, removalMetadata("trojan", "uuid-2"), nil, nil)

	if n := tracker.CloseByUUID("uuid-1"); n != 2 {
		t.Fatalf("CloseByUUID = %d, want 2", n)
	}
	waitClosed(t, "target TCP connection", target.closed.Load)
	waitClosed(t, "target UDP connection", targetUDP.closed.Load)
	stayOpen(t, "other user's connection", other.closed.Load)
	if n := tracker.CloseByUUID("unknown"); n != 0 {
		t.Fatalf("CloseByUUID(unknown) = %d, want 0", n)
	}
}

// naive authenticates by numeric user ID (buildNaive), not by UUID.
func TestConnTrackerNaiveResolvesUserIDAndClosesOnRemoval(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-5": 5})
	conn := &closeFlagConn{}
	wrapped := tracker.RoutedConnection(context.Background(), conn, removalMetadata("naive", "5"), nil, nil)
	tracked, ok := wrapped.(*trackedConn)
	if !ok || conn.closed.Load() || tracked.userID != 5 {
		t.Fatalf("naive user 5 was not served and attributed: %T closed=%v", wrapped, conn.closed.Load())
	}
	// A reset keeps the naive username (ID) but replaces the UUID.
	tracker.SetUserMap(map[string]int{"uuid-5b": 5})
	waitClosed(t, "naive connection of the old UUID", conn.closed.Load)
	next := tracker.RoutedConnection(context.Background(), &closeFlagConn{}, removalMetadata("naive", "5"), nil, nil)
	if next.(*trackedConn).uuid != "uuid-5b" {
		t.Fatal("naive connection after a reset is not attributed to the new UUID")
	}
}

// A connection resolved just before its user was removed must not be indexed
// after SetUserMap's sweep, or it would survive the removal.
func TestConnTrackerRegistrationRechecksUserMap(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetUserMap(map[string]int{})
	tracker.usersMu.Lock()
	ok := tracker.registerLocked("uuid-1", 1, "sb-x", &trackedConn{})
	tracker.usersMu.Unlock()
	if ok {
		t.Fatal("a connection of a removed user was registered")
	}
}

// slowKickConn stands for a connection whose close blocks (a TLS close on a
// full send buffer): it never unindexes itself, so only the tracker removing
// it from the index can prevent a second kick.
type slowKickConn struct {
	kicks atomic.Int32
}

func (c *slowKickConn) kick() { c.kicks.Add(1) }

func registerSlowKick(t *testing.T, tracker *ConnTracker, uuid string, uid int, connID string) *slowKickConn {
	t.Helper()
	conn := &slowKickConn{}
	tracker.usersMu.Lock()
	ok := tracker.registerLocked(uuid, uid, connID, conn)
	tracker.usersMu.Unlock()
	if !ok {
		t.Fatalf("could not register %s", connID)
	}
	return conn
}

func TestConnTrackerRevokedConnectionIsKickedOnce(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	removed := registerSlowKick(t, tracker, "uuid-1", 1, "sb-1")
	closed := registerSlowKick(t, tracker, "uuid-2", 2, "sb-2")

	tracker.SetUserMap(map[string]int{"uuid-2": 2})
	waitClosed(t, "removed user's connection", func() bool { return removed.kicks.Load() > 0 })
	// Its close is still "running": later updates must not kick it again.
	tracker.SetUserMap(map[string]int{"uuid-2": 2, "uuid-3": 3})
	tracker.SetUserMap(map[string]int{})
	if n := tracker.CloseByUUID("uuid-1"); n != 0 {
		t.Fatalf("CloseByUUID of an already revoked UUID = %d, want 0", n)
	}
	waitClosed(t, "remaining user's connection after its removal", func() bool { return closed.kicks.Load() > 0 })

	tracker.SetUserMap(map[string]int{"uuid-4": 4})
	cut := registerSlowKick(t, tracker, "uuid-4", 4, "sb-4")
	if n := tracker.CloseByUUID("uuid-4"); n != 1 {
		t.Fatalf("CloseByUUID = %d, want 1", n)
	}
	waitClosed(t, "CloseByUUID target", func() bool { return cut.kicks.Load() > 0 })
	if n := tracker.CloseByUUID("uuid-4"); n != 0 {
		t.Fatalf("second CloseByUUID = %d, want 0", n)
	}
	tracker.SetUserMap(map[string]int{})

	time.Sleep(50 * time.Millisecond)
	for name, conn := range map[string]*slowKickConn{"removed": removed, "second removed": closed, "CloseByUUID": cut} {
		if got := conn.kicks.Load(); got != 1 {
			t.Fatalf("%s connection kicked %d times, want exactly 1", name, got)
		}
	}
}

// Only HY2/TUIC bind live sessions to UUID-named slots. On every other
// inbound, a UUID that moved to another user ID (or a user recreated with the
// same UUID) belongs to its current owner and must keep working.
func TestConnTrackerMovedUUIDServesCurrentOwnerOutsideSlotInbounds(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-x": 1})
	before := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), before, removalMetadata("vless", "uuid-x"), nil, nil)

	tracker.SetUserMap(map[string]int{"uuid-x": 2})
	waitClosed(t, "previous owner's connection", before.closed.Load)
	for _, inboundType := range []string{"anytls", "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "mieru"} {
		conn := &closeFlagConn{}
		wrapped := tracker.RoutedConnection(context.Background(), conn, removalMetadata(inboundType, "uuid-x"), nil, nil)
		tracked, ok := wrapped.(*trackedConn)
		if !ok || conn.closed.Load() || tracked.userID != 2 {
			t.Fatalf("%s: moved UUID was not served as its current owner (closed=%v)", inboundType, conn.closed.Load())
		}
		udp := &closeFlagPacketConn{}
		tracker.RoutedPacketConnection(context.Background(), udp, removalMetadata(inboundType, "uuid-x"), nil, nil)
		if udp.closed.Load() {
			t.Fatalf("%s: moved UUID was refused for UDP", inboundType)
		}
	}
	naive := tracker.RoutedConnection(context.Background(), &closeFlagConn{}, removalMetadata("naive", "2"), nil, nil)
	if tracked, ok := naive.(*trackedConn); !ok || tracked.uuid != "uuid-x" {
		t.Fatal("naive user owning a moved UUID was refused")
	}
	for _, inboundType := range []string{"hysteria2", "tuic"} {
		conn := &closeFlagConn{}
		tracker.RoutedConnection(context.Background(), conn, removalMetadata(inboundType, "uuid-x"), nil, nil)
		if !conn.closed.Load() {
			t.Fatalf("%s: a UUID that changed owner was served on a slot inbound", inboundType)
		}
	}

	// Delete, then recreate under a new ID.
	tracker.SetUserMap(map[string]int{})
	tracker.SetUserMap(map[string]int{"uuid-x": 3})
	wrapped := tracker.RoutedConnection(context.Background(), &closeFlagConn{}, removalMetadata("anytls", "uuid-x"), nil, nil)
	if tracked, ok := wrapped.(*trackedConn); !ok || tracked.userID != 3 {
		t.Fatal("recreated user was locked out")
	}
	// Two users sharing a UUID in the current map stay ambiguous everywhere.
	tracker.SetUserMap(buildUserMap([]model.UserSpec{{ID: 3, UUID: "uuid-x"}, {ID: 4, UUID: "uuid-x"}}))
	shared := &closeFlagConn{}
	tracker.RoutedConnection(context.Background(), shared, removalMetadata("anytls", "uuid-x"), nil, nil)
	if !shared.closed.Load() {
		t.Fatal("a UUID shared by two current users was served")
	}
}

// HY2 and TUIC keep users in stable slots named by UUID (a retired slot keeps
// the removed UUID as its name). Adding, removing or resetting other users
// must never cut a remaining user's live connections there; the QUIC
// integration test (with_quic) drives the same updates through real clients.
func TestConnTrackerSlotInboundsKeepRemainingUsersConnections(t *testing.T) {
	for _, inboundType := range []string{"hysteria2", "tuic"} {
		tracker := NewConnTracker(0)
		tracker.SetUserMap(map[string]int{"uuid-a": 1, "uuid-b": 2, "uuid-r": 3})
		keptTCP, keptUDP := &closeFlagConn{}, &closeFlagPacketConn{}
		removedTCP, resetTCP := &closeFlagConn{}, &closeFlagConn{}
		tracker.RoutedConnection(context.Background(), keptTCP, removalMetadata(inboundType, "uuid-b"), nil, nil)
		tracker.RoutedPacketConnection(context.Background(), keptUDP, removalMetadata(inboundType, "uuid-b"), nil, nil)
		tracker.RoutedConnection(context.Background(), removedTCP, removalMetadata(inboundType, "uuid-a"), nil, nil)
		tracker.RoutedConnection(context.Background(), resetTCP, removalMetadata(inboundType, "uuid-r"), nil, nil)

		for _, step := range []struct {
			name  string
			users map[string]int
		}{
			{"add", map[string]int{"uuid-a": 1, "uuid-b": 2, "uuid-r": 3, "uuid-c": 4}},
			{"same map", map[string]int{"uuid-a": 1, "uuid-b": 2, "uuid-r": 3, "uuid-c": 4}},
			{"remove", map[string]int{"uuid-b": 2, "uuid-r": 3, "uuid-c": 4}},
			{"reset", map[string]int{"uuid-b": 2, "uuid-r2": 3, "uuid-c": 4}},
		} {
			tracker.SetUserMap(step.users)
			stayOpen(t, inboundType+" kept TCP after "+step.name, keptTCP.closed.Load)
			stayOpen(t, inboundType+" kept UDP after "+step.name, keptUDP.closed.Load)
		}
		waitClosed(t, inboundType+" removed user's connection", removedTCP.closed.Load)
		waitClosed(t, inboundType+" old UUID's connection", resetTCP.closed.Load)

		next := &closeFlagConn{}
		wrapped := tracker.RoutedConnection(context.Background(), next, removalMetadata(inboundType, "uuid-b"), nil, nil)
		if tracked, ok := wrapped.(*trackedConn); !ok || next.closed.Load() || tracked.userID != 2 {
			t.Fatalf("%s: a new stream of the remaining user was refused", inboundType)
		}
	}
}

// RoutedConnection racing a removal: whichever side wins, no connection of
// the removed user may stay open, and the remaining user's must.
func TestConnTrackerConcurrentRoutingAndRemoval(t *testing.T) {
	for round := 0; round < 20; round++ {
		tracker := NewConnTracker(0)
		tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
		var (
			mu      sync.Mutex
			removed []*closeFlagConn
			kept    []*closeFlagConn
			wg      sync.WaitGroup
		)
		start := make(chan struct{})
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				<-start
				for i := 0; i < 25; i++ {
					conn := &closeFlagConn{}
					user := "uuid-1"
					if worker%2 == 1 {
						user = "uuid-2"
					}
					tracker.RoutedConnection(context.Background(), conn, removalMetadata("anytls", user), nil, nil)
					mu.Lock()
					if user == "uuid-1" {
						removed = append(removed, conn)
					} else {
						kept = append(kept, conn)
					}
					mu.Unlock()
				}
			}(worker)
		}
		close(start)
		tracker.SetUserMap(map[string]int{"uuid-2": 2})
		wg.Wait()

		for i, conn := range removed {
			waitClosed(t, "removed user's connection "+strconv.Itoa(i), conn.closed.Load)
		}
		time.Sleep(20 * time.Millisecond)
		for _, conn := range kept {
			if conn.closed.Load() {
				t.Fatal("remaining user's connection was closed")
			}
		}
		tracker.usersMu.RLock()
		_, indexed := tracker.userConns["uuid-1"]
		tracker.usersMu.RUnlock()
		if indexed {
			t.Fatal("a connection of the removed user is still indexed")
		}
	}
}
