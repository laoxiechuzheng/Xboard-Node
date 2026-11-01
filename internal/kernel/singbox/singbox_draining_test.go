package singbox

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// A full restart leaves the old box draining for up to drainTimeout. These
// tests cover revokes that arrive after the restart: they must reach the
// draining box too, and it must never regain a credential.

type drainingConn struct {
	conn    *closeFlagConn
	wrapped net.Conn
}

// routeOn injects a live connection of uuid into tracker, the way a stream
// of an authenticated AnyTLS session reaches it.
func routeOn(t *testing.T, tracker *ConnTracker, uuid string) drainingConn {
	t.Helper()
	conn := &closeFlagConn{}
	wrapped := tracker.RoutedConnection(context.Background(), conn, removalMetadata("anytls", uuid), nil, nil)
	// Let the old box finish draining once the test is done.
	t.Cleanup(func() { wrapped.Close() })
	return drainingConn{conn: conn, wrapped: wrapped}
}

// refusedOn reports whether tracker refuses a new stream of uuid. A served
// probe is closed again so it does not hold up the drain or Stop.
func refusedOn(t *testing.T, tracker *ConnTracker, uuid string) bool {
	t.Helper()
	conn := &closeFlagConn{}
	wrapped := tracker.RoutedConnection(context.Background(), conn, removalMetadata("anytls", uuid), nil, nil)
	refused := conn.closed.Load()
	wrapped.Close()
	return refused
}

func drainingTrackers(s *SingBox) map[*ConnTracker]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[*ConnTracker]bool, len(s.draining))
	for tracker := range s.draining {
		out[tracker] = true
	}
	return out
}

// restartKeepingUsers starts an AnyTLS kernel, puts one live connection per
// user on its tracker, and restarts with the same users, so nothing is cut on
// the now draining box.
func restartKeepingUsers(t *testing.T, users []model.UserSpec) (*SingBox, *ConnTracker, map[int]drainingConn) {
	t.Helper()
	instance := New(config.KernelConfig{Type: "singbox", LogLevel: "none"})
	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), users)
	t.Cleanup(instance.Stop)

	oldTracker := instance.connTracker
	conns := make(map[int]drainingConn, len(users))
	for _, u := range users {
		conns[u.ID] = routeOn(t, oldTracker, u.UUID)
	}

	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), users)
	if instance.connTracker == oldTracker {
		t.Fatal("restart did not replace the tracker")
	}
	if !drainingTrackers(instance)[oldTracker] {
		t.Fatal("old tracker is not registered as draining")
	}
	for _, c := range conns {
		stayOpen(t, "kept user's connection on the draining box", c.conn.closed.Load)
	}
	return instance, oldTracker, conns
}

func TestSingBoxDrainingBoxGetsLaterRemoval(t *testing.T) {
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000041"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000042"}
	instance, oldTracker, conns := restartKeepingUsers(t, []model.UserSpec{u, k})

	if n, err := instance.RemoveUsers([]model.UserSpec{u}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	waitClosed(t, "removed user's connection on the draining box", conns[u.ID].conn.closed.Load)
	stayOpen(t, "kept user's connection on the draining box", conns[k.ID].conn.closed.Load)
	if !refusedOn(t, oldTracker, u.UUID) {
		t.Fatal("draining box served a new stream of a user removed after the restart")
	}
	if refusedOn(t, oldTracker, k.UUID) {
		t.Fatal("draining box refused a kept user")
	}
}

func TestSingBoxDrainingBoxGetsLaterUUIDReset(t *testing.T) {
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000043"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000044"}
	instance, oldTracker, conns := restartKeepingUsers(t, []model.UserSpec{u, k})

	reset := model.UserSpec{ID: u.ID, UUID: "00000000-0000-4000-8000-000000000045"}
	if _, _, err := instance.UpdateUsers([]model.UserSpec{reset, k}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	waitClosed(t, "old-UUID connection on the draining box", conns[u.ID].conn.closed.Load)
	stayOpen(t, "kept user's connection on the draining box", conns[k.ID].conn.closed.Load)
	// The draining box never knew the new UUID: it must not learn it now.
	if !refusedOn(t, oldTracker, u.UUID) || !refusedOn(t, oldTracker, reset.UUID) {
		t.Fatal("draining box served the old or the new UUID of a user reset after the restart")
	}
}

func TestSingBoxDrainingBoxGetsForcedCloses(t *testing.T) {
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000046"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000047"}
	instance, _, conns := restartKeepingUsers(t, []model.UserSpec{u, k})

	if err := instance.CloseUserConnections(context.Background(), u.UUID); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "force-closed user's connection on the draining box", conns[u.ID].conn.closed.Load)
	stayOpen(t, "other user's connection on the draining box", conns[k.ID].conn.closed.Load)

	tracked, ok := conns[k.ID].wrapped.(*trackedConn)
	if !ok {
		t.Fatalf("kept user's connection was not tracked: %T", conns[k.ID].wrapped)
	}
	if err := instance.CloseConnection(context.Background(), tracked.connID); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "connection closed by ID on the draining box", conns[k.ID].conn.closed.Load)
}

// A user removed and re-added after the restart is valid again on the new
// box, but the draining box must not take it back.
func TestSingBoxDrainingBoxDoesNotReadmitReaddedUser(t *testing.T) {
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-000000000048"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-000000000049"}
	instance, oldTracker, conns := restartKeepingUsers(t, []model.UserSpec{u, k})

	if _, err := instance.RemoveUsers([]model.UserSpec{u}); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "removed user's connection on the draining box", conns[u.ID].conn.closed.Load)
	if n, err := instance.AddUsers([]model.UserSpec{u}); err != nil || n != 1 {
		t.Fatalf("AddUsers = (%d, %v), want (1, nil)", n, err)
	}
	if !refusedOn(t, oldTracker, u.UUID) {
		t.Fatal("draining box re-admitted a user re-added after the restart")
	}
	if refusedOn(t, instance.connTracker, u.UUID) {
		t.Fatal("current box refused the re-added user")
	}

	// A UUID moved to another user ID is a new credential, too.
	moved := model.UserSpec{ID: 3, UUID: k.UUID}
	if _, _, err := instance.UpdateUsers([]model.UserSpec{u, moved}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	waitClosed(t, "moved UUID's connection on the draining box", conns[k.ID].conn.closed.Load)
	if !refusedOn(t, oldTracker, k.UUID) {
		t.Fatal("draining box served a UUID that moved to another user after the restart")
	}
}

// Restarts in a row leave several boxes draining; a revoke reaches all of
// them, and each leaves the set once it is recycled.
func TestSingBoxRevokesReachEveryDrainingBoxUntilRecycled(t *testing.T) {
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-00000000004a"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-00000000004b"}
	users := []model.UserSpec{u, k}
	instance, first, firstConns := restartKeepingUsers(t, users)
	second := instance.connTracker
	secondConns := map[int]drainingConn{u.ID: routeOn(t, second, u.UUID), k.ID: routeOn(t, second, k.UUID)}
	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), users)
	if draining := drainingTrackers(instance); !draining[first] || !draining[second] || len(draining) != 2 {
		t.Fatalf("draining set = %v, want both replaced trackers", draining)
	}

	if _, err := instance.RemoveUsers([]model.UserSpec{u}); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "removed user's connection on the first draining box", firstConns[u.ID].conn.closed.Load)
	waitClosed(t, "removed user's connection on the second draining box", secondConns[u.ID].conn.closed.Load)
	stayOpen(t, "kept user's connection on the first draining box", firstConns[k.ID].conn.closed.Load)
	stayOpen(t, "kept user's connection on the second draining box", secondConns[k.ID].conn.closed.Load)

	// Once their last connections end, both boxes are recycled and dropped.
	firstConns[k.ID].wrapped.Close()
	secondConns[k.ID].wrapped.Close()
	deadline := time.Now().Add(drainTimeout + 2*time.Second)
	for len(drainingTrackers(instance)) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("draining set still holds %d trackers after recycling", len(drainingTrackers(instance)))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A real AnyTLS session on the draining box: removing its user after the
// restart must cut the stream and the session well before the drain ends.
func TestSingBoxDrainingAnyTLSSessionLosesLaterRemovedUser(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
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
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()

	instance := New(config.KernelConfig{
		Type: "singbox", LogLevel: "none",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	u := model.UserSpec{ID: 1, UUID: "00000000-0000-4000-8000-00000000004c"}
	k := model.UserSpec{ID: 2, UUID: "00000000-0000-4000-8000-00000000004d"}
	oldPort := freeTCPPort(t)
	startAnyTLSRemovalKernel(t, instance, oldPort, []model.UserSpec{u, k})
	t.Cleanup(instance.Stop)

	client := newAnyTLSRemovalClient(t, oldPort, u.UUID)
	stream := client.open(t, echo.Addr())
	if err := anyTLSEcho(stream, "a1"); err != nil {
		t.Fatalf("before restart: %v", err)
	}
	startAnyTLSRemovalKernel(t, instance, freeTCPPort(t), []model.UserSpec{u, k})
	if err := anyTLSEcho(stream, "a2"); err != nil {
		t.Fatalf("kept user's stream on the draining box after restart: %v", err)
	}

	removedAt := time.Now()
	if n, err := instance.RemoveUsers([]model.UserSpec{u}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	if err := anyTLSCut(stream); err != nil {
		t.Fatalf("removed user's stream on the draining box: %v", err)
	}
	waitPeerClosed(t, "removed user's session on the draining box", client.firstConn(t))
	if elapsed := time.Since(removedAt); elapsed >= 2*time.Second {
		t.Fatalf("draining box cut the removed user only after %v", elapsed)
	}
}
