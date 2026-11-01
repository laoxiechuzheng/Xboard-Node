package xray

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func startTCPEcho(t *testing.T) *stdnet.TCPAddr {
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
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return echo.Addr().(*stdnet.TCPAddr)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	reservation, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*stdnet.TCPAddr).Port
	reservation.Close()
	return port
}

func newRemovalTestXray(t *testing.T) *Xray {
	t.Helper()
	x := New(config.KernelConfig{
		Type: "xray", LogLevel: "none",
		// Only the test permits loopback echo destinations.
		CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}},
	})
	t.Cleanup(func() { stopAndRecycle(t, x) })
	return x
}

// stopAndRecycle stops x without leaving an instance draining into later
// tests: a link the inbound never sees end (SS2022's bridge until its idle
// timeout) would keep the stopped instance and its listener alive, and the
// shared REALITY tests count every listener of the process. Revoking all
// users first ends every link, so the stopped instances close at once.
func stopAndRecycle(t *testing.T, x *Xray) {
	t.Helper()
	x.updateDispatcherLimits(nil)
	x.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		x.mu.Lock()
		draining := len(x.drainingLDs)
		x.mu.Unlock()
		if draining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%d stopped xray instances still draining", draining)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func vlessNode(port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port}
}

func isDraining(x *Xray, ld *LimitDispatcher) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	_, ok := x.drainingLDs[ld]
	return ok
}

// Removing the last user stops the kernel. The user's live links must be cut
// and new dispatches refused first, instead of the instance serving them
// while Stop and closeOld drain it.
func TestXrayRemovingLastUserCutsLinksBeforeStop(t *testing.T) {
	target := startTCPEcho(t)
	port := freeTCPPort(t)
	x := newRemovalTestXray(t)
	only := model.UserSpec{ID: 1, UUID: removalUUID1}
	if err := x.Start(vlessNode(port), []model.UserSpec{only}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	conn := vlessDial(t, port, only.UUID, target)
	if err := conn.echo("hello"); err != nil {
		t.Fatalf("before removal: %v", err)
	}
	ld := x.limitDispatcher

	started := time.Now()
	if n, err := x.RemoveUsers([]model.UserSpec{only}); err != nil || n != 1 {
		t.Fatalf("RemoveUsers = (%d, %v), want (1, nil)", n, err)
	}
	// The link was cut before Stop drained, so Stop did not wait it out.
	if elapsed := time.Since(started); elapsed >= drainTimeout {
		t.Fatalf("RemoveUsers took %v: Stop waited for the removed user's link", elapsed)
	}
	conn.waitCut(t, "last removed user")
	if _, err := ld.Dispatch(vlessUserContext(t, only.ID, only.UUID), removalDest); err == nil {
		t.Fatal("stopped instance's dispatcher accepted the removed user")
	}
	waitFor(t, "stopped instance to leave the draining set", func() bool { return !isDraining(x, ld) })
}

// After a restart (config change), the old instance drains its live
// connections for minutes. A user removed during that window must lose them,
// and the old dispatcher must leave the draining set once closed.
func TestXrayRemovalReachesInstanceDrainingAfterRestart(t *testing.T) {
	target := startTCPEcho(t)
	oldPort := freeTCPPort(t)
	x := newRemovalTestXray(t)
	removed := model.UserSpec{ID: 1, UUID: removalUUID1}
	kept := model.UserSpec{ID: 2, UUID: removalUUID2}
	users := []model.UserSpec{removed, kept}
	if err := x.Start(vlessNode(oldPort), users, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	removedConn := vlessDial(t, oldPort, removed.UUID, target)
	keptConn := vlessDial(t, oldPort, kept.UUID, target)
	for name, conn := range map[string]*vlessTestConn{"removed": removedConn, "kept": keptConn} {
		if err := conn.echo("hello"); err != nil {
			t.Fatalf("%s user before restart: %v", name, err)
		}
	}
	oldLD := x.limitDispatcher

	if err := x.Reload(vlessNode(freeTCPPort(t)), users, kernel.TLSCert{}); err != nil {
		t.Fatalf("restart xray: %v", err)
	}
	if !isDraining(x, oldLD) || x.limitDispatcher == oldLD {
		t.Fatal("restart did not hand the old dispatcher to the draining set")
	}
	if err := keptConn.echo("draining"); err != nil {
		t.Fatalf("restart cut a live connection of a kept user: %v", err)
	}

	if _, err := x.RemoveUsers([]model.UserSpec{removed}); err != nil {
		t.Fatal(err)
	}
	removedConn.waitCut(t, "removed user on the draining instance")
	if err := keptConn.echo("still"); err != nil {
		t.Fatalf("kept user on the draining instance disrupted: %v", err)
	}
	if _, err := oldLD.Dispatch(vlessUserContext(t, removed.ID, removed.UUID), removalDest); err == nil {
		t.Fatal("draining dispatcher accepted the removed user")
	}

	if err := x.CloseUserConnections(context.Background(), kept.UUID); err != nil {
		t.Fatal(err)
	}
	keptConn.waitCut(t, "CloseUserConnections on the draining instance")
	waitFor(t, "drained instance to leave the draining set", func() bool { return !isDraining(x, oldLD) })
}

// AddUsers with an existing ID and a new UUID replaces the account: the old
// UUID is cut and refused, the new one works, others are untouched.
func TestXrayAddUsersWithNewUUIDReplacesAccount(t *testing.T) {
	target := startTCPEcho(t)
	port := freeTCPPort(t)
	x := newRemovalTestXray(t)
	user := model.UserSpec{ID: 1, UUID: removalUUID1}
	other := model.UserSpec{ID: 2, UUID: removalUUID2}
	if err := x.Start(vlessNode(port), []model.UserSpec{user, other}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	oldConn := vlessDial(t, port, user.UUID, target)
	otherConn := vlessDial(t, port, other.UUID, target)
	for name, conn := range map[string]*vlessTestConn{"user": oldConn, "other": otherConn} {
		if err := conn.echo("hello"); err != nil {
			t.Fatalf("%s before AddUsers: %v", name, err)
		}
	}

	replaced := model.UserSpec{ID: user.ID, UUID: removalUUID3}
	if n, err := x.AddUsers([]model.UserSpec{replaced}); err != nil || n != 1 {
		t.Fatalf("AddUsers = (%d, %v), want (1, nil)", n, err)
	}
	oldConn.waitCut(t, "old UUID")
	if err := vlessDial(t, port, user.UUID, target).echo("old"); err == nil {
		t.Fatal("old UUID can still connect")
	}
	if err := vlessDial(t, port, replaced.UUID, target).echo("new"); err != nil {
		t.Fatalf("user locked out after AddUsers replaced its UUID: %v", err)
	}
	if err := otherConn.echo("still"); err != nil {
		t.Fatalf("other user disrupted: %v", err)
	}
	x.mu.Lock()
	count := len(x.users)
	x.mu.Unlock()
	if count != 2 {
		t.Fatalf("users after replacement = %d, want 2", count)
	}
}

// Clearing the user set through UpdateUsers is removing the last user: the
// live links are cut and new dispatches refused before the kernel stops, so
// Stop does not wait them out.
func TestXrayUpdateUsersEmptyCutsLinksAndStops(t *testing.T) {
	target := startTCPEcho(t)
	port := freeTCPPort(t)
	x := newRemovalTestXray(t)
	only := model.UserSpec{ID: 1, UUID: removalUUID1}
	if err := x.Start(vlessNode(port), []model.UserSpec{only}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	conn := vlessDial(t, port, only.UUID, target)
	if err := conn.echo("hello"); err != nil {
		t.Fatalf("before clearing: %v", err)
	}
	ld := x.limitDispatcher

	started := time.Now()
	if added, removed, err := x.UpdateUsers([]model.UserSpec{}); err != nil || added != 0 || removed != 1 {
		t.Fatalf("UpdateUsers(empty) = (%d, %d, %v), want (0, 1, nil)", added, removed, err)
	}
	if elapsed := time.Since(started); elapsed >= drainTimeout {
		t.Fatalf("UpdateUsers(empty) took %v: Stop waited for the cleared user's link", elapsed)
	}
	if x.IsRunning() {
		t.Fatal("kernel still running with no users")
	}
	conn.waitCut(t, "cleared user")
	if _, err := ld.Dispatch(vlessUserContext(t, only.ID, only.UUID), removalDest); err == nil {
		t.Fatal("stopped instance's dispatcher accepted the cleared user")
	}
	waitFor(t, "stopped instance to leave the draining set", func() bool { return !isDraining(x, ld) })
}

// httpConnect sends an HTTP CONNECT without credentials and returns the
// status line, or an error when the proxy is not reachable.
func httpConnect(port int, target *stdnet.TCPAddr) (string, error) {
	conn, err := stdnet.DialTimeout("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return "", err
	}
	return bufio.NewReader(conn).ReadString('\n')
}

// xray's http inbound reads an empty account list as "no authentication":
// clearing its users must not leave an instance listening with zero
// accounts (a restart with no users used to do just that).
func TestXrayUpdateUsersEmptyLeavesNoOpenHTTPProxy(t *testing.T) {
	target := startTCPEcho(t)
	port := freeTCPPort(t)
	x := newRemovalTestXray(t)
	node := &model.NodeSpec{Protocol: "http", ListenIP: "127.0.0.1", ServerPort: port}
	if err := x.Start(node, []model.UserSpec{{ID: 1, UUID: removalUUID1}}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	if status, err := httpConnect(port, target); err != nil || strings.Contains(status, " 200 ") {
		t.Fatalf("anonymous CONNECT with a user configured = %q, %v; want a refusal", status, err)
	}

	if added, removed, err := x.UpdateUsers(nil); err != nil || added != 0 || removed != 1 {
		t.Fatalf("UpdateUsers(empty) = (%d, %d, %v), want (0, 1, nil)", added, removed, err)
	}
	if x.IsRunning() {
		t.Fatal("http kernel still running with no users")
	}
	waitFor(t, "the http listener to close", func() bool {
		conn, err := stdnet.DialTimeout("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})
}
