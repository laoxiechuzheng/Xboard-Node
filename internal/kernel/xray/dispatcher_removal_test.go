package xray

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// fakeInnerDispatcher stands in for xray's DefaultDispatcher: Dispatch hands
// out pipe links like the real one, DispatchLink blocks for the life of the
// connection (until its context ends) like the real synchronous path.
type fakeInnerDispatcher struct {
	dispatched   atomic.Int32
	lastDownlink atomic.Pointer[pipe.Writer] // outbound end of the last Dispatch link's downlink
}

func (*fakeInnerDispatcher) Type() interface{} { return nil }
func (*fakeInnerDispatcher) Start() error      { return nil }
func (*fakeInnerDispatcher) Close() error      { return nil }

func (f *fakeInnerDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	f.dispatched.Add(1)
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	_ = uplinkReader
	f.lastDownlink.Store(downlinkWriter)
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func (f *fakeInnerDispatcher) DispatchLink(ctx context.Context, _ net.Destination, _ *transport.Link) error {
	f.dispatched.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func newRemovalTestDispatcher() (*LimitDispatcher, *fakeInnerDispatcher) {
	inner := &fakeInnerDispatcher{}
	ld := newTestDispatcher()
	ld.inner = inner
	ld.innerDisp = inner
	return ld, inner
}

func vlessUserContext(t *testing.T, userID int, id string) context.Context {
	t.Helper()
	parsed, err := uuid.ParseString(id)
	if err != nil {
		t.Fatal(err)
	}
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.9"), 40000),
		User: &protocol.MemoryUser{
			Email:   userEmail(userID),
			Account: &vless.MemoryAccount{ID: protocol.NewID(parsed)},
		},
	})
}

var removalDest = net.TCPDestination(net.ParseAddress("198.51.100.1"), 443)

func installUsers(ld *LimitDispatcher, users ...model.UserSpec) {
	installNodeUsers(ld, nil, users...)
}

// installNodeUsers installs users the way configureDispatcher does for node.
func installNodeUsers(ld *LimitDispatcher, node *model.NodeSpec, users ...model.UserSpec) {
	credentialOf := credentialFor(node)
	ld.setCredentialFunc(credentialOf)
	ld.UpdateLimits(dispatcherUserSet(users, credentialOf, false))
}

// linkInterrupted reports whether the link's uplink pipe was torn down.
func linkInterrupted(link *transport.Link) bool {
	b := buf.New()
	b.WriteString("x") // the pipe ignores empty writes
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil
}

const (
	removalUUID1 = "11111111-1111-4111-8111-111111111111"
	removalUUID2 = "22222222-2222-4222-8222-222222222222"
	removalUUID3 = "33333333-3333-4333-8333-333333333333"
)

func TestLimitDispatcherRefusesUnknownUserOnlyAfterUserSetIsInstalled(t *testing.T) {
	ld, inner := newRemovalTestDispatcher()

	// Startup: nothing configured yet, nobody is rejected.
	if _, err := ld.Dispatch(vlessUserContext(t, 9, removalUUID3), removalDest); err != nil {
		t.Fatalf("dispatch before the user set was installed: %v", err)
	}

	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
	if _, err := ld.Dispatch(vlessUserContext(t, 9, removalUUID3), removalDest); err == nil {
		t.Fatal("dispatch of a user outside the installed set was accepted")
	}
	ctx, cancel := context.WithTimeout(vlessUserContext(t, 9, removalUUID3), time.Second)
	defer cancel()
	if err := ld.DispatchLink(ctx, removalDest, &transport.Link{Reader: nopReader{}, Writer: buf.Discard}); err == nil || err == context.DeadlineExceeded {
		t.Fatalf("DispatchLink of a user outside the installed set = %v, want refusal", err)
	}
	if got := inner.dispatched.Load(); got != 1 {
		t.Fatalf("inner dispatcher called %d times, want 1 (refused dispatches must not reach it)", got)
	}
	if _, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest); err != nil {
		t.Fatalf("current user refused: %v", err)
	}
	// Anonymous dispatches (no authenticated user) keep working.
	if _, err := ld.Dispatch(context.Background(), removalDest); err != nil {
		t.Fatalf("anonymous dispatch refused: %v", err)
	}
	if ld.connCount.Load() != 1 {
		t.Fatalf("connCount = %d, want 1 (refused and anonymous dispatches are not tracked)", ld.connCount.Load())
	}
}

func TestLimitDispatcherRemovalInterruptsOnlyThatUsersLinks(t *testing.T) {
	ld, _ := newRemovalTestDispatcher()
	user1 := model.UserSpec{ID: 1, UUID: removalUUID1}
	user2 := model.UserSpec{ID: 2, UUID: removalUUID2}
	installUsers(ld, user1, user2)

	removedLink, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
	if err != nil {
		t.Fatal(err)
	}
	keptLink, err := ld.Dispatch(vlessUserContext(t, 2, removalUUID2), removalDest)
	if err != nil {
		t.Fatal(err)
	}
	// A Vision/REALITY style link runs synchronously inside DispatchLink.
	linkDone := make(chan error, 1)
	go func() {
		linkDone <- ld.DispatchLink(vlessUserContext(t, 1, removalUUID1), removalDest, &transport.Link{Reader: nopReader{}, Writer: buf.Discard})
	}()
	keptDone := make(chan error, 1)
	go func() {
		keptDone <- ld.DispatchLink(vlessUserContext(t, 2, removalUUID2), removalDest, &transport.Link{Reader: nopReader{}, Writer: buf.Discard})
	}()
	waitFor(t, "four tracked links", func() bool { return ld.connCount.Load() == 4 })

	installUsers(ld, user2)

	if !linkInterrupted(removedLink) {
		t.Fatal("removed user's pipe link is still writable")
	}
	select {
	case <-linkDone:
	case <-time.After(2 * time.Second):
		t.Fatal("removed user's DispatchLink connection was not cancelled")
	}
	if linkInterrupted(keptLink) {
		t.Fatal("remaining user's pipe link was interrupted")
	}
	select {
	case err := <-keptDone:
		t.Fatalf("remaining user's DispatchLink connection ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if got := ld.connCount.Load(); got != 2 {
		t.Fatalf("connCount after removal = %d, want 2", got)
	}
	ld.mu.RLock()
	_, indexed := ld.links[userEmail(1)]
	ld.mu.RUnlock()
	if indexed {
		t.Fatal("removed user's links are still indexed")
	}
	// New streams of the removed user's (mux) session are refused.
	if _, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest); err == nil {
		t.Fatal("removed user's new sub-stream was accepted")
	}
}

// The stats email is keyed by user ID, so a UUID reset keeps it: the session
// credential must decide.
func TestLimitDispatcherUUIDResetCutsOldCredentialOnly(t *testing.T) {
	ld, _ := newRemovalTestDispatcher()
	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
	oldLink, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
	if err != nil {
		t.Fatal(err)
	}

	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID3})
	if !linkInterrupted(oldLink) {
		t.Fatal("link of the old UUID survived the reset")
	}
	if _, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest); err == nil {
		t.Fatal("new sub-stream of a session authenticated with the old UUID was accepted")
	}
	newLink, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID3), removalDest)
	if err != nil {
		t.Fatalf("new UUID refused: %v", err)
	}
	// Re-installing the same set must not cut the new UUID's link.
	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID3})
	if linkInterrupted(newLink) {
		t.Fatal("link of the current UUID was interrupted")
	}
}

func TestLimitDispatcherCloseUUID(t *testing.T) {
	ld, _ := newRemovalTestDispatcher()
	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1}, model.UserSpec{ID: 2, UUID: removalUUID2})
	target, _ := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
	other, _ := ld.Dispatch(vlessUserContext(t, 2, removalUUID2), removalDest)
	if n := ld.CloseUUID(removalUUID1); n != 1 {
		t.Fatalf("CloseUUID = %d, want 1", n)
	}
	if !linkInterrupted(target) || linkInterrupted(other) {
		t.Fatal("CloseUUID must interrupt exactly the target user's links")
	}
	// The user stays registered and may reconnect.
	if _, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest); err != nil {
		t.Fatalf("CloseUUID must not ban the user: %v", err)
	}
}

// Retired shared REALITY generations keep serving live connections while they
// drain; a user removed afterwards must lose those too.
func TestXrayUserRemovalReachesDrainingGenerations(t *testing.T) {
	current, _ := newRemovalTestDispatcher()
	retired, _ := newRemovalTestDispatcher()
	user1 := model.UserSpec{ID: 1, UUID: removalUUID1}
	user2 := model.UserSpec{ID: 2, UUID: removalUUID2}
	installUsers(current, user1, user2)
	installUsers(retired, user1, user2)
	retiredRemoved, _ := retired.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
	retiredKept, _ := retired.Dispatch(vlessUserContext(t, 2, removalUUID2), removalDest)

	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = current
	x.nodeConfig = &model.NodeSpec{NodeID: 7, Protocol: "vless"}
	x.sharedRetired = []*sharedRealityGeneration{{dispatcher: retired}}
	x.updateDispatcherLimits([]model.UserSpec{user2})

	if !linkInterrupted(retiredRemoved) {
		t.Fatal("removed user kept its connection on a draining generation")
	}
	if linkInterrupted(retiredKept) {
		t.Fatal("remaining user lost its connection on a draining generation")
	}
	if _, err := retired.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest); err == nil {
		t.Fatal("draining generation accepted a new sub-stream of the removed user")
	}

	other, _ := retired.Dispatch(vlessUserContext(t, 2, removalUUID2), removalDest)
	if err := x.CloseUserConnections(context.Background(), removalUUID2); err != nil {
		t.Fatal(err)
	}
	if !linkInterrupted(other) || !linkInterrupted(retiredKept) {
		t.Fatal("CloseUserConnections did not reach the draining generation")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
