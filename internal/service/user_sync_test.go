package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

type pollReply struct {
	snapshot controlplane.Snapshot
	err      error
}

// blockingPollSource is a polling control plane whose Poll blocks until the
// test hands it a reply, so tests control how pulls interleave with WS events.
type blockingPollSource struct {
	noopSource
	polls               chan struct{}
	replies             chan pollReply
	invalidations       atomic.Int32
	configInvalidations atomic.Int32
}

func newBlockingPollSource() *blockingPollSource {
	return &blockingPollSource{polls: make(chan struct{}, 8), replies: make(chan pollReply)}
}

func (p *blockingPollSource) SupportsPolling() bool  { return true }
func (p *blockingPollSource) InvalidateUserCache()   { p.invalidations.Add(1) }
func (p *blockingPollSource) InvalidateConfigCache() { p.configInvalidations.Add(1) }
func (p *blockingPollSource) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	p.polls <- struct{}{}
	select {
	case reply := <-p.replies:
		return reply.snapshot, reply.err
	case <-ctx.Done():
		return controlplane.Snapshot{}, ctx.Err()
	}
}

func (p *blockingPollSource) waitPoll(t *testing.T) {
	t.Helper()
	select {
	case <-p.polls:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a pull")
	}
}

func (p *blockingPollSource) expectNoPoll(t *testing.T) {
	t.Helper()
	select {
	case <-p.polls:
		t.Fatal("unexpected pull")
	case <-time.After(100 * time.Millisecond):
	}
}

func (p *blockingPollSource) reply(t *testing.T, reply pollReply) {
	t.Helper()
	select {
	case p.replies <- reply:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out handing a reply to the pull")
	}
}

func newPollingTestService(k *fakeKernel, src *blockingPollSource) *Service {
	s := newTestService(k)
	s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "xray"}}
	s.source = src
	s.pullResults = make(chan pullResult, 1)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	return s
}

func receivePullResult(t *testing.T, s *Service) pullResult {
	t.Helper()
	select {
	case result := <-s.pullResults:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a pull result")
		return pullResult{}
	}
}

func (s *Service) pullInFlight() (active, rerun bool) {
	s.pullMu.Lock()
	defer s.pullMu.Unlock()
	return s.pullActive, s.pullRerun
}

func usersByID(users []model.UserSpec) map[int]string {
	out := make(map[int]string, len(users))
	for _, user := range users {
		out[user.ID] = user.UUID
	}
	return out
}

func TestWSUserEventsInvalidateUserCache(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx := context.Background()

	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers})
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove"})
	if src.invalidations.Load() != 0 || s.userEventSeq.Load() != 0 {
		t.Fatal("events without users must not invalidate the users cache")
	}

	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 1, UUID: "u1"}}})
	if got := src.invalidations.Load(); got != 2 {
		t.Fatalf("users cache invalidations = %d, want 2", got)
	}
	if got := s.userEventSeq.Load(); got != 2 {
		t.Fatalf("user event sequence = %d, want 2", got)
	}

	// Events that change nothing (the full sync.users sent on every WS
	// reconnect, a remove for an unknown user) keep the ETag, but still mark
	// in-flight pulls as stale.
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 1, UUID: "u1"}}})
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 9}}})
	if got := src.invalidations.Load(); got != 2 {
		t.Fatalf("users cache invalidations after no-op events = %d, want 2", got)
	}
	if got := s.userEventSeq.Load(); got != 4 {
		t.Fatalf("user event sequence after no-op events = %d, want 4", got)
	}
}

// A sync.users with an empty, non-nil list means "no users": a running kernel
// must drop everyone, not ignore the event.
func TestWSEmptyUserListClearsRunningKernel(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	var updated []model.UserSpec
	k.onUpdateUsers = func(users []model.UserSpec) { updated = users }

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{}})

	if k.updateCalls != 1 || updated == nil || len(updated) != 0 {
		t.Fatalf("UpdateUsers calls = %d with %#v, want one call with an empty list", k.updateCalls, updated)
	}
	if len(s.lastUsers) != 0 || s.lastUserHash != computeUserHash([]model.UserSpec{}) {
		t.Fatalf("lastUsers = %+v, want empty", s.lastUsers)
	}
	if src.invalidations.Load() != 1 {
		t.Fatal("clearing all users must invalidate the users cache")
	}
}

// In machine mode a delta removing the node's last user reaches the service
// as a drained full snapshot, which must be an empty list, not nil.
func TestDrainMachineMailboxRemovesLastUser(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	s.machineMailbox = controlplane.NewNodeMailbox()
	s.markMailboxReadyAndDrain(context.Background())
	var updated []model.UserSpec
	k.onUpdateUsers = func(users []model.UserSpec) { updated = users }

	s.machineMailbox.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	s.drainMachineMailbox(context.Background())

	if k.updateCalls != 1 || updated == nil || len(updated) != 0 {
		t.Fatalf("UpdateUsers calls = %d with %#v, want one call with an empty list", k.updateCalls, updated)
	}
	if len(s.lastUsers) != 0 {
		t.Fatalf("lastUsers = %+v, want empty", s.lastUsers)
	}
}

func TestStalePullDoesNotRollBackWSUserEvents(t *testing.T) {
	stale := []model.UserSpec{{ID: 1, UUID: "uuid-old"}, {ID: 2, UUID: "uuid-keep"}}
	for _, tc := range []struct {
		name  string
		event controlplane.Event
		want  map[int]string
	}{
		{
			name:  "uuid-reset",
			event: controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 1, UUID: "uuid-new"}}},
			want:  map[int]string{1: "uuid-new", 2: "uuid-keep"},
		},
		{
			name:  "remove",
			event: controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}},
			want:  map[int]string{2: "uuid-keep"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{running: true}
			src := newBlockingPollSource()
			s := newPollingTestService(k, src)
			s.updateUserState(stale)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// The pull reads the panel, then the WS event lands before its result.
			s.pullViaAPIAsync(ctx)
			src.waitPoll(t)
			s.handleWSEvent(ctx, tc.event)
			src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: stale}})
			result := receivePullResult(t, s)

			k.onUpdateUsers = func(users []model.UserSpec) {
				t.Fatalf("stale pull must not reach the kernel, got UpdateUsers(%+v)", users)
			}
			invalidations := src.invalidations.Load()
			s.applyPullResult(ctx, result)
			k.onUpdateUsers = nil

			if got := usersByID(s.lastUsers); len(got) != len(tc.want) || !mapsEqual(got, tc.want) {
				t.Fatalf("users after stale pull = %v, want %v", got, tc.want)
			}
			if src.invalidations.Load() <= invalidations {
				t.Fatal("discarding a stale pull must invalidate the users cache")
			}

			// The discarded pull is replaced by a re-pull (no jitter in tests),
			// which applies.
			src.waitPoll(t)
			fresh := []model.UserSpec{{ID: 2, UUID: "uuid-keep"}, {ID: 3, UUID: "uuid-other"}}
			src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: fresh}})
			s.applyPullResult(ctx, receivePullResult(t, s))
			if got := usersByID(s.lastUsers); !mapsEqual(got, usersByID(fresh)) {
				t.Fatalf("users after re-pull = %v, want %v", got, usersByID(fresh))
			}
		})
	}
}

func TestStalePullStillAppliesConfig(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	newConfig := &model.NodeSpec{Protocol: "vless", ServerPort: 9443}
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Config: newConfig, Users: []model.UserSpec{{ID: 1, UUID: "u1"}}}})
	s.applyPullResult(ctx, receivePullResult(t, s))

	if s.lastConfig != newConfig || s.lastConfigHash != computeConfigHash(newConfig) {
		t.Fatal("a stale pull's config part must still be applied")
	}
	if len(s.lastUsers) != 0 {
		t.Fatalf("a stale pull's users must be discarded, got %+v", s.lastUsers)
	}
	src.waitPoll(t)
}

func mapsEqual(a, b map[int]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func TestAPIBackoffSkipsOnePeriodicAttemptPerFailure(t *testing.T) {
	var b apiBackoff
	if b.shouldSkip() {
		t.Fatal("no failure must not skip")
	}
	for i := 0; i < 3; i++ {
		b.onFailure()
		if !b.shouldSkip() {
			t.Fatalf("failure %d must skip the next attempt", i+1)
		}
		if b.shouldSkip() {
			t.Fatalf("failure %d must skip exactly one attempt", i+1)
		}
	}
	b.onFailure()
	b.onSuccess()
	if b.shouldSkip() {
		t.Fatal("success must clear a pending skip")
	}
}

func TestResyncPullBypassesBackoff(t *testing.T) {
	src := newBlockingPollSource()
	s := newPollingTestService(&fakeKernel{}, src)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{err: errors.New("panel down")})
	waitPullIdle(t, s)

	// The periodic tick after a failure is skipped...
	s.pullViaAPIAsync(ctx)
	if active, _ := s.pullInFlight(); active {
		t.Fatal("periodic pull after a failure must be skipped")
	}
	src.expectNoPoll(t)

	// ...but a resync (e.g. WS reconnect) is not swallowed by a pending skip.
	s.pullBackoff.onFailure()
	s.resyncViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
	receivePullResult(t, s)
}

func TestResyncDuringInFlightPullRunsAfterIt(t *testing.T) {
	src := newBlockingPollSource()
	s := newPollingTestService(&fakeKernel{}, src)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	s.pullViaAPIAsync(ctx)
	if _, rerun := s.pullInFlight(); rerun {
		t.Fatal("a periodic pull during an in-flight pull must just be dropped")
	}
	s.resyncViaAPIAsync(ctx)
	if _, rerun := s.pullInFlight(); !rerun {
		t.Fatal("a resync during an in-flight pull must be queued")
	}
	src.expectNoPoll(t)

	src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
	receivePullResult(t, s)
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
	receivePullResult(t, s)
	waitPullIdle(t, s)
	src.expectNoPoll(t)
}

func waitPullIdle(t *testing.T, s *Service) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if active, _ := s.pullInFlight(); !active {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the pull to finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A uuid reset arrives as a delta add for a known ID. Removing the old uuid
// first stops a one-user Xray kernel (empty inbound), after which AddUsers and
// the UpdateUsers fallback fail on the stopped kernel.
func TestApplyUserDeltaUUIDChangeUsesSingleUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}})
	k.onRemoveUsers = func([]model.UserSpec) { k.running = false }
	newUser := model.UserSpec{ID: 1, UUID: "uuid-new", SpeedLimit: 4}
	k.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0] != newUser {
			t.Fatalf("UpdateUsers(%+v), want only the new uuid", users)
		}
		if k.speedLimitFunc("uuid-new") == nil || k.speedLimitFunc("uuid-old") != nil {
			t.Fatal("limiters must swap to the new uuid before UpdateUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", []model.UserSpec{newUser})

	if !k.running || k.updateCalls != 1 || k.removeCalls != 0 || k.addCalls != 0 {
		t.Fatalf("running = %v, UpdateUsers = %d, RemoveUsers = %d, AddUsers = %d, want true, 1, 0, 0",
			k.running, k.updateCalls, k.removeCalls, k.addCalls)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0] != newUser || s.lastUserHash != computeUserHash([]model.UserSpec{newUser}) {
		t.Fatalf("lastUsers = %+v, want the new uuid", s.lastUsers)
	}
}

func TestApplyUserDeltaUUIDChangeRestartsKernelWhenUpdateFails(t *testing.T) {
	k := &fakeKernel{running: true, updateErr: errors.New("update failed")}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "uuid-old"}, {ID: 2, UUID: "uuid-other"}})
	k.onStartUsers = func(users []model.UserSpec) {
		if got := usersByID(users); !mapsEqual(got, map[int]string{1: "uuid-new", 2: "uuid-other"}) {
			t.Fatalf("restart users = %v, want the merged set with the new uuid", got)
		}
	}

	s.applyUserDelta(context.Background(), "add", []model.UserSpec{{ID: 1, UUID: "uuid-new"}})

	if !k.running || k.startCalls != 1 || k.removeCalls != 0 {
		t.Fatalf("running = %v, Start = %d, RemoveUsers = %d, want true, 1, 0", k.running, k.startCalls, k.removeCalls)
	}
}

func TestApplyUserDeltaPlainAddStillUsesAddUsers(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})

	// Same uuid with a new speed limit, plus a new user: no credential swap.
	s.applyUserDelta(context.Background(), "add", []model.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: 8}, {ID: 2, UUID: "u2"}})

	if k.addCalls != 1 || k.updateCalls != 0 || k.removeCalls != 0 {
		t.Fatalf("AddUsers = %d, UpdateUsers = %d, RemoveUsers = %d, want 1, 0, 0", k.addCalls, k.updateCalls, k.removeCalls)
	}
}

func TestApplyPullResultReplacesMachineMailboxBaseline(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}})
	s.machineMailbox = controlplane.NewNodeMailbox()
	s.markMailboxReadyAndDrain(context.Background())

	// REST drops user 2 (no WS delta for it), then an unrelated delta arrives.
	rest := []model.UserSpec{{ID: 1, UUID: "u1"}}
	s.applyPullResult(context.Background(), pullResult{users: rest, userHash: computeUserHash(rest), userEventSeq: s.userEventSeq.Load()})
	s.machineMailbox.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "u3"}}})
	s.drainMachineMailbox(context.Background())

	if got := usersByID(s.lastUsers); !mapsEqual(got, map[int]string{1: "u1", 3: "u3"}) {
		t.Fatalf("users after delta = %v, want REST baseline plus delta (1, 3)", got)
	}
}

// A pull that read config C0 before a WS sync.config C1 was applied must not
// roll the kernel back to C0 when it returns C0 as a 200.
func TestStalePullDoesNotRollBackWSConfig(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	c1 := &model.NodeSpec{Protocol: "vless", ServerPort: 9443}
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: c1})
	if s.lastConfig != c1 || k.reloadCalls != 1 {
		t.Fatalf("WS config not applied: lastConfig = %+v, reloads = %d", s.lastConfig, k.reloadCalls)
	}
	wsInvalidations := src.configInvalidations.Load()

	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Config: &model.NodeSpec{Protocol: "vless"}}})
	s.applyPullResult(ctx, receivePullResult(t, s))

	if s.lastConfig != c1 || s.lastConfigHash != computeConfigHash(c1) {
		t.Fatalf("stale pull rolled the config back to %+v", s.lastConfig)
	}
	if k.reloadCalls != 1 || k.startCalls != 0 {
		t.Fatalf("stale pull restarted the kernel: reloads = %d, starts = %d", k.reloadCalls, k.startCalls)
	}
	if src.configInvalidations.Load() != wsInvalidations+1 {
		t.Fatal("a dropped stale config must invalidate the config cache")
	}

	// The re-pull returns the current config, which changes nothing.
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Config: &model.NodeSpec{Protocol: "vless", ServerPort: 9443}}})
	s.applyPullResult(ctx, receivePullResult(t, s))
	if k.reloadCalls != 1 || s.stalePullDiscards != 0 {
		t.Fatalf("re-pull: reloads = %d, stale discards = %d, want 1, 0", k.reloadCalls, s.stalePullDiscards)
	}
}

// A WS user event during a pull that answers 304 keeps the WS state; nothing
// is discarded and no re-pull runs, while the dropped ETag makes the next
// periodic pull return the full list.
func TestWSUserEventDuringNotModifiedPull(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
	s.applyPullResult(ctx, receivePullResult(t, s))

	if got := usersByID(s.lastUsers); !mapsEqual(got, map[int]string{2: "u2"}) {
		t.Fatalf("users after 304 pull = %v, want only user 2", got)
	}
	if src.invalidations.Load() != 1 || s.stalePullDiscards != 0 {
		t.Fatalf("invalidations = %d, stale discards = %d, want 1, 0", src.invalidations.Load(), s.stalePullDiscards)
	}
	waitPullIdle(t, s)
	src.expectNoPoll(t)
}

// The re-pull after a stale result is requested while the stale pull's
// goroutine has not finished yet: it must be queued and run afterwards.
func TestStalePullRepullQueuedBehindInFlightPull(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	stale := []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}
	s.updateUserState(stale)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A full result channel holds the pull goroutine before finishPull.
	s.pullResults <- pullResult{}
	seq := s.userEventSeq.Load()
	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: stale}})

	s.applyPullResult(ctx, pullResult{users: stale, userHash: computeUserHash(stale), userEventSeq: seq})
	if active, rerun := s.pullInFlight(); !active || !rerun {
		t.Fatalf("pull active = %v, rerun = %v, want the re-pull queued behind the in-flight pull", active, rerun)
	}
	src.expectNoPoll(t)

	receivePullResult(t, s) // placeholder
	receivePullResult(t, s) // the in-flight stale result, already handled above
	src.waitPoll(t)
	fresh := []model.UserSpec{{ID: 2, UUID: "u2"}, {ID: 3, UUID: "u3"}}
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: fresh}})
	s.applyPullResult(ctx, receivePullResult(t, s))
	if got := usersByID(s.lastUsers); !mapsEqual(got, usersByID(fresh)) {
		t.Fatalf("users after queued re-pull = %v, want %v", got, usersByID(fresh))
	}
}

func TestStalePullRepullsAreCapped(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Every result started before a pushed event for user 1 and disagrees
	// with it, so each one conflicts.
	s.noteUserEvent([]int{1}, false)
	pulled := []model.UserSpec{{ID: 1, UUID: "u1-old"}}
	stale := pullResult{users: pulled, userHash: computeUserHash(pulled)}

	serveRepull := func() {
		t.Helper()
		src.waitPoll(t)
		src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
		receivePullResult(t, s)
		waitPullIdle(t, s)
	}
	for i := 0; i < maxStalePullRepulls; i++ {
		s.applyPullResult(ctx, stale)
		serveRepull()
	}
	s.applyPullResult(ctx, stale)
	src.expectNoPoll(t)

	// A clean result resets the count.
	s.applyPullResult(ctx, pullResult{userEventSeq: s.userEventSeq.Load()})
	stale.userEventSeq = s.userEventSeq.Load()
	s.noteUserEvent([]int{1}, false)
	s.applyPullResult(ctx, stale)
	serveRepull()
	if got := usersByID(s.lastUsers); !mapsEqual(got, map[int]string{1: "u1"}) {
		t.Fatalf("users = %v, want the pushed state of user 1 kept", got)
	}
}

// A pulled list the kernel rejects is rolled back; its ETag must go too, or
// later pulls answer 304 and the list is never retried.
func TestPulledUsersRejectedByKernelDropETag(t *testing.T) {
	k := &fakeKernel{running: true, updateErr: errors.New("update failed"), startErr: errors.New("start failed")}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	before := []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}
	s.updateUserState(before)

	pulled := []model.UserSpec{{ID: 1, UUID: "u1"}}
	s.applyPullResult(context.Background(), pullResult{users: pulled, userHash: computeUserHash(pulled), userEventSeq: s.userEventSeq.Load()})

	if got := usersByID(s.lastUsers); !mapsEqual(got, usersByID(before)) {
		t.Fatalf("users = %v, want the old users restored", got)
	}
	if src.invalidations.Load() != 1 || s.stalePullDiscards != 1 {
		t.Fatalf("invalidations = %d, stale discards = %d, want 1, 1", src.invalidations.Load(), s.stalePullDiscards)
	}
}

// A pull carrying a config change and an empty user list stops the kernel;
// the users must be revoked before, since Stop drains gracefully (a stopped
// xray instance keeps serving its links for minutes).
func TestPullClearingUsersWithConfigChangeRevokesBeforeStop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  *model.NodeSpec
		renewal bool
	}{
		{name: "config-change", config: &model.NodeSpec{Protocol: "vless", ServerPort: 9443}},
		{name: "cert-renewal", renewal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{running: true}
			src := newBlockingPollSource()
			s := newPollingTestService(k, src)
			s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
			if tc.renewal {
				pendingCertRenewal(s)
			}
			var revoked []model.UserSpec
			k.onUpdateUsers = func(users []model.UserSpec) {
				if !k.running {
					t.Fatal("users were revoked after the kernel stopped")
				}
				revoked = users
			}

			result := pullResult{users: []model.UserSpec{}, userHash: computeUserHash([]model.UserSpec{}), userEventSeq: s.userEventSeq.Load()}
			if tc.config != nil {
				result.config = tc.config
				result.configHash = computeConfigHash(tc.config)
			}
			s.applyPullResult(context.Background(), result)

			if k.updateCalls != 1 || revoked == nil || len(revoked) != 0 {
				t.Fatalf("UpdateUsers calls = %d with %#v, want one call with an empty list", k.updateCalls, revoked)
			}
			if k.running {
				t.Fatal("the kernel must be stopped")
			}
		})
	}
}

// A pull that overlaps pushed events for other users still applies what it
// read for everyone else: a user whose removal push was lost is removed by
// that pull, however busy the node is. Before, any event during the pull
// discarded the whole list, so steady traffic of unrelated events could keep
// the removed user online indefinitely.
func TestPullAppliesUsersUntouchedByConcurrentEvents(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pulled     []model.UserSpec
		wantRepull bool
	}{
		// The pull read the panel before the add of user 4: it conflicts on
		// user 4 only, which keeps its pushed state.
		{name: "read-before-event", pulled: []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 3, UUID: "u3"}}, wantRepull: true},
		// The pull read the panel after it: nothing conflicts.
		{name: "read-after-event", pulled: []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 3, UUID: "u3"}, {ID: 4, UUID: "u4"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{running: true}
			src := newBlockingPollSource()
			s := newPollingTestService(k, src)
			// User 2 was removed on the panel; its push was lost.
			s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}, {ID: 3, UUID: "u3"}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s.pullViaAPIAsync(ctx)
			src.waitPoll(t)
			s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 4, UUID: "u4"}}})
			src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: tc.pulled}})
			result := receivePullResult(t, s)
			waitPullIdle(t, s)
			var kernelUsers []model.UserSpec
			k.onUpdateUsers = func(users []model.UserSpec) { kernelUsers = users }
			invalidations := src.invalidations.Load()
			s.applyPullResult(ctx, result)

			want := map[int]string{1: "u1", 3: "u3", 4: "u4"}
			if got := usersByID(s.lastUsers); !mapsEqual(got, want) {
				t.Fatalf("users = %v, want %v", got, want)
			}
			if got := usersByID(kernelUsers); !mapsEqual(got, want) {
				t.Fatalf("kernel users = %v, want %v", got, want)
			}
			if tc.wantRepull {
				if src.invalidations.Load() <= invalidations || s.stalePullDiscards != 1 {
					t.Fatalf("invalidations %d -> %d, stale discards %d: a conflict must drop the ETag and re-pull",
						invalidations, src.invalidations.Load(), s.stalePullDiscards)
				}
				src.waitPoll(t)
			} else {
				if src.invalidations.Load() != invalidations || s.stalePullDiscards != 0 {
					t.Fatalf("invalidations %d -> %d, stale discards %d: an agreeing pull is not stale",
						invalidations, src.invalidations.Load(), s.stalePullDiscards)
				}
				src.expectNoPoll(t)
			}
		})
	}
}

// A pushed full list may predate or follow the pulled one; the pulled list
// is only applied when it already matches.
func TestPullOverlappingFullUserPushIsDropped(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	seq := s.userEventSeq.Load()
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 2, UUID: "u2"}}})
	pulled := []model.UserSpec{{ID: 1, UUID: "u1"}}
	s.applyPullResult(ctx, pullResult{users: pulled, userHash: computeUserHash(pulled), userEventSeq: seq})
	if got := usersByID(s.lastUsers); !mapsEqual(got, map[int]string{2: "u2"}) {
		t.Fatalf("users = %v, want the pushed full list", got)
	}
	if s.stalePullDiscards != 1 {
		t.Fatalf("stale discards = %d, want a re-pull", s.stalePullDiscards)
	}
}

// A pull older than the retained marks treats every user as touched.
func TestPullOlderThanRetainedMarksIsDropped(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < maxUserEventMarks+1; i++ {
		s.noteUserEvent([]int{100000 + i}, false)
	}
	if len(s.userEventMarks) != maxUserEventMarks || s.userEventMarksFloor != 1 {
		t.Fatalf("marks = %d, floor = %d, want %d, 1", len(s.userEventMarks), s.userEventMarksFloor, maxUserEventMarks)
	}
	pulled := []model.UserSpec{{ID: 2, UUID: "u2"}}
	s.applyPullResult(ctx, pullResult{users: pulled, userHash: computeUserHash(pulled), userEventSeq: 0})
	if got := usersByID(s.lastUsers); !mapsEqual(got, map[int]string{1: "u1"}) {
		t.Fatalf("users = %v, want the local list kept", got)
	}
}

// A pushed sync.config equal to the running config still marks pulls in
// flight: the panel may have briefly had another config (B) that the pull
// read, and has reverted to the running one (A) since.
func TestWSConfigEqualToRunningStillMarksPullStale(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	running := s.lastConfig
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: &model.NodeSpec{Protocol: "vless"}})
	b := &model.NodeSpec{Protocol: "vless", ServerPort: 9443}
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Config: b}})
	result := receivePullResult(t, s)
	waitPullIdle(t, s)
	s.applyPullResult(ctx, result)

	if s.lastConfig != running || s.lastConfigHash != computeConfigHash(running) {
		t.Fatalf("config = %+v, want the running config kept", s.lastConfig)
	}
	if k.reloadCalls != 0 {
		t.Fatalf("Reload calls = %d, want 0", k.reloadCalls)
	}
	src.waitPoll(t)
}

// Machine mode: a delta the mailbox received before the pull started is
// older than the pulled list. Replaying it would remove user 1, whom the
// panel restored afterwards (that push lost).
func TestPullDoesNotReplayMailboxDeltaOlderThanThePull(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	users := []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}
	s.updateUserState(users)
	s.machineMailbox = controlplane.NewNodeMailbox()
	s.markMailboxReadyAndDrain(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.machineMailbox.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: users}})
	result := receivePullResult(t, s)
	waitPullIdle(t, s)
	s.applyPullResult(ctx, result)
	s.drainMachineMailbox(ctx)

	if got := usersByID(s.lastUsers); !mapsEqual(got, usersByID(users)) {
		t.Fatalf("users = %v, want the pulled list (1, 2)", got)
	}
	src.expectNoPoll(t)
}

// A pull result dropped because the service is stopping leaves no ETag for
// data that was never applied.
func TestPullResultDroppedOnShutdownInvalidatesCaches(t *testing.T) {
	src := newBlockingPollSource()
	s := newPollingTestService(&fakeKernel{}, src)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	renewal := pendingCertRenewal(s)

	s.pullResults <- pullResult{}
	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{Config: &model.NodeSpec{Protocol: "vless"}, Users: []model.UserSpec{}}})
	cancel()
	waitPullIdle(t, s)

	if src.configInvalidations.Load() != 1 || src.invalidations.Load() != 1 {
		t.Fatalf("config/users invalidations = %d/%d, want 1/1", src.configInvalidations.Load(), src.invalidations.Load())
	}
	if !renewal.Load() {
		t.Fatal("a dropped pull result consumed the pending cert renewal")
	}
}

// pendingCertRenewal stubs the cert manager with a renewal that is pending
// until a pull result consumes it.
func pendingCertRenewal(s *Service) *atomic.Bool {
	renewal := &atomic.Bool{}
	renewal.Store(true)
	s.certRenewedFn = func() bool { return renewal.Swap(false) }
	return renewal
}

// A panel config that keeps failing normalization must not stop user sync:
// every pull still applies its users and counts as a success, and a pending
// cert renewal restarts the kernel with the running config.
func TestInvalidPulledConfigStillAppliesUsers(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	running := s.lastConfig
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	renewal := pendingCertRenewal(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	configErr := errors.New(`poll config normalize: custom_outbounds[0].proxy_tag references unknown outbound "missing"`)

	pulls := [][]model.UserSpec{
		{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}},
		{{ID: 2, UUID: "u2"}},
	}
	for i, users := range pulls {
		// Periodic pulls: a pull counted as failed would make the next one
		// skip, and waitPoll would time out.
		s.pullViaAPIAsync(ctx)
		src.waitPoll(t)
		src.reply(t, pollReply{snapshot: controlplane.Snapshot{Users: users, ConfigErr: configErr}})
		s.applyPullResult(ctx, receivePullResult(t, s))
		waitPullIdle(t, s)

		if got, want := usersByID(s.lastUsers), usersByID(users); !mapsEqual(got, want) {
			t.Fatalf("pull %d: users = %v, want %v", i+1, got, want)
		}
		if s.lastConfig != running {
			t.Fatalf("pull %d: running config replaced by %+v", i+1, s.lastConfig)
		}
	}
	if renewal.Load() || k.reloadCalls != 1 || k.reloadConfig != running {
		t.Fatalf("cert renewal: pending = %v, reloads = %d, config = %+v, want restart with the running config",
			renewal.Load(), k.reloadCalls, k.reloadConfig)
	}
	if k.updateCalls != 1 {
		t.Fatalf("UpdateUsers calls = %d, want 1 for the second pull", k.updateCalls)
	}
}

// A pull that fails leaves a pending cert renewal for the next pull.
func TestCertRenewalSurvivesFailedPull(t *testing.T) {
	k := &fakeKernel{running: true}
	src := newBlockingPollSource()
	s := newPollingTestService(k, src)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	renewal := pendingCertRenewal(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.pullViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{err: errors.New("panel unreachable")})
	waitPullIdle(t, s)
	if !renewal.Load() || k.reloadCalls != 0 {
		t.Fatalf("after a failed pull: renewal pending = %v, reloads = %d, want true, 0", renewal.Load(), k.reloadCalls)
	}

	s.resyncViaAPIAsync(ctx)
	src.waitPoll(t)
	src.reply(t, pollReply{snapshot: controlplane.Snapshot{}})
	s.applyPullResult(ctx, receivePullResult(t, s))
	if renewal.Load() || k.reloadCalls != 1 || k.reloadConfig != s.lastConfig {
		t.Fatalf("after the next pull: renewal pending = %v, reloads = %d, want false, 1", renewal.Load(), k.reloadCalls)
	}
}

// After a WS sync.config replaced the running config, the next REST pull
// must fetch the config in full: with the old ETag a panel that returned to
// the last REST snapshot would answer 304 and keep the pushed config running.
func TestWSConfigInvalidatesConfigETag(t *testing.T) {
	var mu sync.Mutex
	var configINM []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		inm := r.Header.Get("If-None-Match")
		configINM = append(configINM, inm)
		if inm == `"c0"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"c0"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol":"shadowsocks","server_port":8388,"cipher":"aes-128-gcm"}`))
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"11111111-1111-1111-1111-111111111111"}]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	lastConfigINM := func() string {
		mu.Lock()
		defer mu.Unlock()
		return configINM[len(configINM)-1]
	}

	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "xray"}}
	s.source = controlplane.NewPanelControlPlane(config.PanelConfig{URL: server.URL, Token: "token", NodeID: 1}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "u1"}})
	ctx := context.Background()
	poll := func() {
		t.Helper()
		if _, err := s.source.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}

	poll()
	poll()
	if got := lastConfigINM(); got != `"c0"` {
		t.Fatalf("config If-None-Match before the WS config = %q, want the stored ETag", got)
	}

	c1 := &model.NodeSpec{Protocol: "vless", ServerPort: 9443}
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: c1})
	if s.lastConfig != c1 {
		t.Fatalf("WS config not applied: lastConfig = %+v", s.lastConfig)
	}
	poll()
	if got := lastConfigINM(); got != "" {
		t.Fatalf("config If-None-Match after the WS config = %q, want none", got)
	}
}
