package controlplane

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestNodeMailboxLatestStateAndNotifyCollapse(t *testing.T) {
	mb := NewNodeMailbox()
	cfg1 := &model.NodeSpec{Protocol: "vmess", ServerPort: 10010}
	cfg2 := &model.NodeSpec{Protocol: "vless", ServerPort: 10020}

	mb.Apply(Event{Type: EventSyncConfig, Config: cfg1})
	mb.Apply(Event{Type: EventSyncConfig, Config: cfg2})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected collapsed notify signal")
	}

	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.HasConfig || state.Config == nil {
		t.Fatal("expected config state")
	}
	if state.Config.Protocol != "vless" || state.Config.ServerPort != 10020 {
		t.Fatalf("unexpected config: %+v", state.Config)
	}
}

func TestNodeMailboxFullUsersOverwriteAndDeltaBeforeBaseline(t *testing.T) {
	mb := NewNodeMailbox()
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 1, UUID: "u1"}},
	})
	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected reconcile when delta arrives before baseline")
	}

	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{{ID: 1, UUID: "u1"}}})
	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{{ID: 2, UUID: "u2"}}})
	state = mb.DrainIfReady()
	if !state.HasUsers {
		t.Fatal("expected users snapshot")
	}
	if len(state.Users) != 1 || state.Users[0].ID != 2 {
		t.Fatalf("unexpected users: %+v", state.Users)
	}
}

func TestNodeMailboxDevicesLatestWins(t *testing.T) {
	mb := NewNodeMailbox()
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{1: {"1.1.1.1"}}})
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{1: {"2.2.2.2"}}})
	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.HasDevices {
		t.Fatal("expected devices state")
	}
	if got := state.DeviceUsers[1][0]; got != "2.2.2.2" {
		t.Fatalf("unexpected device state: %v", state.DeviceUsers)
	}
}

func TestNodeMailboxReconcileNotifies(t *testing.T) {
	mb := NewNodeMailbox()
	mb.MarkReady()

	// Drain the MarkReady notification
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Delta without baseline should trigger reconcile AND notify
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 1, UUID: "u1"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify on reconcile path")
	}

	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected NeedsReconcile")
	}
}

func TestNodeMailboxSeedBaselineEnablesDelta(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)
	mb.MarkReady()

	// Drain MarkReady notify
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Delta should now apply incrementally, not trigger reconcile
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 3, UUID: "u3"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify after delta")
	}

	state := mb.DrainIfReady()
	if state.NeedsReconcile {
		t.Fatal("should not need reconcile after seeded baseline")
	}
	if !state.HasUsers {
		t.Fatal("expected users")
	}
	if len(state.Users) != 3 {
		t.Fatalf("expected 3 users, got %d: %+v", len(state.Users), state.Users)
	}
}

func TestNodeMailboxDeltaFailedApplyNotifies(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}}, nil)
	mb.MarkReady()

	// Drain MarkReady notify
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Invalid action should trigger reconcile and still notify
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "invalid_action",
		DeltaUsers:  []model.UserSpec{{ID: 2, UUID: "u2"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify on failed delta apply")
	}

	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected NeedsReconcile for invalid delta action")
	}
}

func mailboxUserIDs(users []model.UserSpec) map[int]string {
	ids := make(map[int]string, len(users))
	for _, user := range users {
		ids[user.ID] = user.UUID
	}
	return ids
}

func TestNodeMailboxReplaceBaselineDropsRESTRemovedUsers(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	// A REST pull removed user 2 (e.g. expiry, which pushes no delta).
	mb.ReplaceBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}})
	if state := mb.DrainIfReady(); state.HasUsers {
		t.Fatalf("replacing the baseline alone must not emit users: %+v", state)
	}

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "u3"}}})
	state := mb.DrainIfReady()
	got := mailboxUserIDs(state.Users)
	if !state.HasUsers || len(got) != 2 || got[1] != "u1" || got[3] != "u3" {
		t.Fatalf("delta after REST baseline = %+v, want users 1 and 3 only", state.Users)
	}
}

func TestNodeMailboxReplaceBaselineReplaysUndrainedDeltas(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "u3"}}})
	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	mb.ReplaceBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 4, UUID: "u4"}})

	state := mb.DrainIfReady()
	got := mailboxUserIDs(state.Users)
	if !state.HasUsers || len(got) != 2 || got[3] != "u3" || got[4] != "u4" {
		t.Fatalf("drained users = %+v, want REST baseline plus undrained deltas (3, 4)", state.Users)
	}

	// Drained deltas must not be replayed onto a later baseline.
	mb.ReplaceBaseline([]model.UserSpec{{ID: 5, UUID: "u5"}})
	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 6, UUID: "u6"}}})
	got = mailboxUserIDs(mb.DrainIfReady().Users)
	if len(got) != 2 || got[5] != "u5" || got[6] != "u6" {
		t.Fatalf("drained users = %+v, want 5 and 6 only", got)
	}
}

func TestNodeMailboxReplaceBaselineKeepsUndrainedFullSnapshot(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}}, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{{ID: 7, UUID: "u7"}}})
	mb.ReplaceBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}})

	got := mailboxUserIDs(mb.DrainIfReady().Users)
	if len(got) != 1 || got[7] != "u7" {
		t.Fatalf("drained users = %+v, want the undrained WS full snapshot", got)
	}
}

// Removing the last user by delta leaves an empty, non-nil list: the service
// ignores a nil list, so a nil here would keep the removed user online.
func TestNodeMailboxDeltaRemovingLastUserDrainsEmptyList(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}}, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	state := mb.DrainIfReady()
	if !state.HasUsers || state.Users == nil || len(state.Users) != 0 {
		t.Fatalf("drained users = %#v (has=%v), want an empty non-nil list", state.Users, state.HasUsers)
	}

	// A later delta still applies on top of the empty list.
	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 2, UUID: "u2"}}})
	if got := mailboxUserIDs(mb.DrainIfReady().Users); len(got) != 1 || got[2] != "u2" {
		t.Fatalf("drained users = %v, want user 2", got)
	}
}

func TestNodeMailboxReplaceBaselineReplayRemovingLastUserDrainsEmptyList(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	mb.ReplaceBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}})
	state := mb.DrainIfReady()
	if !state.HasUsers || state.Users == nil || len(state.Users) != 0 {
		t.Fatalf("drained users = %#v (has=%v), want an empty non-nil list", state.Users, state.HasUsers)
	}
}

func TestNodeMailboxEmptyFullSnapshotDrainsEmptyList(t *testing.T) {
	mb := NewNodeMailbox()
	mb.MarkReady()
	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{}})
	state := mb.DrainIfReady()
	if !state.HasUsers || state.Users == nil || len(state.Users) != 0 {
		t.Fatalf("drained users = %#v (has=%v), want an empty non-nil list", state.Users, state.HasUsers)
	}
}
