package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestHandleWSUserSyncStartsKernelAfterConfig(t *testing.T) {
	users := make([]model.UserSpec, 3551)
	for i := range users {
		users[i] = model.UserSpec{ID: i + 1, UUID: fmt.Sprintf("test-user-%d", i+1), SpeedLimit: 8, DeviceLimit: 3}
	}
	for _, event := range []controlplane.Event{
		{Type: controlplane.EventSyncUsers, Users: users},
		{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: users},
	} {
		t.Run(string(event.Type), func(t *testing.T) {
			k := &fakeKernel{}
			s := newTestService(k)
			s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "xray"}}
			nc := &model.NodeSpec{NodeID: 42, Protocol: "vless", ServerPort: 8443}
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: nc})
			if k.running || k.startCalls != 0 {
				t.Fatal("config without users must not start the kernel")
			}
			k.onStartUsers = func(startUsers []model.UserSpec) {
				if len(startUsers) != len(users) || len(s.lastUsers) != len(users) {
					t.Fatalf("Start received %d users, cached %d users, want %d", len(startUsers), len(s.lastUsers), len(users))
				}
				for _, user := range startUsers {
					if user.ID < 1 || user.ID > len(users) || user != users[user.ID-1] {
						t.Fatalf("unexpected user passed to Start: %#v", user)
					}
					if k.speedLimitFunc(user.UUID) == nil {
						t.Fatalf("user %d limiter must be ready before Start", user.ID)
					}
					if limit, ok := k.deviceLimitFunc(user.UUID); !ok || limit != 3 {
						t.Fatalf("user %d device limit = %d, %v, want 3, true", user.ID, limit, ok)
					}
				}
			}

			s.handleWSEvent(context.Background(), event)

			if !k.running || k.startCalls != 1 {
				t.Fatalf("kernel running = %v, Start calls = %d, want true, 1", k.running, k.startCalls)
			}
			if k.updateCalls != 0 || k.addCalls != 0 {
				t.Fatalf("startup must not reapply users: UpdateUsers = %d, AddUsers = %d", k.updateCalls, k.addCalls)
			}
			if s.appliedState.Config != nc || len(s.appliedState.Users) != len(users) {
				t.Fatal("successful startup must record the config and full user snapshot")
			}
			if s.lastUserHash != computeUserHash(users) {
				t.Fatal("successful startup must record the received user hash")
			}
		})
	}
}

func TestHandleWSUserSyncCachesUsersBeforeConfig(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "uuid-new", SpeedLimit: 8}}
	for _, event := range []controlplane.Event{
		{Type: controlplane.EventSyncUsers, Users: users},
		{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: users},
	} {
		t.Run(string(event.Type), func(t *testing.T) {
			k := &fakeKernel{}
			s := newTestService(k)
			s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "xray"}}

			s.handleWSEvent(context.Background(), event)

			if !slices.Equal(s.lastUsers, users) || s.lastUserHash != computeUserHash(users) {
				t.Fatal("users arriving before config must be cached")
			}
			if k.running || k.startCalls != 0 || k.updateCalls != 0 || k.addCalls != 0 {
				t.Fatal("users without config must not touch the kernel")
			}
			k.onStartUsers = func(startUsers []model.UserSpec) {
				if !slices.Equal(startUsers, users) || k.speedLimitFunc("uuid-new") == nil {
					t.Fatal("later config must start with the cached users and prepared limiter")
				}
			}
			s.handleWSEvent(context.Background(), controlplane.Event{
				Type:   controlplane.EventSyncConfig,
				Config: &model.NodeSpec{Protocol: "vless", ServerPort: 8443},
			})
			if !k.running || k.startCalls != 1 {
				t.Fatalf("kernel running = %v, Start calls = %d, want true, 1", k.running, k.startCalls)
			}
		})
	}
}

func TestApplyUserUpdateStartsStoppedKernelWithNewSnapshot(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}})
	users := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onStartUsers = func(startUsers []model.UserSpec) {
		if !slices.Equal(startUsers, users) {
			t.Fatalf("Start users = %#v, want new snapshot", startUsers)
		}
		if k.speedLimitFunc("uuid-new") == nil || k.speedLimitFunc("uuid-old") != nil {
			t.Fatal("Start must see new limiters and no stale limiters")
		}
	}

	s.applyUserUpdate(context.Background(), users, computeUserHash(users))

	if !k.running || k.startCalls != 1 || k.updateCalls != 0 {
		t.Fatalf("running = %v, Start = %d, UpdateUsers = %d, want true, 1, 0", k.running, k.startCalls, k.updateCalls)
	}
}

func TestHandleWSUserSyncRestoresStateWhenStartFails(t *testing.T) {
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	users := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	for _, tc := range []struct {
		name     string
		previous []model.UserSpec
		event    controlplane.Event
		wantSize int
	}{
		{"initial-full", nil, controlplane.Event{Type: controlplane.EventSyncUsers, Users: users}, 1},
		{"initial-delta", nil, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: users}, 1},
		{"stopped-full", oldUsers, controlplane.Event{Type: controlplane.EventSyncUsers, Users: users}, 1},
		{"stopped-delta", oldUsers, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: users}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{startErr: errors.New("start failed")}
			s := newTestService(k)
			s.lastConfig = &model.NodeSpec{Protocol: "vless"}
			if tc.previous != nil {
				s.updateUserState(tc.previous)
			}
			oldHash := s.lastUserHash

			s.handleWSEvent(context.Background(), tc.event)

			if k.startCalls != 1 || k.running {
				t.Fatalf("Start calls = %d, running = %v, want 1, false", k.startCalls, k.running)
			}
			if !slices.Equal(s.lastUsers, tc.previous) || s.lastUserHash != oldHash {
				t.Fatal("failed startup must restore the previous user snapshot and hash")
			}
			if s.speedTracker.GetLimiter("uuid-new") != nil {
				t.Fatal("failed startup must remove the staged user's limiter")
			}
			if tc.previous != nil && s.speedTracker.GetLimiter("uuid-old") == nil {
				t.Fatal("failed startup must restore the old user's limiter")
			}
			if s.appliedState.Config != nil || s.appliedState.Users != nil {
				t.Fatal("failed startup must not publish applied state")
			}

			k.startErr = nil
			s.handleWSEvent(context.Background(), tc.event)
			if !k.running || k.startCalls != 2 || len(s.lastUsers) != tc.wantSize {
				t.Fatalf("retry: running = %v, Start = %d, users = %d, want true, 2, %d", k.running, k.startCalls, len(s.lastUsers), tc.wantSize)
			}
		})
	}
}

func TestHandleWSUserSyncDistinguishesNilAndEmptySnapshot(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers})
	if s.lastUserHash != "" {
		t.Fatal("nil users must not establish a full-sync baseline")
	}

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{}})
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if len(s.lastUsers) != 0 || s.lastUserHash != emptyHash {
		t.Fatalf("empty snapshot: users = %d, hash = %q, want 0, empty-list hash", len(s.lastUsers), s.lastUserHash)
	}
	if k.running || k.startCalls != 0 || k.updateCalls != 0 {
		t.Fatal("empty first snapshot must not start or update the stopped kernel")
	}

	users := []model.UserSpec{{ID: 1, UUID: "uuid-new", SpeedLimit: 8}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: users})
	if !k.running || k.startCalls != 1 {
		t.Fatal("non-empty snapshot after an empty baseline must start the kernel")
	}
}

func TestHandleWSUserSyncEmptySnapshotClearsRunningUsers(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}})
	oldHash := s.lastUserHash

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers})
	if k.updateCalls != 0 || s.lastUserHash != oldHash || len(s.lastUsers) != 1 {
		t.Fatal("nil snapshot must leave existing users unchanged")
	}
	k.onUpdateUsers = func(users []model.UserSpec) {
		if users == nil || len(users) != 0 || k.speedLimitFunc("uuid-old") != nil {
			t.Fatal("explicit empty snapshot must clear users and limiters before UpdateUsers")
		}
	}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{}})
	if !k.running || k.startCalls != 0 || k.updateCalls != 1 || len(s.lastUsers) != 0 {
		t.Fatal("empty snapshot must hot-update the running kernel without restarting")
	}
}

func TestApplyUserDeltaRemoveWhileStoppedUpdatesPendingUsers(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "xray"}}
	oldUser := model.UserSpec{ID: 1, UUID: "uuid-old", SpeedLimit: 4}
	remaining := model.UserSpec{ID: 2, UUID: "uuid-remaining", SpeedLimit: 8}
	s.updateUserState([]model.UserSpec{oldUser, remaining})

	s.applyUserDelta(context.Background(), "remove", []model.UserSpec{oldUser})

	if !slices.Equal(s.lastUsers, []model.UserSpec{remaining}) || s.speedTracker.GetLimiter("uuid-old") != nil {
		t.Fatal("removal while stopped must remove pending users and their limiters")
	}
	if k.startCalls != 0 || k.removeCalls != 0 || k.updateCalls != 0 {
		t.Fatal("removal while stopped must not touch the kernel")
	}
	k.onStartUsers = func(users []model.UserSpec) {
		if !slices.Equal(users, []model.UserSpec{remaining}) {
			t.Fatal("later config must not start with a removed user's credentials")
		}
	}
	s.handleWSEvent(context.Background(), controlplane.Event{
		Type:   controlplane.EventSyncConfig,
		Config: &model.NodeSpec{Protocol: "vless", ServerPort: 8443},
	})
	if !k.running || k.startCalls != 1 {
		t.Fatal("later config must start the kernel with the remaining pending user")
	}
}

func TestApplyPullResultStartsKernelOnFirstUsers(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{NodeID: 42, Protocol: "vless"}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	configHash := s.lastConfigHash
	s.updateUserState([]model.UserSpec{})
	users := []model.UserSpec{{ID: 1, UUID: "uuid-new", SpeedLimit: 8}}
	k.onStartUsers = func(startUsers []model.UserSpec) {
		if !slices.Equal(startUsers, users) || k.speedLimitFunc("uuid-new") == nil {
			t.Fatal("REST first users must be staged before kernel startup")
		}
	}

	s.applyPullResult(context.Background(), pullResult{users: users, userHash: computeUserHash(users)})

	if !k.running || k.startCalls != 1 || k.updateCalls != 0 {
		t.Fatalf("running = %v, Start = %d, UpdateUsers = %d, want true, 1, 0", k.running, k.startCalls, k.updateCalls)
	}
	if s.lastConfig.NodeID != 42 || s.lastConfigHash != configHash {
		t.Fatal("user-only REST update must start without changing the config or its hash")
	}
}
