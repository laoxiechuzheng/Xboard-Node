package singbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// drainTimeout is how long stop() waits for in-flight connections to finish
// naturally after closing all listen sockets, before hard-killing them.
const drainTimeout = 5 * time.Second

// SingBox implements kernel.Kernel by embedding sing-box as a Go library.
//
// User operations (AddUsers/RemoveUsers/UpdateUsers) use sing-box's native
// UpdatableInbound interface, which hot-swaps user credentials without
// restarting listeners — zero connection disruption.
type SingBox struct {
	cfg config.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// The pinned HY2 inbound authenticates QUIC sessions by array index. Keep
	// these slots stable until a full inbound reconstruction or restart.
	hysteria2Users []option.Hysteria2User

	// TUIC authenticates sessions by array index too, so it gets the same slots.
	tuicUsers []option.TUICUser

	// connTracker is our lightweight in-process byte/IP tracker.
	// Created fresh on every Start (full restart).
	// Survives Reload (hot-swap) since live connections persist.
	connTracker *ConnTracker

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	// Set once by SetSpeedLimitFunc and forwarded to every new ConnTracker.
	speedLimitFunc func(string) *rate.Limiter

	// deviceLimitFunc resolves a user UUID to (limit, hasLimit) for gate-keeping.
	// Set once by SetDeviceLimitFunc and forwarded to every new ConnTracker.
	deviceLimitFunc func(string) (int, bool)
}

func New(cfg config.KernelConfig) *SingBox {
	return &SingBox{cfg: cfg}
}

var _ kernel.Kernel = (*SingBox)(nil)

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "hy2", "tuic", "naive", "socks", "http", "anytls", "mieru",
	}
}

func (s *SingBox) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	nlog.Core().Debug("sing-box config generated", "len", len(data))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	// Save old state before creating the new instance.
	oldBox := s.box
	oldCancel := s.cancel
	oldCtx := s.ctx
	oldTracker := s.connTracker

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}

	tracker := NewConnTracker(idleTimeoutFromConfig(s.cfg))
	tracker.SetUserMap(buildUserMap(users))
	tracker.SetAuditSink(s.cfg.AuditSink, nodeConfig.NodeID, inboundProtocol(nodeConfig))
	if s.speedLimitFunc != nil {
		tracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		tracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		instance.Close()
		cancel()
		return fmt.Errorf("sing-box router not available")
	}
	router.AppendTracker(tracker)

	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}

	// New instance started successfully — swap state.
	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	s.connTracker = tracker
	s.hysteria2Users = nil
	s.tuicUsers = nil
	for _, inb := range opts.Inbounds {
		if options, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
			s.hysteria2Users = append([]option.Hysteria2User(nil), options.Users...)
		}
		if options, ok := inb.Options.(*option.TUICInboundOptions); ok {
			s.tuicUsers = append([]option.TUICUser(nil), options.Users...)
		}
	}
	// Idle janitor lives for the lifetime of this instance context.
	go tracker.runIdleJanitor(ctx)

	// Recycle old instance in background — drain then close.
	if oldBox != nil {
		go recycleOldBox(oldBox, oldCancel, oldCtx, oldTracker)
	}

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

// defaultSingboxIdleTimeout is the sing-box equivalent of xray's connIdle.
const defaultSingboxIdleTimeout = 35

// idleTimeoutFromConfig resolves the singbox TCP idle timeout from config:
// 0 = default (35s), negative = disabled, positive = explicit seconds.
func idleTimeoutFromConfig(cfg config.KernelConfig) time.Duration {
	t := cfg.IdleTimeout
	if t == 0 {
		t = defaultSingboxIdleTimeout
	}
	if t < 0 {
		return 0
	}
	return time.Duration(t) * time.Second
}

// recycleOldBox gracefully shuts down a previous sing-box instance in the
// background. It closes listen sockets first, waits for connections to drain,
// then hard-closes. This avoids blocking the new instance's startup.
func recycleOldBox(oldBox *box.Box, oldCancel context.CancelFunc, oldCtx context.Context, oldTracker *ConnTracker) {
	// Step 1: close listen sockets so no new connections arrive on old ports.
	if im := service.FromContext[adapter.InboundManager](oldCtx); im != nil {
		_ = im.Close()
	}

	// Step 2: drain in-flight connections (best-effort).
	if oldTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if oldTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything.
	oldBox.Close()
	if oldCancel != nil {
		oldCancel()
	}
	nlog.Core().Debug("sing-box: old instance recycled")
}

// Reload hot-swaps the inbound users and routing rules without restarting the box.
// Routes, outbounds, and the connTracker stay alive so in-flight connections
// continue to be tracked correctly.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	// Update routing rules
	if err := router.UpdateRules(opts.Route.Rules, opts.Route.RuleSet); err != nil {
		nlog.Core().Debug("routing reload failed", "error", err)
	} else {
		nlog.Core().Debug("sing-box routing reloaded")
	}

	nopFactory := singLog.NewNOPFactory()

	// Configuration hash check for inbound reconstruction
	tlsChanged := !bytes.Equal(s.tls.CertPEM, tls.CertPEM) || !bytes.Equal(s.tls.KeyPEM, tls.KeyPEM)
	configUsers, previousConfigUsers := users, s.users
	if p := inboundProtocol(nodeConfig); p == "hysteria2" || p == "tuic" {
		// HY2 and TUIC credentials are updated in stable slots without rebinding QUIC.
		configUsers, previousConfigUsers = nil, nil
	}
	configChanged := tlsChanged || s.nodeConfig == nil || kernel.ComputeHash(nodeConfig, configUsers) != kernel.ComputeHash(s.nodeConfig, previousConfigUsers)

	// Trackers remain registered on the Router (which survives ReloadUsers).
	// Only update the user map — do NOT re-register or traffic is double-counted.
	// Publish it before the inbounds change: a HY2 session of a just-added user
	// is closed by the tracker when its user is not in the map yet.
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
		s.connTracker.SetAuditSink(s.cfg.AuditSink, nodeConfig.NodeID, inboundProtocol(nodeConfig))
	}

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if !configChanged {
			if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
				var err error
				switch v := existing.(type) {
				case adapter.UpdatableInbound[option.VMessUser]:
					if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.VLESSUser]:
					if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.TrojanUser]:
					if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.Hysteria2User]:
					if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
						slots := stableHysteria2Users(s.hysteria2Users, opts.Users)
						err = v.UpdateUsers(slots)
						if err == nil {
							s.hysteria2Users = slots
						}
					}
				case adapter.UpdatableShadowsocksInbound:
					if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
						err = v.UpdateUsersByOptions(opts.Users)
					}
				case adapter.UpdatableInbound[option.TUICUser]:
					if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
						slots := stableTUICUsers(s.tuicUsers, opts.Users)
						err = v.UpdateUsers(slots)
						if err == nil {
							s.tuicUsers = slots
						}
					}
				case adapter.UpdatableInbound[option.AnyTLSUser]:
					if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.MieruUser]:
					if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[auth.User]:
					switch opts := inb.Options.(type) {
					case *option.NaiveInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.SocksInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.HTTPMixedInboundOptions:
						err = v.UpdateUsers(opts.Users)
					}
				}
				if err == nil {
					continue
				}
				nlog.Core().Warn("incremental update failed, falling back to recreate", "tag", tag, "error", err)
			}
		}

		// Config mismatch or incremental update failure: Reconstruct Inbound.
		// Remove the existing inbound first so im.Create() can bind the same port.
		// im.Create() cannot atomically swap a TCP listener — it tries to start the
		// new socket before the old one is closed, causing "address already in use".
		// The brief listen gap (< 1 ms) is far less disruptive than a full restart.
		_ = im.Remove(tag) // ignore error when tag doesn't exist yet
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
		s.hysteria2Users = nil
		if options, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
			s.hysteria2Users = append([]option.Hysteria2User(nil), options.Users...)
		}
		s.tuicUsers = nil
		if options, ok := inb.Options.(*option.TUICInboundOptions); ok {
			s.tuicUsers = append([]option.TUICUser(nil), options.Users...)
		}
	}

	nlog.Core().Debug("sing-box reloaded", "users", len(users))
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	return nil
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *SingBox) stop() {
	if s.box == nil {
		return
	}

	// Step 1: close all listen sockets so no new connections are accepted.
	// im.Close() sets m.started=false so the subsequent box.Close() call is a no-op
	// for inbounds (avoids double-close), but box.Close() still tears down routers
	// and outbounds.
	if im := service.FromContext[adapter.InboundManager](s.ctx); im != nil {
		_ = im.Close()
	}

	// Step 2: wait for in-flight connections to drain naturally (best-effort).
	if s.connTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if s.connTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything that is still open.
	s.box.Close()
	s.box = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.ctx = nil
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

// connTrackerLocked returns the connTracker under a read-optimised lock.
func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

// SetSpeedLimitFunc configures per-user bandwidth throttling.
func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

// SetDeviceLimitFunc configures per-user device limit gate-keeping.
// Connections exceeding the limit are rejected at connect time.
func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

// UpdateGlobalDevices updates the global device state from panel (for multi-node).
func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.UpdateGlobalDevices(users)
	}
}

// ClearGlobalDevices clears the global device state (on WS disconnect).
func (s *SingBox) ClearGlobalDevices() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.ClearGlobalDevices()
	}
}

// ─── User management (non-disruptive) ───────────────────────────────────────

// AddUsers hot-swaps users into running inbounds. Zero connection disruption.
func (s *SingBox) AddUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.ID] = struct{}{}
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, dup := existing[u.ID]; !dup {
			toAdd = append(toAdd, u)
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	merged := append(append([]model.UserSpec{}, s.users...), toAdd...)
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.users = merged
	return len(toAdd), nil
}

// RemoveUsers hot-swaps users out of running inbounds. Zero connection disruption
// for remaining users.
func (s *SingBox) RemoveUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.users = kept
	return removed, nil
}

// UpdateUsers replaces the entire user set atomically via hot-swap.
func (s *SingBox) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := kernel.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits may have changed — update tracker map.
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
			s.connTracker.SetAuditSink(s.cfg.AuditSink, s.nodeConfig.NodeID, inboundProtocol(s.nodeConfig))
		}
		s.users = users
		return 0, 0, nil
	}

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.users = users
	return
}

// reloadInboundsLocked hot-swaps inbound users using UpdatableInbound.
// Must be called with s.mu held.
func (s *SingBox) reloadInboundsLocked(users []model.UserSpec) error {
	cfgMap := buildConfig(s.cfg, s.nodeConfig, users, s.tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	nopFactory := singLog.NewNOPFactory()

	// Publish the user map before the inbounds change so a HY2 session of a
	// just-added user is not closed by the tracker as unknown.
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
		s.connTracker.SetAuditSink(s.cfg.AuditSink, s.nodeConfig.NodeID, inboundProtocol(s.nodeConfig))
	}

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
			var err error
			switch v := existing.(type) {
			case adapter.UpdatableInbound[option.VMessUser]:
				if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.VLESSUser]:
				if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.TrojanUser]:
				if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.Hysteria2User]:
				if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
					slots := stableHysteria2Users(s.hysteria2Users, opts.Users)
					err = v.UpdateUsers(slots)
					if err == nil {
						s.hysteria2Users = slots
					}
				}
			case adapter.UpdatableShadowsocksInbound:
				if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
					err = v.UpdateUsersByOptions(opts.Users)
				}
			case adapter.UpdatableInbound[option.TUICUser]:
				if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
					slots := stableTUICUsers(s.tuicUsers, opts.Users)
					err = v.UpdateUsers(slots)
					if err == nil {
						s.tuicUsers = slots
					}
				}
			case adapter.UpdatableInbound[option.AnyTLSUser]:
				if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.MieruUser]:
				if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[auth.User]:
				switch opts := inb.Options.(type) {
				case *option.NaiveInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.SocksInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.HTTPMixedInboundOptions:
					err = v.UpdateUsers(opts.Users)
				}
			}
			if err == nil {
				continue
			}
			nlog.Core().Warn("incremental update failed, recreating inbound", "tag", tag, "error", err)
		}

		_ = im.Remove(tag)
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
		s.hysteria2Users = nil
		if options, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
			s.hysteria2Users = append([]option.Hysteria2User(nil), options.Users...)
		}
		s.tuicUsers = nil
		if options, ok := inb.Options.(*option.TUICInboundOptions); ok {
			s.tuicUsers = append([]option.TUICUser(nil), options.Users...)
		}
	}

	nlog.Core().Debug("sing-box users hot-swapped", "users", len(users))
	return nil
}

// ─── Observability ──────────────────────────────────────────────────────────
func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, nil, 0, nil
	}
	traffic, aliveIPs, connCount = ct.GetUserTraffic()
	return traffic, aliveIPs, connCount, nil
}

// CloseConnection force-closes a specific connection by its ID.
func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

// CloseUserConnections terminates all connections for a user UUID.
func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

// buildUserMap creates a UUID→userID mapping used by ConnTracker to attribute
// connections to the correct user. All sing-box protocols use the user's UUID
// as the inbound name/username, so this covers every protocol.
func buildUserMap(users []model.UserSpec) map[string]int {
	m := make(map[string]int, len(users))
	for _, u := range users {
		if u.UUID == "" || u.ID <= 0 {
			continue
		}
		if uid, exists := m[u.UUID]; exists && uid != u.ID {
			m[u.UUID] = 0
			continue
		}
		m[u.UUID] = u.ID
	}
	return m
}

// stableTUICUsers is the TUIC counterpart of stableHysteria2Users: a removed
// user keeps its slot with a random UUID and password that no client can
// present, so a live session's index never resolves to another account.
func stableTUICUsers(previous, users []option.TUICUser) []option.TUICUser {
	active := make(map[string]option.TUICUser, len(users))
	for _, user := range users {
		active[user.Name] = user
	}
	slots := make([]option.TUICUser, 0, len(previous)+len(users))
	for _, old := range previous {
		if user, exists := active[old.Name]; exists {
			slots = append(slots, user)
			delete(active, old.Name)
		} else {
			slots = append(slots, option.TUICUser{Name: old.Name, UUID: randomUUID(), Password: rand.Text()})
		}
	}
	for _, user := range users {
		if _, exists := active[user.Name]; exists {
			slots = append(slots, user)
			delete(active, user.Name)
		}
	}
	return slots
}

// randomUUID returns a random version 4 UUID string.
func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func stableHysteria2Users(previous, users []option.Hysteria2User) []option.Hysteria2User {
	active := make(map[string]option.Hysteria2User, len(users))
	for _, user := range users {
		active[user.Name] = user
	}
	slots := make([]option.Hysteria2User, 0, len(previous)+len(users))
	for _, old := range previous {
		if user, exists := active[old.Name]; exists {
			slots = append(slots, user)
			delete(active, old.Name)
		} else {
			// Never compact or reuse an index while its QUIC session may live.
			// An empty password would enable anonymous HY2 authentication.
			slots = append(slots, option.Hysteria2User{Name: old.Name, Password: rand.Text()})
		}
	}
	for _, user := range users {
		if _, exists := active[user.Name]; exists {
			slots = append(slots, user)
			delete(active, user.Name)
		}
	}
	return slots
}
