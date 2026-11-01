package controlplane

import (
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

// MailboxState is the coalesced snapshot drained from a NodeMailbox.
type MailboxState struct {
	Config         *model.NodeSpec
	Users          []model.UserSpec
	DeviceUsers    map[int][]string
	HasConfig      bool
	HasUsers       bool
	HasDevices     bool
	NeedsReconcile bool
	// TouchedUserIDs lists the users named by the deltas folded into Users
	// since the last drain; TouchedAllUsers means a full snapshot was among
	// them. The service uses them to tell which pulled users may be older
	// than these events.
	TouchedUserIDs  []int
	TouchedAllUsers bool
}

// NodeMailbox buffers WS events for a machine-mode node service that is not
// yet ready to process them. Events are coalesced (latest-wins) and drained
// as a single snapshot once the service marks the mailbox as ready.
type NodeMailbox struct {
	mu               sync.Mutex
	ready            bool
	config           *model.NodeSpec
	users            []model.UserSpec
	deviceUsers      map[int][]string
	dirtyConfig      bool
	dirtyUsers       bool
	dirtyDevices     bool
	needsReconcile   bool
	hasFullUserState bool
	// pendingFullUsers is set while users holds an undrained WS full snapshot.
	pendingFullUsers bool
	// userGen counts received user events (full snapshots and deltas);
	// fullUsersGen is the generation of the undrained full snapshot. A pull
	// records userGen when it starts, so ReplaceBaseline can tell events the
	// pulled list already reflects from events received during the pull.
	userGen      uint64
	fullUsersGen uint64
	// pendingDeltas are the user deltas folded into users since the last
	// drain or full snapshot, kept so ReplaceBaseline can replay them.
	pendingDeltas []pendingDelta
	// touchedUserIDs and touchedAllUsers collect what the undrained user
	// events named, for MailboxState.
	touchedUserIDs  map[int]struct{}
	touchedAllUsers bool
	notifyCh        chan struct{}
}

type pendingDelta struct {
	gen    uint64
	action string
	users  []model.UserSpec
}

func NewNodeMailbox() *NodeMailbox {
	return &NodeMailbox{notifyCh: make(chan struct{}, 1)}
}

func (m *NodeMailbox) MarkReady() {
	m.mu.Lock()
	m.ready = true
	m.mu.Unlock()
	m.notify()
}

// SeedBaseline initializes the mailbox with the REST-derived baseline so that
// subsequent delta events can be applied incrementally instead of triggering
// a full REST reconciliation.
func (m *NodeMailbox) SeedBaseline(users []model.UserSpec, config *model.NodeSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if users != nil && !m.hasFullUserState {
		m.users = cloneUsers(users)
		m.hasFullUserState = true
	}
	if config != nil && m.config == nil {
		m.config = cloneNodeSpec(config)
	}
}

// UserGeneration returns the number of user events received so far. A pull
// records it before reading the panel and passes it to ReplaceBaseline.
func (m *NodeMailbox) UserGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userGen
}

// ReplaceBaseline installs the user list the service just applied from a REST
// pull that started at user generation since. Deltas are folded into the
// mailbox's own list and drained as a full snapshot, so without this
// REST-only changes (expiry, a missed push) would be undone by the next
// delta.
//
// Undrained events received before the pull started are older than the
// pulled list and are dropped; when only those were pending, nothing is left
// to drain. Undrained events received during the pull may
// be newer, so deltas among them are replayed on top of the new baseline and
// a full snapshot among them is kept as is. Either way the next drain may
// differ from the pulled list, so ReplaceBaseline then returns true and the
// caller re-pulls to settle it.
func (m *NodeMailbox) ReplaceBaseline(users []model.UserSpec, since uint64) bool {
	if users == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingFullUsers && m.fullUsersGen > since {
		return true
	}
	baseline := cloneUserState(users)
	kept := m.pendingDeltas[:0]
	// Only the kept deltas still count as touching users; the service already
	// applied the pulled list, which supersedes the dropped events.
	m.touchedUserIDs = nil
	m.touchedAllUsers = false
	for _, delta := range m.pendingDeltas {
		if delta.gen <= since {
			continue
		}
		applyUserDelta(&baseline, delta.action, delta.users)
		kept = append(kept, delta)
		if m.touchedUserIDs == nil {
			m.touchedUserIDs = make(map[int]struct{}, len(delta.users))
		}
		for _, user := range delta.users {
			m.touchedUserIDs[user.ID] = struct{}{}
		}
	}
	m.pendingDeltas = kept
	m.pendingFullUsers = false
	m.users = baseline
	m.hasFullUserState = true
	if len(kept) == 0 {
		// The service already applied this list: nothing left to drain.
		m.dirtyUsers = false
	}
	return len(kept) > 0
}

func (m *NodeMailbox) Apply(event Event) {
	m.mu.Lock()
	changed := false

	switch event.Type {
	case EventSyncConfig:
		if event.Config != nil {
			m.config = cloneNodeSpec(event.Config)
			m.dirtyConfig = true
			changed = true
		}
	case EventSyncUsers:
		if event.Users != nil {
			m.userGen++
			m.users = cloneUsers(event.Users)
			m.dirtyUsers = true
			m.hasFullUserState = true
			m.pendingFullUsers = true
			m.fullUsersGen = m.userGen
			m.pendingDeltas = nil
			m.touchedAllUsers = true
			changed = true
		}
	case EventSyncDevices:
		if event.DeviceUsers != nil {
			m.deviceUsers = cloneDeviceUsers(event.DeviceUsers)
			m.dirtyDevices = true
			changed = true
		}
	case EventSyncUserDelta:
		if len(event.DeltaUsers) > 0 {
			m.userGen++
			if !m.hasFullUserState {
				m.needsReconcile = true
				changed = true
			} else if !applyUserDelta(&m.users, event.DeltaAction, event.DeltaUsers) {
				m.needsReconcile = true
				changed = true
			} else {
				m.pendingDeltas = append(m.pendingDeltas, pendingDelta{
					gen:    m.userGen,
					action: event.DeltaAction,
					users:  cloneUsers(event.DeltaUsers),
				})
				if m.touchedUserIDs == nil {
					m.touchedUserIDs = make(map[int]struct{}, len(event.DeltaUsers))
				}
				for _, user := range event.DeltaUsers {
					m.touchedUserIDs[user.ID] = struct{}{}
				}
				m.dirtyUsers = true
				changed = true
			}
		}
	}
	m.mu.Unlock()

	if changed {
		m.notify()
	}
}

func (m *NodeMailbox) notify() {
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
}

func (m *NodeMailbox) NotifyCh() <-chan struct{} { return m.notifyCh }

func (m *NodeMailbox) DrainIfReady() MailboxState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return MailboxState{}
	}
	state := MailboxState{NeedsReconcile: m.needsReconcile}
	if m.dirtyConfig && m.config != nil {
		state.Config = cloneNodeSpec(m.config)
		state.HasConfig = true
		m.dirtyConfig = false
	}
	if m.dirtyUsers {
		// A drained list is a full user state: an empty one means "no users"
		// and must stay non-nil, because the service ignores a nil list.
		state.Users = cloneUserState(m.users)
		state.HasUsers = true
		state.TouchedAllUsers = m.touchedAllUsers
		for id := range m.touchedUserIDs {
			state.TouchedUserIDs = append(state.TouchedUserIDs, id)
		}
		m.dirtyUsers = false
		m.pendingFullUsers = false
		m.pendingDeltas = nil
		m.touchedUserIDs = nil
		m.touchedAllUsers = false
	}
	if m.dirtyDevices && m.deviceUsers != nil {
		state.DeviceUsers = cloneDeviceUsers(m.deviceUsers)
		state.HasDevices = true
		m.dirtyDevices = false
	}
	m.needsReconcile = false
	return state
}

func cloneNodeSpec(spec *model.NodeSpec) *model.NodeSpec {
	if spec == nil {
		return nil
	}
	clone := *spec
	if spec.NetworkSettings != nil {
		clone.NetworkSettings = make(map[string]interface{}, len(spec.NetworkSettings))
		for k, v := range spec.NetworkSettings {
			clone.NetworkSettings[k] = v
		}
	}
	if spec.TLSSettings != nil {
		clone.TLSSettings = make(map[string]interface{}, len(spec.TLSSettings))
		for k, v := range spec.TLSSettings {
			clone.TLSSettings[k] = v
		}
	}
	if spec.Routes != nil {
		clone.Routes = append([]model.RouteRule(nil), spec.Routes...)
	}
	if spec.CustomOutbounds != nil {
		clone.CustomOutbounds = append([]model.OutboundConfig(nil), spec.CustomOutbounds...)
	}
	if spec.CustomRoutes != nil {
		clone.CustomRoutes = make([]map[string]any, len(spec.CustomRoutes))
		for i, route := range spec.CustomRoutes {
			if route == nil {
				continue
			}
			copied := make(map[string]any, len(route))
			for k, v := range route {
				copied[k] = v
			}
			clone.CustomRoutes[i] = copied
		}
	}
	if spec.CustomRouteRules != nil {
		clone.CustomRouteRules = append([]model.CustomRouteRule(nil), spec.CustomRouteRules...)
	}
	if spec.CertConfig != nil {
		certCopy := *spec.CertConfig
		if spec.CertConfig.DNSEnv != nil {
			certCopy.DNSEnv = make(map[string]string, len(spec.CertConfig.DNSEnv))
			for k, v := range spec.CertConfig.DNSEnv {
				certCopy.DNSEnv[k] = v
			}
		}
		clone.CertConfig = &certCopy
	}
	if spec.Multiplex != nil {
		muxCopy := *spec.Multiplex
		if spec.Multiplex.Brutal != nil {
			brutalCopy := *spec.Multiplex.Brutal
			muxCopy.Brutal = &brutalCopy
		}
		clone.Multiplex = &muxCopy
	}
	return &clone
}

func cloneUsers(users []model.UserSpec) []model.UserSpec {
	if users == nil {
		return nil
	}
	cloned := make([]model.UserSpec, len(users))
	copy(cloned, users)
	return cloned
}

// cloneUserState copies a full user list, returning an empty non-nil slice
// for an empty or nil one.
func cloneUserState(users []model.UserSpec) []model.UserSpec {
	if users == nil {
		return []model.UserSpec{}
	}
	return cloneUsers(users)
}

func cloneDeviceUsers(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	cloned := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		dup := make([]string, len(ips))
		copy(dup, ips)
		cloned[uid] = dup
	}
	return cloned
}

// applyUserDelta folds a delta into a full user list. The result is never
// nil: removing the last user leaves an empty list, which still means "no
// users" to the service, while nil means "no user state".
func applyUserDelta(users *[]model.UserSpec, action string, delta []model.UserSpec) bool {
	current := cloneUserState(*users)
	index := make(map[int]int, len(current))
	for i, user := range current {
		index[user.ID] = i
	}

	switch action {
	case "add":
		for _, user := range delta {
			if idx, ok := index[user.ID]; ok {
				current[idx] = user
				continue
			}
			index[user.ID] = len(current)
			current = append(current, user)
		}
	case "remove":
		removeIDs := make(map[int]struct{}, len(delta))
		for _, user := range delta {
			removeIDs[user.ID] = struct{}{}
		}
		filtered := current[:0]
		for _, user := range current {
			if _, ok := removeIDs[user.ID]; ok {
				continue
			}
			filtered = append(filtered, user)
		}
		current = append(make([]model.UserSpec, 0, len(filtered)), filtered...)
	default:
		return false
	}

	*users = current
	return true
}
