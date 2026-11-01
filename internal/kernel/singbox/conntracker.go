package singbox

import (
	"context"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections
}

// addConn registers a new connection from sourceIP.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Architecture: instead of maintaining a per-connection map (O(connections)),
// it maintains per-user atomic counters and IP refcount sets (O(users)).
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
type ConnTracker struct {
	usersMu sync.RWMutex
	users   map[int]*userStats       // userID → stats
	uuidMap map[string]int           // UUID → userID (for lookup in RoutedConnection)
	idUUID  map[int]string           // userID → UUID (naive authenticates by user ID)
	connMap map[string]*trackedEntry // connID → live TCP conn (force-close + idle janitor)

	// userConns indexes every live TCP and UDP connection of a known user by
	// the UUID it authenticated with, so removing or replacing that UUID cuts
	// the connections instead of letting them run on unaccounted.
	userConns map[string]*liveUserConns

	// Retain UUID ownership for this instance so an old QUIC session cannot
	// become a different panel account after a remove/add cycle. A UUID that
	// ever changed owner is recorded as 0 and refused on HY2/TUIC, whose
	// sessions authenticate by slot (see resolveUserLocked).
	uuidOwners map[string]int

	// idleTimeout is the sing-box equivalent of xray's connIdle. A TCP
	// connection with no read/write activity for this long is closed by the
	// idle janitor. 0 disables the janitor.
	idleTimeout time.Duration

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time
	auditSink        audit.Sink
	auditNodeID      int
	auditProtocol    string
}

// NewConnTracker creates a tracker.
func NewConnTracker(idleTimeout time.Duration) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		idUUID:        make(map[int]string),
		connMap:       make(map[string]*trackedEntry),
		userConns:     make(map[string]*liveUserConns),
		uuidOwners:    make(map[string]int),
		globalDevices: make(map[int]map[string]bool),
		idleTimeout:   idleTimeout,
	}
}

// trackedEntry is a live TCP connection together with its last activity
// timestamp. lastSeen is updated from the data path (Read/Write/CountFunc),
// so it measures real traffic, not connection setup.
type trackedEntry struct {
	conn     net.Conn
	lastSeen atomic.Int64 // unix nanoseconds
}

func (e *trackedEntry) touch() {
	e.lastSeen.Store(time.Now().UnixNano())
}

// liveUserConns is the set of live connections authenticated as one UUID.
type liveUserConns struct {
	userID int
	conns  map[string]userConn // connID → conn
}

// userConn is a tracked connection that can be cut when its user is removed.
type userConn interface {
	kick()
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Old users that are no longer present keep
// their stats (traffic not yet reported), but every live connection that
// authenticated with a UUID no longer mapped to the same user — a removed
// user, or the old UUID of a reset subscription — is closed, and
// RoutedConnection refuses new connections presenting it.
//
// Callers publish the map BEFORE the inbounds change their credentials: a
// just-added user is then never refused, and a just-removed user that still
// authenticates against the not-yet-updated inbound is refused here.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	t.usersMu.Lock()
	revoked := t.setUserMapLocked(m)
	t.usersMu.Unlock()
	kickRevoked(revoked)
}

// RestrictUserMap narrows the user map to the entries whose UUID still maps
// to the same user in next, closing the connections of every dropped entry
// like SetUserMap. It never adds a UUID or moves one to another user: a
// draining box must lose revoked credentials but never regain one, since its
// inbounds still hold the credential set from before the restart.
func (t *ConnTracker) RestrictUserMap(next map[string]int) {
	t.usersMu.Lock()
	kept := make(map[string]int, len(t.uuidMap))
	for uuid, uid := range t.uuidMap {
		if next[uuid] == uid {
			kept[uuid] = uid
		}
	}
	revoked := t.setUserMapLocked(kept)
	t.usersMu.Unlock()
	kickRevoked(revoked)
}

// setUserMapLocked installs m and unindexes the connections it revokes; the
// caller kicks them after releasing usersMu.
func (t *ConnTracker) setUserMapLocked(m map[string]int) []userConn {
	t.uuidMap = make(map[string]int, len(m))
	t.idUUID = make(map[int]string, len(m))
	for uuid, uid := range m {
		if uuid == "" || uid <= 0 {
			continue
		}
		if owner, known := t.uuidOwners[uuid]; !known {
			t.uuidOwners[uuid] = uid
		} else if owner != uid {
			t.uuidOwners[uuid] = 0
		}
		// The current owner is resolvable everywhere; only slot-based
		// inbounds keep refusing a UUID that changed owner.
		t.uuidMap[uuid] = uid
		t.idUUID[uid] = uuid
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	// Revoked connections leave the index here, under the lock, so a later
	// SetUserMap or CloseByUUID cannot collect them again while their
	// background close is still running: each one is kicked exactly once.
	var revoked []userConn
	for uuid, set := range t.userConns {
		if t.uuidMap[uuid] != set.userID {
			for _, conn := range set.conns {
				revoked = append(revoked, conn)
			}
			delete(t.userConns, uuid)
		}
	}
	return revoked
}

func kickRevoked(revoked []userConn) {
	if len(revoked) > 0 {
		nlog.Core().Info("singbox: closing connections of removed users", "connections", len(revoked))
		kickAll(revoked)
	}
}

// kickAll closes conns in the background: a TLS close can block on a full
// send buffer for seconds, and callers hold the kernel lock.
func kickAll(conns []userConn) {
	for _, conn := range conns {
		go conn.kick()
	}
}

// resolveUserLocked maps the inbound's authenticated user name to the panel
// UUID it stands for and that UUID's current user. Every inbound names users
// by UUID except naive, whose username is the numeric user ID (buildNaive).
// Must be called with usersMu held.
func (t *ConnTracker) resolveUserLocked(metadata adapter.InboundContext) (uuid string, uid int, us *userStats) {
	uuid = metadata.User
	if metadata.InboundType == "naive" && uuid != "" {
		if id, err := strconv.Atoi(uuid); err == nil {
			uuid = t.idUUID[id]
		}
	}
	if uuid == "" {
		return "", 0, nil
	}
	uid, known := t.uuidMap[uuid]
	if !known || uid <= 0 {
		return uuid, 0, nil
	}
	// HY2 and TUIC bind a live session to a slot whose name is the UUID: a
	// UUID that moved to another user could hand an old session to the new
	// owner, so it stays refused there until the next full Start.
	if (metadata.InboundType == "hysteria2" || metadata.InboundType == "tuic") && t.uuidOwners[uuid] != uid {
		return uuid, 0, nil
	}
	return uuid, uid, t.users[uid]
}

// authenticatingInbounds are the inbound types that always name the
// authenticated user, so a connection without one is never a panel user. On
// HY2 and TUIC it is a retired slot. socks, http, mixed and naive stop
// authenticating once their user list is empty (sing's auth.NewAuthenticator
// returns nil), so there it is an anonymous client of an open proxy.
var authenticatingInbounds = map[string]bool{
	"hysteria2": true, "tuic": true, "socks": true, "http": true, "mixed": true, "naive": true,
}

// refusesUnknown reports whether a connection must be refused because its
// authenticated user is not (or no longer) a current user. Other inbound
// types may route connections with an empty metadata.User; those are served
// as before, since an empty user list does not open those protocols up.
func refusesUnknown(metadata adapter.InboundContext, us *userStats) bool {
	if us != nil {
		return false
	}
	return metadata.User != "" || authenticatingInbounds[metadata.InboundType]
}

// registerLocked indexes a live connection under its UUID. It fails when the
// UUID was removed after RoutedConnection resolved it, so SetUserMap cannot
// miss a connection that was being set up concurrently.
// Must be called with usersMu held for writing.
func (t *ConnTracker) registerLocked(uuid string, uid int, connID string, conn userConn) bool {
	if t.uuidMap[uuid] != uid {
		return false
	}
	set := t.userConns[uuid]
	if set == nil {
		set = &liveUserConns{userID: uid, conns: make(map[string]userConn)}
		t.userConns[uuid] = set
	}
	set.conns[connID] = conn
	return true
}

func (t *ConnTracker) SetAuditSink(sink audit.Sink, nodeID int, protocol string) {
	t.usersMu.Lock()
	t.auditSink = sink
	t.auditNodeID = nodeID
	t.auditProtocol = protocol
	t.usersMu.Unlock()
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uuid, uid, us := t.resolveUserLocked(metadata)
	auditSink, auditNodeID, auditProtocol := t.auditSink, t.auditNodeID, t.auditProtocol
	t.usersMu.RUnlock()

	// A user that is not in the map was removed, had its UUID reset, or is a
	// retired/ambiguous slot: it must never be served or go unaccounted. This
	// also refuses new streams of a session that authenticated before the
	// removal (AnyTLS sessions, multiplexed streams, QUIC connections).
	if refusesUnknown(metadata, us) {
		closeAnyTLSSession(conn)
		_ = conn.Close()
		return conn
	}
	if metadata.InboundType == "hysteria2" {
		auditProtocol = "hysteria2"
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}
	if auditSink != nil && uid > 0 {
		auditSink.Record(audit.Event{UserID: uid, UUID: uuid, NodeID: auditNodeID, Core: "singbox", Protocol: auditProtocol, Network: "tcp", SourceIP: sourceIP, Target: metadata.Destination.String()})
	}

	// Register connection
	if us != nil {
		us.addConn(sourceIP)
	}

	connID := t.nextID()

	// Store a placeholder for force-close support and the idle janitor. The
	// wrapper is assigned below so closing it also cleans up per-user state.
	entry := &trackedEntry{}
	entry.touch()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tc := &trackedConn{
		Conn:     conn,
		tracker:  t,
		us:       us,
		userID:   uid,
		connID:   connID,
		sourceIP: sourceIP,
		uuid:     uuid,
		limiter:  lim,
		entry:    entry,
		ctx:      ctx,
	}
	entry.conn = tc
	t.usersMu.Lock()
	if us != nil && !t.registerLocked(uuid, uid, connID, tc) {
		t.usersMu.Unlock()
		tc.kick()
		return tc
	}
	t.connMap[connID] = entry
	t.usersMu.Unlock()
	return tc
}

// RoutedPacketConnection wraps UDP with per-user counting. UDP connections
// are not in connMap (the idle janitor is TCP-only) but are indexed per user
// in userConns, so removing a user closes them too.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uuid, uid, us := t.resolveUserLocked(metadata)
	auditSink, auditNodeID, auditProtocol := t.auditSink, t.auditNodeID, t.auditProtocol
	t.usersMu.RUnlock()

	// Same rule as RoutedConnection: unknown users are never served.
	if refusesUnknown(metadata, us) {
		closeAnyTLSSession(conn)
		_ = conn.Close()
		return conn
	}
	if metadata.InboundType == "hysteria2" {
		auditProtocol = "hysteria2"
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting UDP connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}
	if auditSink != nil && uid > 0 {
		auditSink.Record(audit.Event{UserID: uid, UUID: uuid, NodeID: auditNodeID, Core: "singbox", Protocol: auditProtocol, Network: "udp", SourceIP: sourceIP, Target: metadata.Destination.String()})
	}

	if us != nil {
		us.addConn(sourceIP)
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tc := &trackedPacketConn{
		PacketConn: conn,
		tracker:    t,
		us:         us,
		userID:     uid,
		connID:     connID,
		sourceIP:   sourceIP,
		uuid:       uuid,
		limiter:    lim,
		ctx:        ctx,
	}
	if us != nil {
		t.usersMu.Lock()
		registered := t.registerLocked(uuid, uid, connID, tc)
		t.usersMu.Unlock()
		if !registered {
			tc.kick()
		}
	}
	return tc
}

// checkDeviceGate rejects connections exceeding device limit.
// Strategy: merge local + global state when fresh; local-only when stale.
func (t *ConnTracker) checkDeviceGate(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil || limit <= 0 {
		return false
	}

	us.mu.RLock()
	localIPs := make(map[string]bool, len(us.ips))
	for ip := range us.ips {
		localIPs[ip] = true
	}
	localCount := len(us.ips)
	us.mu.RUnlock()

	// Already known locally
	if localIPs[sourceIP] {
		return false
	}

	// Check global state freshness
	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()

	// Stale or missing global state → local-only check
	if globalStale || globalIPs == nil {
		if localCount < limit {
			return false
		}
		ipList := make([]string, 0, localCount+1)
		for ip := range localIPs {
			ipList = append(ipList, ip)
		}
		ipList = append(ipList, sourceIP)
		sort.Strings(ipList)
		for i := 0; i < limit && i < len(ipList); i++ {
			if ipList[i] == sourceIP {
				return false
			}
		}
		nlog.Core().Debug("device limit: local over limit, rejecting",
			"userID", userID, "ip", sourceIP, "localIPs", localCount, "limit", limit)
		return true
	}

	// Known globally (from other node)
	if globalIPs[sourceIP] {
		return false
	}

	// Merge local + global
	allIPs := make(map[string]bool)
	for ip := range localIPs {
		allIPs[ip] = true
	}
	for ip := range globalIPs {
		allIPs[ip] = true
	}

	if len(allIPs) < limit {
		return false
	}

	// Over limit → lexicographic selection
	ipList := make([]string, 0, len(allIPs)+1)
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			return false
		}
	}
	nlog.Core().Debug("device limit: total over limit, rejecting",
		"userID", userID, "ip", sourceIP, "totalIPs", len(allIPs), "limit", limit)
	return true
}

// connIDCounter is process-wide so connection IDs stay unique across the
// current tracker and the draining ones: CloseConnection asks all of them.
var connIDCounter atomic.Int64

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(connIDCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	entry, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	if entry != nil && entry.conn != nil {
		entry.conn.Close()
	}
	return true
}

// runIdleJanitor periodically closes TCP connections that have been idle
// longer than idleTimeout. It runs until ctx is cancelled (instance shutdown).
func (t *ConnTracker) runIdleJanitor(ctx context.Context) {
	if t.idleTimeout <= 0 {
		return
	}

	interval := t.idleTimeout / 4
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	if interval > 10*time.Second {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.closeIdleConns()
		}
	}
}

// closeIdleConns closes TCP connections whose last activity is older than
// idleTimeout. UDP/QUIC connections are intentionally not tracked here.
func (t *ConnTracker) closeIdleConns() {
	cutoff := time.Now().Add(-t.idleTimeout).UnixNano()

	var stale []net.Conn
	t.usersMu.RLock()
	for _, entry := range t.connMap {
		if entry != nil && entry.conn != nil && entry.lastSeen.Load() <= cutoff {
			stale = append(stale, entry.conn)
		}
	}
	t.usersMu.RUnlock()

	for _, conn := range stale {
		// Close is idempotent; the trackedConn.Close wrapper cleans up the
		// per-user IP refcount and removes the connMap entry.
		_ = conn.Close()
	}
}

// CloseByUUID force-closes every live TCP and UDP connection that
// authenticated with uuid (and the AnyTLS session carrying it) in the
// background, and returns how many it is closing. It does not stop the UUID
// from connecting again: removing it from the user map (SetUserMap) does
// that, and closes the connections by itself.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.Lock()
	var conns []userConn
	if set := t.userConns[uuid]; set != nil {
		for _, conn := range set.conns {
			conns = append(conns, conn)
		}
		// Unindex now so each connection is kicked once (see SetUserMap).
		delete(t.userConns, uuid)
	}
	t.usersMu.Unlock()
	kickAll(conns)
	return len(conns)
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection from connMap and the per-user index
// on close.
func (t *ConnTracker) removeConnRef(uuid, connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	if set := t.userConns[uuid]; set != nil {
		delete(set.conns, connID)
		if len(set.conns) == 0 {
			delete(t.userConns, uuid)
		}
	}
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a Writer with non-blocking rate limiting.
// Uses AllowN for instant checks and context-aware waiting when needed.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

// Write implements io.Writer with rate limiting.
func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	// Truncate to burst size
	if burst := w.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	// Fast path: check if tokens available (non-blocking)
	if w.limiter.AllowN(time.Now(), len(b)) {
		return w.writer.Write(b)
	}

	// Slow path: wait for tokens with context cancellation support
	resv := w.limiter.ReserveN(time.Now(), len(b))
	if delay := resv.Delay(); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Tokens available, proceed
		case <-w.ctx.Done():
			resv.Cancel()
			return 0, w.ctx.Err()
		}
	}

	return w.writer.Write(b)
}

// RateLimitedReadCloser wraps a Reader with non-blocking rate limiting.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// Read implements io.Reader with rate limiting.
func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	// Truncate to burst size
	if burst := r.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	n, err := r.reader.Read(b)
	if n > 0 && r.limiter != nil {
		// Fast path: check if tokens available
		if !r.limiter.AllowN(time.Now(), n) {
			// Slow path: wait with context cancellation
			resv := r.limiter.ReserveN(time.Now(), n)
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-r.ctx.Done():
					resv.Cancel()
					return n, r.ctx.Err()
				}
			}
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker  *ConnTracker
	us       *userStats // per-user stats (upload/download atomics + IP tracking)
	userID   int        // user ID for device tracking
	connID   string
	sourceIP string
	uuid     string // credential the user authenticated with (userConns key)
	limiter  *rate.Limiter
	entry    *trackedEntry // nil for connections created before the idle janitor existed
	ctx      context.Context
	closed   atomic.Bool
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.entry != nil {
		c.entry.touch()
	}
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			// Non-blocking rate limiting
			if !c.limiter.AllowN(time.Now(), n) {
				resv := c.limiter.ReserveN(time.Now(), n)
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return n, c.ctx.Err()
					}
				}
			}
		}
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	if c.entry != nil {
		c.entry.touch()
	}
	// Apply rate limiting before write
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
		// Non-blocking check first
		if !c.limiter.AllowN(time.Now(), len(b)) {
			resv := c.limiter.ReserveN(time.Now(), len(b))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return 0, c.ctx.Err()
				}
			}
		}
	}

	n, err := c.Conn.Write(b)
	if n > 0 && c.us != nil {
		c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.uuid, c.connID)
	}
	return c.Conn.Close()
}

// kick closes the connection of a removed user together with the AnyTLS
// session carrying it, so the client has to authenticate again.
func (c *trackedConn) kick() {
	closeAnyTLSSession(c.Conn)
	_ = c.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	// sing-box may bypass Read/Write via UnwrapReader/UnwrapWriter, so the
	// idle timer must also be refreshed from the CountFunc data path.
	if c.limiter == nil {
		return func(n int64) {
			counter.Add(n)
			if c.entry != nil {
				c.entry.touch()
			}
		}
	}
	return func(n int64) {
		counter.Add(n)
		if c.entry != nil {
			c.entry.touch()
		}
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker  *ConnTracker
	us       *userStats
	userID   int
	connID   string
	sourceIP string
	uuid     string
	limiter  *rate.Limiter
	ctx      context.Context
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			// Non-blocking rate limiting with context cancellation
			if !c.limiter.AllowN(time.Now(), int(n)) {
				resv := c.limiter.ReserveN(time.Now(), int(n))
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return dest, c.ctx.Err()
					}
				}
			}
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return c.ctx.Err()
				}
			}
		}
	}

	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n) // 向入站写入 = 用户下载
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.uuid, c.connID)
	}
	return c.PacketConn.Close()
}

// kick closes the packet connection of a removed user, and the AnyTLS
// session of a UDP-over-TCP stream.
func (c *trackedPacketConn) kick() {
	closeAnyTLSSession(c.PacketConn)
	_ = c.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }
