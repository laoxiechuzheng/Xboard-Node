package xray

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
		links:      make(map[string]map[*liveLink]struct{}),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// It is limited to gate-keeping and connection lifecycle bookkeeping: it
// wraps a link's Writer to observe close and, for Dispatch links, the
// downlink *pipe.Reader to observe its end (see downlinkReader, which keeps
// the pipe interface mux/XUDP relies on).
//
// It is also where removed users are cut off: every dispatch of a user that
// is not (or no longer) in the configured user set is refused — this covers
// new mux/XUDP sub-streams of a session that authenticated before the
// removal — and UpdateLimits interrupts the live links of users it drops.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// limitedUsers: users with device limit > 0, protected by mu.
	// Needs deterministic IP ordering for kick decisions.
	mu           sync.RWMutex
	limitedIPs   map[string]map[string]int         // email → sourceIP → refcount
	deviceLimits map[string]int                    // email → max devices
	emailToUID   map[string]int                    // email → panel user ID; nil until configured
	credentials  map[string]string                 // email → credential the user must present (see credentialFor)
	credentialOf func(uuid string) string          // panel UUID → credential, for CloseUUID; nil means normalizeCredential
	links        map[string]map[*liveLink]struct{} // email → live dispatched links
	audit        *auditLogger

	// unlimitedIPs: users without device limit — sync.Map for lock-free access.
	// Each entry is *ipCounter{ips sync.Map}.
	unlimitedIPs sync.Map // email → *ipCounter

	connCount atomic.Int64 // total active connections tracked by dispatcher
}

// ipCounter tracks IPs for unlimited users without any lock.
type ipCounter struct {
	ips sync.Map // sourceIP → *atomic.Int64 (refcount)
}

// aliveIPs returns a snapshot of distinct IPs.
func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	id, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if id.email != "" && id.isTCP {
			d.delConn(id.email, id.sourceIP)
		}
		return nil, err
	}

	if id.email != "" {
		// The outbound side runs on its own goroutine behind pipes, so
		// interrupting this link's pipes is enough to tear it down.
		if !d.trackLink(ctx, link, id, nil) {
			return nil, errUserRevoked(id.email)
		}
		if audit := d.auditLog(); audit != nil {
			audit.LogAccepted(id.email, id.sourceIP, dest)
		}
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	id, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if id.email != "" {
		// The link reads and writes the client connection directly (VLESS
		// Vision, REALITY), where Interrupt is a no-op: revoking cancels the
		// context the outbound runs under instead. cancel is only called on
		// revocation; the context ends with the connection's parent context.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		if !d.trackLink(ctx, link, id, cancel) {
			return errUserRevoked(id.email)
		}
	}
	if err := d.innerDisp.DispatchLink(ctx, dest, link); err != nil {
		return err
	}
	if id.email != "" {
		if audit := d.auditLog(); audit != nil {
			audit.LogAccepted(id.email, id.sourceIP, dest)
		}
	}
	return nil
}

// linkIdentity is the authenticated user of one dispatch.
type linkIdentity struct {
	email    string
	cred     string // credential the session authenticated with (see accountCredential), "" if unknown
	sourceIP string
	isTCP    bool
}

func errUserRevoked(email string) error {
	return errors.New("user " + email + " is not a current user of this node")
}

// identifyAndCheck extracts user identity from the session context, refuses
// users that are not (or no longer) current, enforces device limits, and
// returns the user's identity. Returns a non-nil error only when the
// connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (linkIdentity, error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return linkIdentity{}, nil
	}
	id := linkIdentity{
		email:    si.User.Email,
		cred:     accountCredential(si.User.Account),
		sourceIP: si.Source.Address.IP().String(),
		isTCP:    dest.Network == net.Network_TCP,
	}

	// A mux/XUDP session authenticates once; its later sub-streams are only
	// stopped here once the user was removed or its UUID replaced.
	d.mu.RLock()
	admitted := d.admitsLocked(id.email, id.cred)
	d.mu.RUnlock()
	if !admitted {
		nlog.Core().Debug("xray: refusing dispatch of removed user", "email", id.email)
		return linkIdentity{}, errUserRevoked(id.email)
	}

	if d.checkDeviceLimit(id.email, id.sourceIP, id.isTCP) {
		nlog.Core().Debug("xray: device limit exceeded", "email", id.email, "ip", id.sourceIP)
		return linkIdentity{}, errors.New("device limit exceeded for " + id.email)
	}
	return id, nil
}

// admitsLocked reports whether email, authenticated with cred, is a current
// user. Until the kernel configures the user set (emailToUID == nil) every
// user is admitted, so nothing is rejected during startup.
// Must be called with mu held.
func (d *LimitDispatcher) admitsLocked(email, cred string) bool {
	if d.emailToUID == nil {
		return true
	}
	if _, ok := d.emailToUID[email]; !ok {
		return false
	}
	// The email is keyed by user ID and survives a UUID reset; the
	// credential tells the old UUID's sessions apart from the new one.
	if want := d.credentials[email]; want != "" && cred != "" && want != cred {
		return false
	}
	return true
}

// accountCredential returns the secret a session authenticated with, in the
// form credentialFor pins for the node's protocol: VLESS/VMess identify users
// by the UUID's bytes (normalised); Trojan, Shadowsocks and Hysteria by the
// exact configured string (for Shadowsocks 2022 the derived key, see
// ss2022UserKey). Other types (socks, http) return "" and are checked by
// email, plus the re-key sweep in UpdateLimits.
func accountCredential(account protocol.Account) string {
	switch a := account.(type) {
	case *vless.MemoryAccount:
		if a.ID != nil {
			return normalizeCredential(a.ID.String())
		}
	case *vmess.MemoryAccount:
		if a.ID != nil {
			return normalizeCredential(a.ID.String())
		}
	case *trojan.MemoryAccount:
		return a.Password
	case *shadowsocks.MemoryAccount:
		return a.Password
	case *ss2022.MemoryAccount:
		return a.Key
	case *hysteriaaccount.MemoryAccount:
		return a.Auth
	}
	return ""
}

// normalizeCredential maps a panel UUID to the form xray reports a VLESS or
// VMess ID in, so both sides of the comparison in admitsLocked agree.
func normalizeCredential(secret string) string {
	if id, err := uuid.ParseString(secret); err == nil {
		return id.String()
	}
	return secret
}

// liveLink is one dispatched link of an authenticated user.
type liveLink struct {
	reader buf.Reader
	writer *closeTrackingWriter
	cred   string
	cancel context.CancelFunc // DispatchLink only

	// open counts the ends (writer, and the downlink reader of a Dispatch
	// pipe link) that must finish before the link is released.
	open      atomic.Int32
	onRelease func()

	mu        sync.Mutex
	released  bool
	stopWatch func() bool // stops the context backstop registered by watch
}

// endOne records that one end of the link finished; the last one releases it.
func (l *liveLink) endOne() {
	if l.open.Add(-1) == 0 {
		l.release()
	}
}

// release runs onRelease exactly once, whichever comes first: the link's
// ends finishing, its context ending, or kill.
func (l *liveLink) release() {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	stop := l.stopWatch
	l.stopWatch = nil
	l.mu.Unlock()
	if stop != nil {
		stop()
	}
	l.onRelease()
}

// watch releases the link when ctx ends. It is registered only after the
// link is indexed, so a context that is already done cannot release it
// before it is registered; the stop function is dropped once released.
func (l *liveLink) watch(ctx context.Context) {
	stop := context.AfterFunc(ctx, l.release)
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		stop()
		return
	}
	l.stopWatch = stop
	l.mu.Unlock()
}

// kill tears the link down and releases it. It must be called without mu
// held: the release callback takes it.
func (l *liveLink) kill() {
	if l.cancel != nil {
		l.cancel()
	}
	l.writer.Interrupt()
	common.Interrupt(l.reader)
	l.release()
}

func killLinks(links []*liveLink) {
	for _, l := range links {
		l.kill()
	}
}

// trackLink records connection lifecycle so the dispatcher can release
// device-limit state when the link ends, and interrupt the link when its user
// is removed. It re-checks admission under the same lock UpdateLimits sweeps
// with, so a dispatch racing a removal cannot survive it; a link that is no
// longer admitted is torn down and false is returned.
//
// A link stays indexed (and counted) until the first of:
//   - DispatchLink (cancel != nil): its Writer, the downlink to the client,
//     closes or is interrupted;
//   - Dispatch with a *pipe.Reader downlink: both the Writer (the uplink)
//     closed and the downlink ended, so a client that half-closed its upload
//     is still cut by a removal while its download runs;
//   - Dispatch with any other reader: its Writer closes;
//   - ctx ends: the inbound returned (the proxyman worker cancels the
//     per-connection context after Process), which also covers inbounds that
//     never close the Writer (SS2022's singbridge). XUDP links are dispatched
//     under a timeout-only context their outbound outlives, so they rely on
//     their ends only.
func (d *LimitDispatcher) trackLink(ctx context.Context, link *transport.Link, id linkIdentity, cancel context.CancelFunc) bool {
	d.connCount.Add(1)

	live := &liveLink{cred: id.cred, cancel: cancel}
	live.onRelease = func() {
		d.unregisterLink(id.email, live)
		if id.isTCP {
			d.delConn(id.email, id.sourceIP)
		}
		d.connCount.Add(-1)
	}
	live.open.Store(1)
	live.writer = &closeTrackingWriter{
		Writer:  link.Writer,
		onClose: live.endOne,
	}
	link.Writer = live.writer
	if downlink, ok := link.Reader.(*pipe.Reader); ok && cancel == nil {
		live.open.Store(2)
		link.Reader = &downlinkReader{Reader: downlink, onDone: live.endOne}
	}
	live.reader = link.Reader

	d.mu.Lock()
	admitted := d.admitsLocked(id.email, id.cred)
	if admitted {
		if d.links == nil {
			d.links = make(map[string]map[*liveLink]struct{})
		}
		set := d.links[id.email]
		if set == nil {
			set = make(map[*liveLink]struct{})
			d.links[id.email] = set
		}
		set[live] = struct{}{}
	}
	d.mu.Unlock()
	if !admitted {
		live.kill()
		return false
	}
	if !session.TimeoutOnlyFromContext(ctx) {
		live.watch(ctx)
	}
	return true
}

func (d *LimitDispatcher) unregisterLink(email string, live *liveLink) {
	d.mu.Lock()
	if set := d.links[email]; set != nil {
		delete(set, live)
		if len(set) == 0 {
			delete(d.links, email)
		}
	}
	d.mu.Unlock()
}

// collectRevokedLocked removes and returns the live links whose user is no
// longer admitted, and the credential-less links of rekeyed emails (see
// UpdateLimits). Must be called with mu held for writing.
func (d *LimitDispatcher) collectRevokedLocked(rekeyed map[string]bool) []*liveLink {
	var revoked []*liveLink
	for email, set := range d.links {
		for live := range set {
			if !d.admitsLocked(email, live.cred) || (live.cred == "" && rekeyed[email]) {
				revoked = append(revoked, live)
				delete(set, live)
			}
		}
		if len(set) == 0 {
			delete(d.links, email)
		}
	}
	return revoked
}

// CloseUUID interrupts every live link that authenticated with the panel
// UUID id, and returns how many it interrupted. It does not stop the user
// from connecting again; UpdateLimits without the user does that.
func (d *LimitDispatcher) CloseUUID(id string) int {
	d.mu.Lock()
	cred := normalizeCredential(id)
	if d.credentialOf != nil {
		cred = d.credentialOf(id)
	}
	email := ""
	if uid := d.emailToUID[id]; uid > 0 {
		email = userEmail(uid)
	}
	var victims []*liveLink
	for linkEmail, set := range d.links {
		for live := range set {
			// Links of account types without a known credential are
			// matched by the email of the user that owns the UUID now.
			if (live.cred != "" && live.cred == cred) || (live.cred == "" && email != "" && linkEmail == email) {
				victims = append(victims, live)
				delete(set, live)
			}
		}
		if len(set) == 0 {
			delete(d.links, linkEmail)
		}
	}
	d.mu.Unlock()
	killLinks(victims)
	return len(victims)
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

// UpdateLimits installs the current user set: emailToUID admits users,
// deviceLimits caps their devices and credentials (email → credential, see
// credentialFor) pins the credential each email must present. Live links of
// users that are no longer admitted — removed, or authenticated with a
// replaced UUID — are interrupted, and their new dispatches are refused from
// now on.
//
// Links whose account type exposes no credential cannot be told apart by
// it, so when an email's pinned credential changes they are cut as well: the
// kernel installs the new set after removing the old account and before
// adding the new one, so they belong to the old account.
func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits map[string]int, credentials map[string]string) {
	d.mu.Lock()
	var rekeyed map[string]bool
	for email, old := range d.credentials {
		if old != "" && credentials[email] != old {
			if rekeyed == nil {
				rekeyed = make(map[string]bool)
			}
			rekeyed[email] = true
		}
	}
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.credentials = credentials
	revoked := d.collectRevokedLocked(rekeyed)
	d.mu.Unlock()

	if len(revoked) > 0 {
		nlog.Core().Info("xray: interrupting connections of removed users", "connections", len(revoked))
		killLinks(revoked)
	}
}

// setCredentialFunc sets how CloseUUID maps a panel UUID to the credential
// its sessions present; the kernel sets it with the node's protocol.
func (d *LimitDispatcher) setCredentialFunc(credentialOf func(uuid string) string) {
	d.mu.Lock()
	d.credentialOf = credentialOf
	d.mu.Unlock()
}

// credentialFunc returns the function set by setCredentialFunc, or nil.
func (d *LimitDispatcher) credentialFunc() func(uuid string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.credentialOf
}

func (d *LimitDispatcher) SetAuditLogger(a *auditLogger) {
	d.mu.Lock()
	d.audit = a
	d.mu.Unlock()
}

func (d *LimitDispatcher) auditLog() *auditLogger {
	d.mu.RLock()
	a := d.audit
	d.mu.RUnlock()
	return a
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.links = make(map[string]map[*liveLink]struct{})
	d.mu.Unlock()

	// Clear unlimited IPs
	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	d.mu.RLock()
	// Deep-copy the snapshots: both maps are mutated in place by other
	// goroutines, so iterating shared references after releasing the lock
	// races with writers ("concurrent map iteration and map write").
	emailToUID := make(map[string]int, len(d.emailToUID))
	for email, uid := range d.emailToUID {
		emailToUID[email] = uid
	}
	limitedIPs := make(map[string]map[string]int, len(d.limitedIPs))
	for email, ips := range d.limitedIPs {
		ipCopy := make(map[string]int, len(ips))
		for ip, ref := range ips {
			ipCopy[ip] = ref
		}
		limitedIPs[email] = ipCopy
	}
	d.mu.RUnlock()

	aliveIPs = make(map[int]map[string]bool)

	// Collect IPs from limited users (under RLock snapshot).
	for email, ipsMap := range limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}

	// Collect IPs from unlimited users (lock-free).
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			// Merge with limited IPs if any
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit enforces per-user device limits.
// Fast path: unlimited users use lock-free sync.Map.
// Slow path: limited users use RWMutex with deterministic IP ordering.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	d.mu.RUnlock()

	// Fast path: no device limit — use lock-free sync.Map.
	if !hasLimit || limit <= 0 {
		if isTCP {
			v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
			ic := v.(*ipCounter)

			// Increment IP refcount atomically.
			rv, _ := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
			rv.(*atomic.Int64).Add(1)
		}
		return false
	}

	// Slow path: user has device limit — need deterministic ordering.
	d.mu.RLock()
	ips := d.limitedIPs[email]
	if ips != nil && ips[sourceIP] > 0 {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			// Re-check under the write lock: delConn may have deleted the
			// per-user map between the read-lock snapshot and this write,
			// which would panic on assignment into a nil map.
			if ips := d.limitedIPs[email]; ips != nil {
				ips[sourceIP]++
			}
			d.mu.Unlock()
		}
		return false
	}

	if ips != nil && len(ips) < limit {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			if d.limitedIPs[email] == nil {
				d.limitedIPs[email] = make(map[string]int)
			}
			d.limitedIPs[email][sourceIP]++
			d.mu.Unlock()
		}
		return false
	}
	d.mu.RUnlock()

	// Over limit — need write lock for deterministic check.
	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under write lock.
	ips = d.limitedIPs[email]
	if ips == nil {
		ips = make(map[string]int)
		d.limitedIPs[email] = ips
	}

	if ips[sourceIP] > 0 {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	if len(ips) < limit {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	// Over limit — deterministic: allow lowest IPs lexicographically.
	ipList := make([]string, 0, len(ips)+1)
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			if isTCP {
				ips[sourceIP]++
			}
			return false
		}
	}
	return true
}

// delConn decrements the IP refcount when a connection closes.
func (d *LimitDispatcher) delConn(email, sourceIP string) {
	// Check if this is an unlimited user first (lock-free).
	if v, ok := d.unlimitedIPs.Load(email); ok {
		ic := v.(*ipCounter)
		if rv, ok := ic.ips.Load(sourceIP); ok {
			counter := rv.(*atomic.Int64)
			if counter.Add(-1) <= 0 {
				ic.ips.Delete(sourceIP)
			}
		}
		return
	}

	// Limited user — use write lock.
	d.mu.Lock()
	defer d.mu.Unlock()
	if ips, ok := d.limitedIPs[email]; ok {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.limitedIPs, email)
		}
	}
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}

// downlinkReader observes the end of a Dispatch link's downlink: the inbound
// reads the response from it until the outbound closes it, and interrupts it
// when the connection fails. It keeps the pipe's ReturnAnError/Recover, which
// mux uses to detach an XUDP session from its link (common/mux/session.go)
// without ending it: an error injected that way is passed through as is and
// does not count as the end.
type downlinkReader struct {
	*pipe.Reader
	onDone func()
	done   atomic.Bool
}

// injectedReadError marks an error injected through ReturnAnError while it
// travels through the pipe.
type injectedReadError struct{ err error }

func (e *injectedReadError) Error() string {
	if e.err == nil {
		return "injected read error"
	}
	return e.err.Error()
}

func (r *downlinkReader) finish() {
	if r.done.CompareAndSwap(false, true) {
		r.onDone()
	}
}

func (r *downlinkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err != nil {
		if injected, ok := err.(*injectedReadError); ok {
			return mb, injected.err
		}
		r.finish()
	}
	return mb, err
}

func (r *downlinkReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBufferTimeout(timeout)
	if err != nil && err != buf.ErrReadTimeout {
		r.finish()
	}
	return mb, err
}

func (r *downlinkReader) Interrupt() {
	r.Reader.Interrupt()
	r.finish()
}

func (r *downlinkReader) ReturnAnError(err error) {
	r.Reader.ReturnAnError(&injectedReadError{err: err})
}

func (r *downlinkReader) Recover() error {
	err := r.Reader.Recover()
	if injected, ok := err.(*injectedReadError); ok {
		return injected.err
	}
	return err
}
