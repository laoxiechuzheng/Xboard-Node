package xray

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	xrayProxy "github.com/xtls/xray-core/proxy"
	vlessInbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/transport/internet"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/protobuf/proto"

	"github.com/cedar2025/xboard-node/internal/model"
)

const (
	sharedRealityTransport = "xboard-shared-reality"
	sharedRealityTaskKey   = "xboard.node.shared-reality.tasks"
)

type sharedRealityContextKey struct{}

var (
	sharedRealitySequence atomic.Uint64
	sharedRealityPending  sync.Map
	sharedRealityMu       sync.Mutex
	sharedRealityGroups   = make(map[string]*sharedRealityGroup)
	sharedTaskProbeOnce   sync.Once
	sharedTaskProbeOK     bool
)

type sharedRealityTaskProbe struct{ observed atomic.Bool }

func (p *sharedRealityTaskProbe) TaskStarted() { p.observed.Store(true) }
func (*sharedRealityTaskProbe) TaskFinished()  {}

func sharedRealityNativeTasksAvailable() bool {
	sharedTaskProbeOnce.Do(func() {
		probe := new(sharedRealityTaskProbe)
		ctx := context.WithValue(context.Background(), sharedRealityTaskKey, probe)
		_ = task.Run(ctx, func() error { return nil })
		sharedTaskProbeOK = probe.observed.Load()
	})
	return sharedTaskProbeOK
}

func init() {
	common.Must(internet.RegisterTransportListener(sharedRealityTransport, listenSharedReality))
	configType := reflect.TypeOf((*vlessInbound.Config)(nil))
	original := typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = func(ctx context.Context, cfg interface{}) (interface{}, error) {
		object, err := original(ctx, cfg)
		runtime, shared := ctx.Value(sharedRealityContextKey{}).(*sharedRealityRuntime)
		if err != nil || !shared {
			return object, err
		}
		inbound, ok := object.(xrayProxy.Inbound)
		if !ok {
			return nil, fmt.Errorf("shared REALITY requires a VLESS inbound")
		}
		users, ok := object.(xrayProxy.UserManager)
		if !ok {
			return nil, fmt.Errorf("shared REALITY requires a VLESS user manager")
		}
		return &sharedRealityProxy{Inbound: inbound, UserManager: users, runtime: runtime}, nil
	}
}

func (x *Xray) sharedRealityEnabled() bool {
	return x.cfg.SharedReality != nil && x.cfg.SharedReality.Enabled
}

func (x *Xray) sharedRealityLedgerEnabled() bool {
	return x.sharedLedger.Load()
}

func isSharedRealityNode(nc *model.NodeSpec) bool {
	return nc != nil && nc.Protocol == "vless" && nc.TLS == 2 &&
		(nc.Network == "" || nc.Network == "tcp" || nc.Network == "raw")
}

func validateSharedRealityNode(nc *model.NodeSpec) error {
	if nc == nil || nc.Protocol != "vless" || nc.TLS != 2 {
		return fmt.Errorf("shared REALITY only supports VLESS+REALITY")
	}
	if nc.Network != "" && nc.Network != "tcp" && nc.Network != "raw" {
		return fmt.Errorf("shared REALITY requires TCP/RAW transport")
	}
	if nc.GetProxyProtocol() {
		return fmt.Errorf("shared REALITY does not support PROXY protocol")
	}
	key, ok := nc.TLSSettings["private_key"].(string)
	if !ok {
		return fmt.Errorf("shared REALITY requires tls_settings.private_key")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("shared REALITY tls_settings.private_key must be a valid X25519 key")
	}
	var ids []string
	switch value := nc.TLSSettings["short_id"].(type) {
	case string:
		ids = []string{value}
	case []string:
		ids = value
	case []interface{}:
		for _, item := range value {
			id, ok := item.(string)
			if !ok {
				return fmt.Errorf("shared REALITY short_id entries must be hex strings")
			}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return fmt.Errorf("shared REALITY requires nonempty tls_settings.short_id")
	}
	seen := make(map[[8]byte]bool, len(ids))
	for _, id := range ids {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) == 0 || len(decoded) > 8 {
			return fmt.Errorf("shared REALITY short_id must contain 2 to 16 hex characters with even length")
		}
		var padded [8]byte
		copy(padded[:], decoded)
		if seen[padded] {
			return fmt.Errorf("shared REALITY short_id entries must be unique after zero padding")
		}
		seen[padded] = true
	}
	return nil
}

// The private transport marker identifies a generation, not a credential. No
// transport registry mutation is needed after package initialization.
func (x *Xray) prepareSharedReality(pb *xrayCore.Config) (*sharedRealityRuntime, error) {
	if len(pb.Inbound) != 1 {
		return nil, fmt.Errorf("shared REALITY requires exactly one managed inbound")
	}
	object, err := pb.Inbound[0].ReceiverSettings.GetInstance()
	if err != nil {
		return nil, fmt.Errorf("shared REALITY receiver settings are invalid")
	}
	receiver, ok := object.(*proxyman.ReceiverConfig)
	if !ok || receiver.StreamSettings == nil {
		return nil, fmt.Errorf("shared REALITY receiver has no stream settings")
	}
	stream := receiver.StreamSettings
	memory, err := internet.ToMemoryStreamConfig(stream)
	if err != nil || memory.ProtocolName != "tcp" || memory.SecurityType != "xray.transport.internet.reality.Config" {
		return nil, fmt.Errorf("shared REALITY requires an unmodified TCP/RAW REALITY stream")
	}
	tcpSettings, ok := memory.ProtocolSettings.(*tcp.Config)
	if !ok || tcpSettings.HeaderSettings != nil || tcpSettings.AcceptProxyProtocol || memory.TcpmaskManager != nil ||
		(memory.SocketSettings != nil && (memory.SocketSettings.AcceptProxyProtocol || memory.SocketSettings.Tproxy != internet.SocketConfig_Off)) {
		return nil, fmt.Errorf("shared REALITY does not support TCP headers, masks, PROXY protocol or transparent proxying")
	}
	runtime := &sharedRealityRuntime{
		owner: x, token: strconv.FormatUint(sharedRealitySequence.Add(1), 10),
		accepting: true, connections: make(map[stat.Connection]context.CancelFunc),
	}
	stream.ProtocolName = sharedRealityTransport
	stream.TransportSettings = []*internet.TransportConfig{{
		ProtocolName: sharedRealityTransport,
		Settings: serial.ToTypedMessage(&tcp.Config{HeaderSettings: &serial.TypedMessage{
			Type: sharedRealityTransport, Value: []byte(runtime.token),
		}}),
	}}
	pb.Inbound[0].ReceiverSettings = serial.ToTypedMessage(receiver)
	sharedRealityPending.Store(runtime.token, runtime)
	return runtime, nil
}

type sharedRealityProxy struct {
	xrayProxy.Inbound
	xrayProxy.UserManager
	runtime *sharedRealityRuntime
}

func (p *sharedRealityProxy) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	ctx = context.WithValue(ctx, sharedRealityTaskKey, p.runtime)
	ctx, cancel := context.WithCancel(ctx)
	p.runtime.mu.Lock()
	if !p.runtime.accepting {
		p.runtime.mu.Unlock()
		cancel()
		return fmt.Errorf("shared REALITY logical node is no longer accepting connections")
	}
	p.runtime.connections[conn] = cancel
	p.runtime.mu.Unlock()
	defer func() {
		cancel()
		// Waiters harvest stats only after the actual transport has closed.
		conn.Close()
		p.runtime.mu.Lock()
		delete(p.runtime.connections, conn)
		p.runtime.mu.Unlock()
	}()
	return p.Inbound.Process(ctx, network, conn, dispatcher)
}

func (p *sharedRealityProxy) Close() error {
	p.runtime.disableAndCloseConnections()
	return common.Close(p.Inbound)
}

type sharedRealityRuntime struct {
	owner       *Xray
	token       string
	lease       *sharedRealityLease
	mu          sync.Mutex
	accepting   bool
	connections map[stat.Connection]context.CancelFunc
	tasks       int
}

func (r *sharedRealityRuntime) TaskStarted() {
	r.mu.Lock()
	r.tasks++
	r.mu.Unlock()
}

func (r *sharedRealityRuntime) TaskFinished() {
	r.mu.Lock()
	r.tasks--
	r.mu.Unlock()
}

func (r *sharedRealityRuntime) stopAccepting() {
	r.mu.Lock()
	r.accepting = false
	r.mu.Unlock()
}

func (r *sharedRealityRuntime) disableAndCloseConnections() {
	r.mu.Lock()
	r.accepting = false
	connections := make(map[stat.Connection]context.CancelFunc, len(r.connections))
	for conn, cancel := range r.connections {
		connections[conn] = cancel
	}
	r.mu.Unlock()
	for conn, cancel := range connections {
		cancel()
		conn.Close()
	}
}

func (r *sharedRealityRuntime) activeConnections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.connections)
}

func (r *sharedRealityRuntime) wait(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for r.pendingWork() > 0 && (timeout <= 0 || time.Now().Before(deadline)) {
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *sharedRealityRuntime) pendingWork() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.connections) + r.tasks
}

type sharedRealitySnapshot struct {
	targets map[[8]byte]*sharedRealityLease
	direct  *sharedRealityLease
}

type sharedRealityGroup struct {
	listener   net.Listener
	key        string
	direct     bool
	members    map[*sharedRealityLease]bool
	snapshot   atomic.Pointer[sharedRealitySnapshot]
	ctx        context.Context
	cancel     context.CancelFunc
	handshakes chan struct{}
	pending    sync.Map
}

type sharedRealityLease struct {
	group    *sharedRealityGroup
	original *sharedRealityGroup
	key      string
	runtime  *sharedRealityRuntime
	ids      [][8]byte
	handler  internet.ConnHandler
	config   *goreality.Config
	active   bool
	closed   bool
}

func listenSharedReality(ctx context.Context, address xnet.Address, port xnet.Port, stream *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	transport, ok := stream.ProtocolSettings.(*tcp.Config)
	if !ok || transport.HeaderSettings == nil || transport.HeaderSettings.Type != sharedRealityTransport {
		return nil, fmt.Errorf("shared REALITY runtime marker is missing")
	}
	value, ok := sharedRealityPending.Load(string(transport.HeaderSettings.Value))
	if !ok {
		return nil, fmt.Errorf("shared REALITY runtime is not registered")
	}
	runtime := value.(*sharedRealityRuntime)
	rc := xreality.ConfigFromStreamSettings(stream)
	if rc == nil || len(rc.ShortIds) == 0 {
		return nil, fmt.Errorf("shared REALITY security settings are missing")
	}
	base := proto.Clone(rc).(*xreality.Config)
	base.Show = false
	base.MasterKeyLog = "none"
	shared := runtime.owner.cfg.SharedReality
	listenIP, listenPort := shared.ListenIP, shared.ListenPort
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	if listenPort == 0 {
		listenPort = 443
	}
	if net.ParseIP(listenIP) == nil || listenPort < 1 || listenPort > 65535 || int(port) == listenPort {
		return nil, fmt.Errorf("shared REALITY requires a valid global address and an original node port different from the global port")
	}
	key := net.JoinHostPort(net.ParseIP(listenIP).String(), strconv.Itoa(listenPort))
	originalKey := net.JoinHostPort(address.IP().String(), strconv.Itoa(int(port)))
	lease := &sharedRealityLease{key: key, runtime: runtime, handler: handler, config: base.GetREALITYConfig()}
	lease.config.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	for _, id := range rc.ShortIds {
		if len(id) != 8 {
			return nil, fmt.Errorf("shared REALITY Short ID is invalid")
		}
		lease.ids = append(lease.ids, [8]byte(id))
	}
	sharedRealityMu.Lock()
	defer sharedRealityMu.Unlock()
	group := sharedRealityGroups[key]
	if group != nil {
		if group.direct {
			return nil, fmt.Errorf("shared REALITY global port conflicts with an original node listener")
		}
		for member := range group.members {
			if member.runtime.owner == runtime.owner {
				continue
			}
			for _, existing := range member.ids {
				for _, incoming := range lease.ids {
					if existing == incoming {
						return nil, fmt.Errorf("shared REALITY Short ID is already assigned to another logical node on %s", key)
					}
				}
			}
		}
	}
	original := sharedRealityGroups[originalKey]
	if original != nil {
		if !original.direct {
			return nil, fmt.Errorf("shared REALITY original node port conflicts with a global listener")
		}
		for member := range original.members {
			if member.runtime.owner != runtime.owner {
				return nil, fmt.Errorf("shared REALITY original listener is already owned by another logical node")
			}
		}
	}
	var err error
	if group == nil {
		group, err = newSharedRealityGroup(ctx, key, false, nil)
		if err != nil {
			return nil, err
		}
	}
	if original == nil {
		original, err = newSharedRealityGroup(ctx, originalKey, true, stream.SocketSettings)
		if err != nil {
			if len(group.members) == 0 {
				group.closeLocked()
			}
			return nil, err
		}
	}
	lease.group = group
	lease.original = original
	group.members[lease] = true
	original.members[lease] = true
	runtime.lease = lease
	go goreality.DetectPostHandshakeRecordsLens(lease.config)
	return lease, nil
}

func newSharedRealityGroup(ctx context.Context, key string, direct bool, socket *internet.SocketConfig) (*sharedRealityGroup, error) {
	address, err := net.ResolveTCPAddr("tcp", key)
	if err != nil {
		return nil, fmt.Errorf("shared REALITY listen address is invalid")
	}
	var listener net.Listener
	if direct {
		if socket != nil {
			socket = proto.Clone(socket).(*internet.SocketConfig)
		}
		listener, err = internet.ListenSystem(ctx, address, socket)
	} else {
		// Xray's ListenSystem enables SO_REUSEPORT unconditionally. The
		// global entry must instead reject another process owning this port.
		lc := net.ListenConfig{KeepAlive: -1}
		network := "tcp"
		if address.IP.To4() != nil {
			network = "tcp4"
		}
		listener, err = lc.Listen(ctx, network, key)
	}
	if err != nil {
		return nil, fmt.Errorf("bind REALITY listener %s: %w", key, err)
	}
	groupCtx, cancel := context.WithCancel(context.Background())
	group := &sharedRealityGroup{
		listener: listener, key: key, direct: direct, members: make(map[*sharedRealityLease]bool),
		ctx: groupCtx, cancel: cancel, handshakes: make(chan struct{}, 256),
	}
	sharedRealityGroups[key] = group
	group.publishLocked()
	go group.accept()
	return group, nil
}

func (g *sharedRealityGroup) publishLocked() {
	targets := make(map[[8]byte]*sharedRealityLease)
	var direct *sharedRealityLease
	for lease := range g.members {
		if !lease.active || lease.closed {
			continue
		}
		for _, id := range lease.ids {
			targets[id] = lease
		}
		direct = lease
	}
	g.snapshot.Store(&sharedRealitySnapshot{targets: targets, direct: direct})
}

func (l *sharedRealityLease) activate() {
	sharedRealityMu.Lock()
	defer sharedRealityMu.Unlock()
	for member := range l.group.members {
		if member != l && member.runtime.owner == l.runtime.owner {
			member.active = false
			member.runtime.stopAccepting()
			member.closed = true
			delete(l.group.members, member)
			delete(member.original.members, member)
			if member.original != l.original {
				if len(member.original.members) == 0 {
					member.original.closeLocked()
				} else {
					member.original.publishLocked()
				}
			}
		}
	}
	l.active = true
	l.group.publishLocked()
	l.original.publishLocked()
}

func (l *sharedRealityLease) Addr() net.Addr { return l.original.listener.Addr() }

func (l *sharedRealityLease) Close() error {
	sharedRealityMu.Lock()
	defer sharedRealityMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.active = false
	l.runtime.stopAccepting()
	delete(l.group.members, l)
	delete(l.original.members, l)
	for _, group := range []*sharedRealityGroup{l.group, l.original} {
		if len(group.members) > 0 {
			group.publishLocked()
		} else {
			group.closeLocked()
		}
	}
	return nil
}

func (g *sharedRealityGroup) closeLocked() {
	delete(sharedRealityGroups, g.key)
	g.cancel()
	g.pending.Range(func(conn, _ interface{}) bool {
		conn.(net.Conn).Close()
		return true
	})
	g.listener.Close()
}

func (g *sharedRealityGroup) accept() {
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if g.ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case g.handshakes <- struct{}{}:
			g.pending.Store(conn, true)
			go g.handle(conn)
		default:
			conn.Close()
		}
	}
}

func (g *sharedRealityGroup) handle(raw net.Conn) {
	defer func() {
		g.pending.Delete(raw)
		<-g.handshakes
	}()
	snapshot := g.snapshot.Load()
	if snapshot == nil || len(snapshot.targets) == 0 {
		raw.Close()
		return
	}
	// A watchdog also bounds mirrored fallback sessions. It is stopped after
	// a verified handshake so normal proxy connections have no extra deadline.
	ctx, cancel := context.WithTimeout(g.ctx, 15*time.Second)
	defer cancel()
	var coverMu sync.Mutex
	var cover net.Conn
	closeCover := func() {
		coverMu.Lock()
		conn := cover
		coverMu.Unlock()
		if conn != nil {
			conn.Close()
		}
	}
	watchdog := context.AfterFunc(ctx, func() { raw.Close(); closeCover() })
	defer watchdog()
	defer closeCover()
	target := snapshot.direct
	input := raw
	if !g.direct {
		var err error
		input, target, err = selectSharedRealityTarget(raw, snapshot.targets)
		if err != nil {
			raw.Close()
			return
		}
	}
	if target == nil {
		raw.Close()
		return
	}
	handshakeConfig := target.config.Clone()
	baseDial := handshakeConfig.DialContext
	// REALITY uses ctx for dialing, but its cover reads are otherwise not
	// cancelled. Track that socket as well as the original client socket.
	handshakeConfig.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		conn, err := baseDial(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		coverMu.Lock()
		if err := ctx.Err(); err != nil {
			coverMu.Unlock()
			conn.Close()
			return nil, err
		}
		cover = conn
		coverMu.Unlock()
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	conn, err := goreality.Server(ctx, input, handshakeConfig)
	if err != nil {
		raw.Close()
		return
	}
	if !watchdog() || ctx.Err() != nil {
		conn.Close()
		return
	}
	if snapshot.targets[conn.ClientShortId] != target {
		conn.Close()
		return
	}
	// Native Xray workers and Vision receive the original concrete REALITY
	// connection. There is no plaintext forwarder or additional TLS layer.
	target.handler(&xreality.Conn{Conn: conn})
}
