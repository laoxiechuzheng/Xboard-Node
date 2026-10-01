package xray

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/cedar2025/xboard-node/internal/model"
)

type auditLogger struct {
	enabled atomic.Bool
	context atomic.Pointer[auditContext]
	remote  audit.Sink
	output  *auditLogger
}

type auditContext struct {
	protocol string
	nodeID   int
	users    map[string]auditUser
}

type auditUser struct {
	ID   int    `json:"user_id"`
	UUID string `json:"uuid"`
}

func newAuditLogger(remote audit.Sink) *auditLogger {
	if remote == nil {
		return nil
	}
	a := &auditLogger{remote: remote}
	a.enabled.Store(true)
	a.context.Store(&auditContext{users: make(map[string]auditUser)})
	return a
}

func newRemoteAudit(remote audit.Sink) *auditLogger { return newAuditLogger(remote) }

func (a *auditLogger) Close() {
	if a == nil {
		return
	}
	a.enabled.Store(false)
}

func (a *auditLogger) UpdateContext(nc *model.NodeSpec, users []model.UserSpec) {
	if a == nil {
		return
	}
	m := make(map[string]auditUser, len(users)*2)
	for _, u := range users {
		au := auditUser{ID: u.ID, UUID: u.UUID}
		m[userEmail(u.ID)] = au
		m[u.UUID] = au
	}

	protocol := ""
	nodeID := 0
	if nc != nil {
		protocol = audit.NormalizeProtocol(nc.Protocol, nc.Version)
		nodeID = nc.NodeID
	}

	a.context.Store(&auditContext{users: m, protocol: protocol, nodeID: nodeID})
}

func (a *auditLogger) forContext(nc *model.NodeSpec, users []model.UserSpec) *auditLogger {
	if a == nil {
		return nil
	}
	scoped := &auditLogger{output: a}
	scoped.enabled.Store(true)
	scoped.UpdateContext(nc, users)
	return scoped
}

func (a *auditLogger) LogAccepted(email, sourceIP string, dest net.Destination) {
	if a == nil {
		return
	}
	network := ""
	if dest.Network == net.Network_TCP {
		network = "tcp"
	} else if dest.Network == net.Network_UDP {
		network = "udp"
	} else {
		network = fmt.Sprint(dest.Network)
	}
	target := strings.TrimPrefix(dest.String(), network+":")

	if !a.enabled.Load() {
		return
	}
	ctx := a.context.Load()
	if ctx == nil {
		return
	}
	au := ctx.users[email]
	output := a.output
	if output == nil {
		output = a
	}
	if !output.enabled.Load() {
		return
	}
	if output.remote == nil || au.ID <= 0 {
		return
	}
	output.remote.Record(audit.Event{Time: time.Now().UTC(), Event: "accepted", UserID: au.ID, UUID: au.UUID, NodeID: ctx.nodeID, Core: "xray", Protocol: ctx.protocol, Network: network, SourceIP: sourceIP, Target: target})
}
