package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

type auditLogger struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	enabled  bool
	protocol string
	nodeID   int
	users    map[string]auditUser
}

type auditUser struct {
	ID   int    `json:"user_id"`
	UUID string `json:"uuid"`
}

type auditEntry struct {
	Time     string `json:"time"`
	Event    string `json:"event"`
	UserID   int    `json:"user_id"`
	UUID     string `json:"uuid"`
	Email    string `json:"email"`
	NodeID   int    `json:"node_id,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Network  string `json:"network"`
	SourceIP string `json:"source_ip"`
	Target   string `json:"target"`
}

func newAuditLogger(path string) *auditLogger {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		nlog.Core().Error("xray audit: create log dir failed", "path", path, "error", err)
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		nlog.Core().Error("xray audit: open log failed", "path", path, "error", err)
		return nil
	}
	nlog.Core().Info("xray audit log enabled", "path", path)
	return &auditLogger{
		file:    f,
		path:    path,
		enabled: true,
		users:   make(map[string]auditUser),
	}
}

func (a *auditLogger) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		_ = a.file.Close()
		a.file = nil
	}
	a.enabled = false
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
		protocol = nc.Protocol
		nodeID = nc.NodeID
	}

	a.mu.Lock()
	a.users = m
	a.protocol = protocol
	a.nodeID = nodeID
	a.mu.Unlock()
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
	entryTime := time.Now().Format(time.RFC3339Nano)
	target := dest.String()

	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled || a.file == nil {
		return
	}
	au := a.users[email]
	entry := auditEntry{
		Time:     entryTime,
		Event:    "accepted",
		UserID:   au.ID,
		UUID:     au.UUID,
		Email:    email,
		NodeID:   a.nodeID,
		Protocol: a.protocol,
		Network:  network,
		SourceIP: sourceIP,
		Target:   target,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = a.file.Write(append(data, '\n'))
}

