package xray

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/net"
)

type auditCapture struct{ events []audit.Event }

func (c *auditCapture) Record(event audit.Event) { c.events = append(c.events, event) }

type concurrentAuditCapture struct {
	active  atomic.Int32
	max     atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *concurrentAuditCapture) Record(audit.Event) {
	active := c.active.Add(1)
	for max := c.max.Load(); active > max && !c.max.CompareAndSwap(max, active); max = c.max.Load() {
	}
	c.entered <- struct{}{}
	<-c.release
	c.active.Add(-1)
}

func TestRemoteAuditRecordDoesNotSerializeConnections(t *testing.T) {
	capture := &concurrentAuditCapture{entered: make(chan struct{}, 2), release: make(chan struct{})}
	recorder := newRemoteAudit(capture)
	recorder.UpdateContext(&model.NodeSpec{NodeID: 7, Protocol: "vless"}, []model.UserSpec{{ID: 42, UUID: "uuid-42"}})
	dest := net.TCPDestination(net.ParseAddress("example.com"), 443)
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			recorder.LogAccepted(userEmail(42), "203.0.113.2", dest)
			done <- struct{}{}
		}()
		if i == 0 {
			select {
			case <-capture.entered:
			case <-time.After(time.Second):
				t.Fatal("first audit event did not reach the sink")
			}
		}
	}
	concurrent := false
	select {
	case <-capture.entered:
		concurrent = true
	case <-time.After(time.Second):
	}
	close(capture.release)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("audit record did not finish")
		}
	}
	if !concurrent || capture.max.Load() < 2 {
		t.Fatal("concurrent connection audit calls were serialized")
	}
}

func TestRemoteAuditMapsAcceptedConnection(t *testing.T) {
	capture := &auditCapture{}
	recorder := newRemoteAudit(capture)
	recorder.UpdateContext(&model.NodeSpec{NodeID: 7, Protocol: "vless"}, []model.UserSpec{{ID: 42, UUID: "uuid-42"}})
	recorder.LogAccepted(userEmail(42), "203.0.113.2", net.TCPDestination(net.ParseAddress("example.com"), 443))
	recorder.LogAccepted("unknown", "203.0.113.2", net.TCPDestination(net.ParseAddress("example.com"), 443))
	if len(capture.events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.events))
	}
	event := capture.events[0]
	if event.UserID != 42 || event.UUID != "uuid-42" || event.NodeID != 7 || event.Core != "xray" || event.Protocol != "vless" || event.Network != "tcp" || event.SourceIP != "203.0.113.2" || event.Target != "example.com:443" {
		t.Fatalf("wrong accepted event: %+v", event)
	}
}

func TestRemoteAuditDoesNotWriteConfiguredLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection-audit.jsonl")
	x := New(config.KernelConfig{AuditLog: path, AuditSink: &auditCapture{}})
	x.audit.UpdateContext(&model.NodeSpec{NodeID: 7, Protocol: "vless"}, []model.UserSpec{{ID: 42, UUID: "uuid-42"}})
	x.audit.LogAccepted(userEmail(42), "203.0.113.2", net.TCPDestination(net.ParseAddress("example.com"), 443))
	x.audit.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("remote audit created a local log file, stat error = %v", err)
	}
}

func TestXrayOldDispatcherKeepsAuditIdentityAfterReload(t *testing.T) {
	capture := &auditCapture{}
	x := New(config.KernelConfig{AuditSink: capture})
	old := newTestDispatcher()
	x.limitDispatcher = old
	x.nodeConfig = &model.NodeSpec{NodeID: 7, Protocol: "vless"}
	x.updateDispatcherLimits([]model.UserSpec{{ID: 42, UUID: "old-uuid"}})

	current := newTestDispatcher()
	x.limitDispatcher = current
	x.nodeConfig = &model.NodeSpec{NodeID: 8, Protocol: "vmess"}
	x.updateDispatcherLimits([]model.UserSpec{{ID: 42, UUID: "new-uuid"}})

	dest := net.TCPDestination(net.ParseAddress("example.com"), 443)
	old.auditLog().LogAccepted(userEmail(42), "203.0.113.2", dest)
	current.auditLog().LogAccepted(userEmail(42), "203.0.113.3", dest)
	if len(capture.events) != 2 {
		t.Fatalf("events = %d, want 2", len(capture.events))
	}
	if event := capture.events[0]; event.NodeID != 7 || event.Protocol != "vless" || event.UUID != "old-uuid" {
		t.Fatalf("old dispatcher identity changed: %+v", event)
	}
	if event := capture.events[1]; event.NodeID != 8 || event.Protocol != "vmess" || event.UUID != "new-uuid" {
		t.Fatalf("new dispatcher identity incorrect: %+v", event)
	}
}

func TestXrayFailedReloadPreservesOldDispatcherAuditIdentity(t *testing.T) {
	capture := &auditCapture{}
	x := New(config.KernelConfig{
		AuditSink:      capture,
		CustomOutbound: []map[string]any{{"protocol": "not-a-protocol", "tag": "direct"}},
	})
	old := newTestDispatcher()
	x.limitDispatcher = old
	x.nodeConfig = &model.NodeSpec{NodeID: 7, Protocol: "vless"}
	x.updateDispatcherLimits([]model.UserSpec{{ID: 42, UUID: "old-uuid"}})

	if err := x.Reload(&model.NodeSpec{NodeID: 8, Protocol: "vmess"}, []model.UserSpec{{ID: 42, UUID: "new-uuid"}}, kernel.TLSCert{}); err == nil {
		t.Fatal("invalid replacement config unexpectedly started")
	}
	old.auditLog().LogAccepted(userEmail(42), "203.0.113.2", net.TCPDestination(net.ParseAddress("example.com"), 443))
	if len(capture.events) != 1 || capture.events[0].NodeID != 7 || capture.events[0].UUID != "old-uuid" {
		t.Fatalf("failed reload changed old dispatcher identity: %+v", capture.events)
	}
}

func TestXrayDoesNotPersistLegacyLocalAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	x := New(config.KernelConfig{AuditLog: path})
	if x.audit != nil {
		x.audit.Close()
		t.Fatal("legacy local audit_log must not enable persistent connection logging")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("legacy local audit_log created a file, stat error = %v", err)
	}
}
