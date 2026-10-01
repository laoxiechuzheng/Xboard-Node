package xray

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/net"
)

func TestRemoteAuditNormalizesHysteria2Protocol(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		version  int
		want     string
	}{
		{"hysteria", 2, "hysteria2"},
		{"hy2", 0, "hysteria2"},
		{"hysteria", 1, "hysteria"},
		{"vless", 0, "vless"},
	} {
		capture := &auditCapture{}
		recorder := newRemoteAudit(capture)
		recorder.UpdateContext(&model.NodeSpec{NodeID: 7, Protocol: tc.protocol, Version: tc.version}, []model.UserSpec{{ID: 42, UUID: "uuid-42"}})
		recorder.LogAccepted(userEmail(42), "203.0.113.2", net.UDPDestination(net.ParseAddress("example.com"), 443))
		if len(capture.events) != 1 || capture.events[0].Protocol != tc.want {
			t.Fatalf("protocol %q v%d: events = %+v, want protocol %q", tc.protocol, tc.version, capture.events, tc.want)
		}
	}
}

func TestConfigureDispatcherToleratesMissingDispatcher(t *testing.T) {
	x := New(config.KernelConfig{AuditSink: &auditCapture{}})
	x.configureDispatcher(nil, &model.NodeSpec{NodeID: 7, Protocol: "vless"}, []model.UserSpec{{ID: 42, UUID: "uuid-42"}})
}
