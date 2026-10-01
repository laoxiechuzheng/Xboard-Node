package singbox

import (
	"context"
	"net"
	"testing"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
)

type auditCapture struct{ events []audit.Event }

func (c *auditCapture) Record(event audit.Event) { c.events = append(c.events, event) }

func TestConnTrackerAuditsTCPAndUDP(t *testing.T) {
	capture := &auditCapture{}
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-42": 42})
	tracker.SetAuditSink(capture, 7, "tuic")
	metadata := adapter.InboundContext{User: "uuid-42", Source: singM.ParseSocksaddr("203.0.113.2:1234"), Destination: singM.ParseSocksaddr("example.com:443")}
	client, server := net.Pipe()
	defer server.Close()
	tracked := tracker.RoutedConnection(context.Background(), client, metadata, nil, nil)
	defer tracked.Close()
	tracker.RoutedPacketConnection(context.Background(), nil, metadata, nil, nil)
	if len(capture.events) != 2 {
		t.Fatalf("events = %d, want 2", len(capture.events))
	}
	for i, network := range []string{"tcp", "udp"} {
		event := capture.events[i]
		if event.UserID != 42 || event.UUID != "uuid-42" || event.NodeID != 7 || event.Core != "singbox" || event.Protocol != "tuic" || event.Network != network || event.SourceIP != "203.0.113.2" || event.Target != "example.com:443" {
			t.Fatalf("wrong %s event: %+v", network, event)
		}
	}
}
