package singbox

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
)

// TestRoutedConnectionNoEnforceDoesNotReject verifies record-only behaviour:
// without a device-limit lookup func, an over-limit user is tracked but the
// connection is never rejected.
func TestRoutedConnectionNoEnforceDoesNotReject(t *testing.T) {
	ct := NewConnTracker(0)
	ct.SetUserMap(map[string]int{"u1": 1})

	client, server := net.Pipe()
	defer server.Close()

	md := adapter.InboundContext{
		User:   "u1",
		Source: singM.ParseSocksaddr("1.2.3.4:1000"),
	}
	out := ct.RoutedConnection(context.Background(), client, md, nil, nil)
	if out == nil {
		t.Fatal("RoutedConnection returned nil")
	}

	// If admission had rejected the conn it would be closed; a round trip
	// must still succeed.
	go func() { _, _ = server.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("connection should remain open when enforcement is disabled: %v", err)
	}
}
