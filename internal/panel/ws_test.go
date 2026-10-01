package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeWSServer simulates a minimal Workerman-style WS server for testing.
// It authenticates via token/node_id query params, sends auth.success, then
// delivers the provided events and handles pongs until the client disconnects.
func fakeWSServer(t *testing.T, events []wsMessage) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate query params
		q := r.URL.Query()
		if q.Get("token") == "" || q.Get("node_id") == "" {
			http.Error(w, "missing auth params", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Send auth.success
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}

		// Send test events
		for _, evt := range events {
			time.Sleep(50 * time.Millisecond)
			if err := conn.WriteJSON(evt); err != nil {
				return
			}
		}

		// Handle pongs/messages until connection closes
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Event == "pong" {
				// Client pong — acknowledged
			}
		}
	}))
}

func TestWSClient_ConnectAndReceiveDataEvents(t *testing.T) {
	configPayload := syncConfigPayload{
		Config:    NodeConfig{Protocol: "vless", ServerPort: 443},
		Timestamp: 1234,
	}
	usersPayload := syncUsersPayload{
		Users:     []User{{ID: 1, UUID: "abc", SpeedLimit: 100, DeviceLimit: 3}},
		Timestamp: 1235,
	}

	configData, _ := json.Marshal(configPayload)
	usersData, _ := json.Marshal(usersPayload)

	events := []wsMessage{
		{Event: WSEventSyncConfig, Data: configData},
		{Event: WSEventSyncUsers, Data: usersData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "test-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for events
	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events, got %d", n)
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}

	// Verify config event
	if received[0].Type != WSEventSyncConfig {
		t.Errorf("event[0].Type = %q, want %q", received[0].Type, WSEventSyncConfig)
	}
	if received[0].Config == nil {
		t.Fatal("event[0].Config is nil")
	}
	if received[0].Config.Protocol != "vless" {
		t.Errorf("config.Protocol = %q, want %q", received[0].Config.Protocol, "vless")
	}
	if received[0].Config.ServerPort != 443 {
		t.Errorf("config.ServerPort = %d, want 443", received[0].Config.ServerPort)
	}
	if received[0].NodeID != 1 || received[0].Config.NodeID != 1 {
		t.Errorf("config node identity: event=%d config=%d, want 1", received[0].NodeID, received[0].Config.NodeID)
	}

	// Verify users event
	if received[1].Type != WSEventSyncUsers {
		t.Errorf("event[1].Type = %q, want %q", received[1].Type, WSEventSyncUsers)
	}
	if len(received[1].Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(received[1].Users))
	}
	if received[1].Users[0].UUID != "abc" {
		t.Errorf("user.UUID = %q, want %q", received[1].Users[0].UUID, "abc")
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true while server is running")
	}
}

func TestWSClient_ConfigNodeIdentity(t *testing.T) {
	tests := []struct {
		name      string
		nodeID    int
		machineID int
		data      string
		wantID    int
	}{
		{name: "legacy_missing_ids", nodeID: 41, data: `{"config":{"protocol":"vless","server_port":443}}`, wantID: 41},
		{name: "legacy_zero_ids", nodeID: 41, data: `{"node_id":0,"config":{"node_id":0,"protocol":"vless","server_port":443}}`, wantID: 41},
		{name: "single_outer_id", nodeID: 41, data: `{"node_id":17,"config":{"protocol":"vless","server_port":443}}`, wantID: 17},
		{name: "single_nested_id", nodeID: 41, data: `{"config":{"node_id":23,"protocol":"vless","server_port":443}}`, wantID: 23},
		{name: "machine_outer_id", machineID: 9, data: `{"node_id":17,"config":{"protocol":"vless","server_port":443}}`, wantID: 17},
		{name: "machine_nested_id", machineID: 9, data: `{"config":{"node_id":23,"protocol":"vless","server_port":443}}`, wantID: 23},
		{name: "machine_matching_ids", machineID: 9, data: `{"node_id":17,"config":{"node_id":17,"protocol":"vless","server_port":443}}`, wantID: 17},
		{name: "machine_conflicting_ids_outer_wins", machineID: 9, data: `{"node_id":17,"config":{"node_id":23,"protocol":"vless","server_port":443}}`, wantID: 17},
		{name: "single_conflicting_ids_outer_wins", nodeID: 41, data: `{"node_id":17,"config":{"node_id":23,"protocol":"vless","server_port":443}}`, wantID: 17},
		{name: "weakly_typed_outer_id", machineID: 9, data: `{"node_id":"17","config":{"protocol":"vless","server_port":"443"}}`, wantID: 17},
		{name: "weakly_typed_nested_id", machineID: 9, data: `{"config":{"node_id":"23","protocol":"vless","server_port":443}}`, wantID: 23},
		{name: "nonpositive_outer_uses_nested", machineID: 9, data: `{"node_id":-1,"config":{"node_id":23,"protocol":"vless","server_port":443}}`, wantID: 23},
		{name: "machine_missing_ids_remain_unroutable", machineID: 9, data: `{"config":{"protocol":"vless","server_port":443}}`, wantID: 0},
		{name: "machine_does_not_use_single_node_fallback", nodeID: 41, machineID: 9, data: `{"config":{"protocol":"vless","server_port":443}}`, wantID: 0},
		{name: "unbound_client_missing_ids", data: `{"config":{"protocol":"vless","server_port":443}}`, wantID: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var received []WSEvent
			w := NewWSClient("", "", tt.nodeID, WSClientConfig{MachineID: tt.machineID}, func(event WSEvent) {
				received = append(received, event)
			}, nil, nil)
			w.handleMessage(wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(tt.data)})
			if len(received) != 1 || received[0].Config == nil {
				t.Fatalf("expected one config event, got %+v", received)
			}
			event := received[0]
			if event.NodeID != tt.wantID {
				t.Errorf("event.NodeID = %d, want %d", event.NodeID, tt.wantID)
			}
			if event.Config.NodeID != tt.wantID {
				t.Errorf("config.NodeID = %d, want %d", event.Config.NodeID, tt.wantID)
			}
			if event.Type != WSEventSyncConfig || event.Config.Protocol != "vless" || event.Config.ServerPort != 443 {
				t.Errorf("unexpected config event: %+v config=%+v", event, event.Config)
			}
		})
	}
}

func TestWSClient_ConfigInvalidPayloadsAreDropped(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "malformed_json", data: `{`},
		{name: "array_envelope", data: `[]`},
		{name: "null_envelope", data: `null`},
		{name: "missing_config", data: `{"node_id":17}`},
		{name: "missing_protocol", data: `{"node_id":17,"config":{"server_port":443}}`},
		{name: "invalid_config_type", data: `{"node_id":17,"config":"invalid"}`},
		{name: "invalid_node_id", data: `{"node_id":"invalid","config":{"protocol":"vless","server_port":443}}`},
		{name: "invalid_port", data: `{"node_id":17,"config":{"protocol":"vless","server_port":"invalid"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := 0
			w := NewWSClient("", "", 41, WSClientConfig{}, func(WSEvent) { count++ }, nil, nil)
			w.handleMessage(wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(tt.data)})
			if count != 0 {
				t.Fatalf("invalid config delivered %d events", count)
			}
		})
	}
}

func TestWSClient_NonConfigRoutingIsUnchanged(t *testing.T) {
	tests := []struct {
		event  string
		data   string
		wantID int
	}{
		{event: WSEventSyncUsers, data: `{"users":[{"id":1,"uuid":"abc"}]}`, wantID: 0},
		{event: WSEventSyncUsers, data: `{"node_id":17,"users":[{"id":1,"uuid":"abc"}]}`, wantID: 17},
		{event: WSEventSyncUserDelta, data: `{"action":"add","users":[{"id":1,"uuid":"abc"}]}`, wantID: 0},
		{event: WSEventSyncUserDelta, data: `{"node_id":17,"action":"add","users":[{"id":1,"uuid":"abc"}]}`, wantID: 17},
		{event: WSEventSyncDevices, data: `{"users":{"1":["10.0.0.1"]}}`, wantID: 0},
		{event: WSEventSyncDevices, data: `{"node_id":17,"users":{"1":["10.0.0.1"]}}`, wantID: 17},
		{event: WSEventSyncNodes, data: `{"nodes":[]}`, wantID: 0},
	}
	for _, tt := range tests {
		t.Run(tt.event, func(t *testing.T) {
			var received []WSEvent
			w := NewWSClient("", "", 41, WSClientConfig{}, func(event WSEvent) {
				received = append(received, event)
			}, nil, nil)
			w.handleMessage(wsMessage{Event: tt.event, Data: json.RawMessage(tt.data)})
			if len(received) != 1 {
				t.Fatalf("expected one event, got %+v", received)
			}
			if received[0].Type != tt.event || received[0].NodeID != tt.wantID || received[0].Config != nil {
				t.Errorf("unexpected event routing: %+v, want node_id=%d", received[0], tt.wantID)
			}
		})
	}
}

func TestWSClient_ConfigUpdatesKeepIndependentSnapshots(t *testing.T) {
	var received []WSEvent
	w := NewWSClient("", "", 41, WSClientConfig{}, func(event WSEvent) {
		received = append(received, event)
	}, nil, nil)
	legacy := wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(`{"config":{"protocol":"vless","server_port":443}}`)}
	w.handleMessage(legacy)
	w.handleMessage(wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(`{"node_id":17,"config":{"protocol":"vless","server_port":8443}}`)})
	w.handleMessage(legacy)
	if len(received) != 3 {
		t.Fatalf("expected three config events, got %d", len(received))
	}
	for i, wantID := range []int{41, 17, 41} {
		if received[i].Config == nil {
			t.Fatalf("event[%d].Config is nil", i)
		}
		if received[i].NodeID != wantID || received[i].Config.NodeID != wantID {
			t.Errorf("event[%d] identity: event=%d config=%d, want %d", i, received[i].NodeID, received[i].Config.NodeID, wantID)
		}
	}
	if received[0].Config.ServerPort != 443 || received[1].Config.ServerPort != 8443 || received[2].Config.ServerPort != 443 {
		t.Errorf("config snapshots changed across updates: %+v, %+v, %+v", received[0].Config, received[1].Config, received[2].Config)
	}
	firstID, secondID := received[0].Config.NodeID, received[1].Config.NodeID
	received[2].Config.NodeID = 99
	if received[0].Config.NodeID != firstID || received[1].Config.NodeID != secondID {
		t.Error("mutating a later config changed a retained snapshot")
	}
	if string(legacy.Data) != `{"config":{"protocol":"vless","server_port":443}}` {
		t.Error("config normalization mutated the input payload")
	}
}

func TestWSClient_ConfigIdentityAcrossReconnect(t *testing.T) {
	tests := []struct {
		name          string
		nodeID        int
		machineID     int
		authNodeID    string
		authMachineID string
		payloads      []string
		wantIDs       []int
	}{
		{
			name: "legacy_single_node", nodeID: 41, authNodeID: "41",
			payloads: []string{
				`{"config":{"protocol":"vless","server_port":443}}`,
				`{"config":{"protocol":"vless","server_port":8443}}`,
				`{"config":{"protocol":"vless","server_port":9443}}`,
			},
			wantIDs: []int{41, 41, 41},
		},
		{
			name: "machine_node_updates", machineID: 9, authMachineID: "9",
			payloads: []string{
				`{"node_id":17,"config":{"protocol":"vless","server_port":443}}`,
				`{"node_id":23,"config":{"protocol":"vless","server_port":8443}}`,
				`{"config":{"node_id":41,"protocol":"vless","server_port":9443}}`,
			},
			wantIDs: []int{17, 23, 41},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
			var mu sync.Mutex
			connectCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("node_id") != tt.authNodeID || q.Get("machine_id") != tt.authMachineID {
					t.Errorf("unexpected authentication params: node_id=%q machine_id=%q", q.Get("node_id"), q.Get("machine_id"))
					http.Error(w, "incorrect node identity", http.StatusUnauthorized)
					return
				}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				mu.Lock()
				connectCount++
				count := connectCount
				mu.Unlock()
				if count == 1 {
					// Legacy panels may push config before auth.success.
					conn.WriteJSON(wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(tt.payloads[0])})
					return
				}
				if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
					return
				}
				for _, payload := range tt.payloads[1:] {
					if err := conn.WriteJSON(wsMessage{Event: WSEventSyncConfig, Data: json.RawMessage(payload)}); err != nil {
						return
					}
				}
				for {
					var msg wsMessage
					if err := conn.ReadJSON(&msg); err != nil {
						return
					}
				}
			}))
			t.Cleanup(server.Close)
			events := make(chan WSEvent, 3)
			w := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), "test-token", tt.nodeID, WSClientConfig{
				MachineID: tt.machineID, StatusInterval: time.Hour, BackoffInitial: 10 * time.Millisecond, BackoffMax: 10 * time.Millisecond,
			}, func(event WSEvent) { events <- event }, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				w.Run(ctx)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("WS client did not stop after cancellation")
				}
			})
			for i, wantID := range tt.wantIDs {
				select {
				case event := <-events:
					if event.Config == nil {
						t.Fatalf("event[%d].Config is nil", i)
					}
					if event.NodeID != wantID || event.Config.NodeID != wantID {
						t.Errorf("event[%d] identity: event=%d config=%d, want %d", i, event.NodeID, event.Config.NodeID, wantID)
					}
					if wantPort := []int{443, 8443, 9443}[i]; event.Config.ServerPort != wantPort {
						t.Errorf("event[%d] port = %d, want %d", i, event.Config.ServerPort, wantPort)
					}
				case <-ctx.Done():
					t.Fatalf("timed out waiting for config event %d", i)
				}
			}
		})
	}
}

func TestWSClient_ReconnectOnDisconnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	var mu sync.Mutex
	connectCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		mu.Lock()
		connectCount++
		count := connectCount
		mu.Unlock()

		// Send auth.success
		conn.WriteJSON(wsMessage{Event: "auth.success"})

		// Close immediately on first connection to trigger reconnect
		if count == 1 {
			conn.Close()
			return
		}

		// Keep second connection alive
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "reconnect-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for reconnection
	deadline := time.After(4 * time.Second)
	for {
		mu.Lock()
		n := connectCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("expected at least 2 connections, got %d", connectCount)
			mu.Unlock()
		case <-time.After(100 * time.Millisecond):
		}
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true after reconnect")
	}
}

func TestWSClient_FallbackWhenNoServer(t *testing.T) {
	ws := NewWSClient("ws://127.0.0.1:19999", "fallback-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go ws.Run(ctx)

	time.Sleep(500 * time.Millisecond)
	if ws.IsConnected() {
		t.Error("expected IsConnected() = false when no server")
	}
}

func TestWSClient_UserDeltaEvent(t *testing.T) {
	deltaPayload := syncUserDeltaPayload{
		Action:    "add",
		Users:     []User{{ID: 42, UUID: "delta-uuid"}},
		Timestamp: 1236,
	}
	deltaData, _ := json.Marshal(deltaPayload)

	events := []wsMessage{
		{Event: WSEventSyncUserDelta, Data: deltaData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "delta-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for delta event")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if received[0].Type != WSEventSyncUserDelta {
		t.Errorf("event.Type = %q, want %q", received[0].Type, WSEventSyncUserDelta)
	}
	if received[0].DeltaAction != "add" {
		t.Errorf("event.DeltaAction = %q, want %q", received[0].DeltaAction, "add")
	}
	if len(received[0].DeltaUsers) != 1 || received[0].DeltaUsers[0].ID != 42 {
		t.Errorf("unexpected DeltaUsers: %+v", received[0].DeltaUsers)
	}
}

func TestWSClient_DeviceReportDeliveredImmediatelyAfterConnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	var mu sync.Mutex
	var reports []wsMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Event == WSEventReportDevices {
				mu.Lock()
				reports = append(reports, msg)
				mu.Unlock()
			}
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	var ws *WSClient
	ws = NewWSClient("ws://"+host, "report-token", 1, WSClientConfig{StatusInterval: time.Hour}, func(WSEvent) {}, func(status WSStatusChange) {
		if status.Connected {
			ws.SendDeviceReportForNode(1, map[int][]string{7: {"10.0.0.1"}})
		}
	}, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go ws.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("timed out waiting for device report, got %d", len(reports))
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reports) == 0 {
		t.Fatal("expected at least one report.devices message")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reports[0].Data, &payload); err != nil {
		t.Fatalf("unmarshal report payload: %v", err)
	}
	if int(payload["node_id"].(float64)) != 1 {
		t.Errorf("node_id: got %v, want 1", payload["node_id"])
	}
}

func TestWSClient_PendingDeviceReportCoalescesPerNodeLatestWins(t *testing.T) {
	w := &WSClient{devWake: make(chan struct{}, 1)}

	w.enqueueDeviceReport(1, &wsMessage{Event: WSEventReportDevices, Data: json.RawMessage(`"one-a"`)})
	w.enqueueDeviceReport(1, &wsMessage{Event: WSEventReportDevices, Data: json.RawMessage(`"one-b"`)})
	w.enqueueDeviceReport(2, &wsMessage{Event: WSEventReportDevices, Data: json.RawMessage(`"two"`)})

	got := make(map[int]*pendingDevice)
	for {
		pd := w.takePendingDevice()
		if pd == nil {
			break
		}
		got[pd.nodeID] = pd
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 pending device reports (one per node), got %d", len(got))
	}
	if string(got[1].msg.Data) != `"one-b"` {
		t.Errorf("node 1 pending: got %s, want one-b (latest wins)", got[1].msg.Data)
	}
	if string(got[2].msg.Data) != `"two"` {
		t.Errorf("node 2 pending: got %s, want two", got[2].msg.Data)
	}

	// A failed write restores the pending slot so it is retried.
	w.restorePendingDevice(got[1])
	restored := w.takePendingDevice()
	if restored == nil || string(restored.msg.Data) != `"one-b"` {
		t.Fatalf("restored pending device report mismatch: %+v", restored)
	}
}

func TestWSClient_ReadTimeoutDisconnectsSilentConnection(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}
		// Stay silent: never send ping/pong or data. The client must notice the
		// half-open connection via its read deadline.
		<-r.Context().Done()
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	var mu sync.Mutex
	var statuses []bool
	ws := NewWSClient("ws://"+host, "timeout-token", 1, WSClientConfig{
		ReadTimeout:    200 * time.Millisecond,
		StatusInterval: time.Hour,
		BackoffInitial: time.Hour,
		BackoffMax:     time.Hour,
	}, func(WSEvent) {}, func(status WSStatusChange) {
		mu.Lock()
		statuses = append(statuses, status.Connected)
		mu.Unlock()
	}, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go ws.Run(ctx)

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		sawDisconnect := false
		for _, s := range statuses {
			if !s {
				sawDisconnect = true
			}
		}
		mu.Unlock()
		if sawDisconnect {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("timed out waiting for read-timeout disconnect, statuses: %v", statuses)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
