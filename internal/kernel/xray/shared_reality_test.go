package xray

import (
	"context"
	"net"
	"runtime"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/transport/internet"
	"gopkg.in/yaml.v3"
)

func enableSharedRealityTest(t *testing.T, x *Xray) {
	t.Helper()
	if err := yaml.Unmarshal([]byte("shared_reality:\n  enabled: true\n  listen_ip: 127.0.0.1\n  listen_port: 443\n"), &x.cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRealityRemovedUserTrafficRemainsCollectable(t *testing.T) {
	x, mgr := newStatsBackedXray(t, []model.UserSpec{{ID: 7}}, nil)
	enableSharedRealityTest(t, x)
	x.sharedLedger.Store(true)
	uplink := mustRegisterCounter(t, mgr, counterName(7, "uplink"))
	downlink := mustRegisterCounter(t, mgr, counterName(7, "downlink"))
	uplink.Add(101)
	downlink.Add(203)
	if _, _, _, err := x.GetUserTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.users = nil
	uplink.Add(17)
	downlink.Add(31)
	traffic, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := traffic[7]; got != [2]int64{118, 234} {
		t.Fatalf("removed user's final traffic = %v, want [118 234]", got)
	}
}

func TestSharedRealityStoppedLedgerRemainsCollectable(t *testing.T) {
	x, mgr := newStatsBackedXray(t, []model.UserSpec{{ID: 7}}, nil)
	enableSharedRealityTest(t, x)
	x.sharedLedger.Store(true)
	mustRegisterCounter(t, mgr, counterName(7, "uplink")).Add(101)
	mustRegisterCounter(t, mgr, counterName(7, "downlink")).Add(203)
	if _, _, _, err := x.GetUserTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.running.Store(false)
	traffic, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := traffic[7]; got != [2]int64{101, 203} {
		t.Fatalf("stopped ledger = %v, want [101 203]", got)
	}
}

func TestSharedRealityReportsConnectionsFromRetiredGenerations(t *testing.T) {
	current := newTestDispatcher()
	current.UpdateLimits(map[string]int{userEmail(7): 7}, nil, nil)
	current.checkDeviceLimit(userEmail(7), "127.0.0.2", true)
	current.connCount.Store(1)
	old := newTestDispatcher()
	old.UpdateLimits(map[string]int{userEmail(7): 7, userEmail(99): 99}, nil, nil)
	old.checkDeviceLimit(userEmail(7), "127.0.0.2", true)
	old.checkDeviceLimit(userEmail(7), "127.0.0.3", true)
	old.checkDeviceLimit(userEmail(99), "127.0.0.4", true)
	old.connCount.Store(3)
	x, _ := newStatsBackedXray(t, []model.UserSpec{{ID: 7}}, current)
	enableSharedRealityTest(t, x)
	x.sharedLedger.Store(true)
	x.sharedRetired = []*sharedRealityGeneration{{dispatcher: old}}

	_, alive, connections, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if connections != 4 || len(alive[7]) != 2 || !alive[7]["127.0.0.2"] || !alive[7]["127.0.0.3"] || !alive[99]["127.0.0.4"] {
		t.Fatalf("connections across reload = (%v, %d), want deduplicated real IPs for uid 7 and retired uid 99, 4 active connections", alive, connections)
	}
	old.delConn(userEmail(7), "127.0.0.3")
	old.connCount.Add(-1)
	_, nextAlive, nextConnections, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if nextConnections != 3 || nextAlive[7]["127.0.0.3"] || !nextAlive[99]["127.0.0.4"] || !alive[7]["127.0.0.3"] {
		t.Fatalf("closed retired connection or previous snapshot was not handled correctly: previous=%v, current=(%v, %d)", alive, nextAlive, nextConnections)
	}
}

func TestSharedRealityGlobalListenerRejectsForeignReusePortOwner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the pinned Xray system listener enables SO_REUSEPORT on Linux")
	}
	foreign, err := internet.ListenSystem(context.Background(), &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	sharedRealityMu.Lock()
	group, err := newSharedRealityGroup(context.Background(), foreign.Addr().String(), false, nil)
	if group != nil {
		group.closeLocked()
	}
	sharedRealityMu.Unlock()
	if err == nil {
		t.Fatal("global entry silently shared a foreign SO_REUSEPORT listener instead of rejecting a port conflict")
	}
}

func TestSharedRealityStartRejectsMissingPrivateKey(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray", LogLevel: "none"})
	enableSharedRealityTest(t, x)
	t.Cleanup(x.Stop)
	if err := x.Start(&model.NodeSpec{Protocol: "vless", TLS: 2, ServerPort: 28443}, nil, kernel.TLSCert{}); err == nil {
		t.Fatal("shared REALITY must reject missing private keys before creating a core")
	}
}

func TestSharedRealityLeavesNonRealityNodesUnchanged(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			x := New(config.KernelConfig{Type: "xray", LogLevel: "none"})
			enableSharedRealityTest(t, x)
			t.Cleanup(x.Stop)
			node := &model.NodeSpec{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: port}
			user := model.UserSpec{ID: 7, UUID: "11111111-1111-1111-1111-111111111111"}
			if err := x.Start(node, []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
				t.Fatalf("global alias configuration must not reject an ordinary %s node: %v", protocol, err)
			}
			if x.sharedRuntime != nil {
				t.Fatal("non-REALITY node was registered with the alias entry")
			}
			if removed, err := x.RemoveUsers([]model.UserSpec{user}); err != nil || removed != 1 {
				t.Fatalf("ordinary %s RemoveUsers = (%d, %v), want (1, nil)", protocol, removed, err)
			}
			if x.IsRunning() {
				t.Fatal("global alias setting changed ordinary nodes' stop-on-last-user behavior")
			}
		})
	}
}
