package xray

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type sharedTailInbound struct {
	started chan struct{}
	release chan struct{}
	counter stats.Counter
}

func (*sharedTailInbound) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

func (p *sharedTailInbound) Process(ctx context.Context, _ xnet.Network, _ stat.Connection, _ routing.Dispatcher) error {
	return task.Run(ctx, func() error {
		close(p.started)
		<-p.release
		// Native splice publishes its counter only after its copy returns.
		p.counter.Add(37)
		return nil
	})
}

func TestSharedRealityStopWaitsForNativeCopyTailAfterProcessReturns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
	}{
		{"after_process_return", 50 * time.Millisecond},
		{"after_original_drain_timeout", drainTimeout + 50*time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) { testSharedRealityStoppedCopyTail(t, tc.delay) })
	}
}

func testSharedRealityStoppedCopyTail(t *testing.T, delay time.Duration) {
	t.Helper()
	x, manager := newStatsBackedXray(t, []model.UserSpec{{ID: 7}}, nil)
	enableSharedRealityTest(t, x)
	x.sharedLedger.Store(true)
	runtime := &sharedRealityRuntime{owner: x, accepting: true, connections: make(map[stat.Connection]context.CancelFunc)}
	x.sharedRuntime = runtime
	inbound := &sharedTailInbound{
		started: make(chan struct{}), release: make(chan struct{}),
		counter: mustRegisterCounter(t, manager, counterName(7, "downlink")),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(inbound.release) }) }
	defer release()
	conn, peer := net.Pipe()
	defer peer.Close()
	processDone := make(chan struct{})
	go func() {
		defer close(processDone)
		proxy := &sharedRealityProxy{Inbound: inbound, runtime: runtime}
		_ = proxy.Process(context.Background(), xnet.Network_TCP, conn, nil)
	}()
	select {
	case <-inbound.started:
	case <-time.After(time.Second):
		t.Fatal("native copy did not start")
	}
	stopDone := make(chan struct{})
	go func() { x.Stop(); close(stopDone) }()
	t.Cleanup(func() {
		release()
		select {
		case <-stopDone:
		case <-time.After(6 * time.Second):
			t.Error("Stop did not finish after releasing the native copy")
		}
	})
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled Process did not return while native copy remained pending")
	}
	select {
	case <-stopDone:
		t.Fatal("Stop harvested the ledger before the native copy published its tail")
	case <-time.After(delay):
	}
	release()
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not settle after the native copy finished")
	}
	traffic, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil || traffic[7] != [2]int64{0, 37} {
		t.Fatalf("final native copy tail = %v, error=%v, want [0 37]", traffic[7], err)
	}
}
