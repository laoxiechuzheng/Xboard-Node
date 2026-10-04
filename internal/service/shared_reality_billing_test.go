package service

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

type billingLifecycleKernel struct {
	fakeKernel
	mu         sync.Mutex
	running    bool
	traffic    map[int][2]int64
	final      map[int][2]int64
	stopCalls  int
	finalReads int
	stopped    chan struct{}
	stopOnce   sync.Once
	onStart    func()
}

func (k *billingLifecycleKernel) Start(_ *model.NodeSpec, _ []model.UserSpec, _ kernel.TLSCert) error {
	k.mu.Lock()
	k.running = true
	k.mu.Unlock()
	if k.onStart != nil {
		k.onStart()
	}
	return nil
}

func (k *billingLifecycleKernel) Stop() {
	k.mu.Lock()
	k.stopCalls++
	k.running = false
	k.traffic = maps.Clone(k.final)
	k.mu.Unlock()
	k.stopOnce.Do(func() { close(k.stopped) })
}

func (k *billingLifecycleKernel) IsRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

func (k *billingLifecycleKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, 0, err
	}
	if !k.running {
		k.finalReads++
	}
	return maps.Clone(k.traffic), nil, 0, nil
}

type billingLifecycleSink struct {
	mu           sync.Mutex
	reports      []map[int][2]int64
	active       int
	maxActive    int
	firstStarted chan struct{}
	releaseFirst chan struct{}
	releaseOnce  sync.Once
	firstErr     error
	finalErr     error
}

func (p *billingLifecycleSink) Report(payload controlplane.ReportPayload) error {
	p.mu.Lock()
	index := len(p.reports)
	p.reports = append(p.reports, maps.Clone(payload.Traffic))
	p.active++
	if p.active > p.maxActive {
		p.maxActive = p.active
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	if index == 0 && p.firstStarted != nil {
		close(p.firstStarted)
		<-p.releaseFirst
		return p.firstErr
	}
	return p.finalErr
}

func (p *billingLifecycleSink) unblock() {
	if p.releaseFirst != nil {
		p.releaseOnce.Do(func() { close(p.releaseFirst) })
	}
}

func (*billingLifecycleSink) ReportDevices(controlplane.PushClient, map[int][]string) {}
func (*billingLifecycleSink) SupportsReporting() bool                                 { return true }
func (*billingLifecycleSink) SupportsDeviceReports() bool                             { return false }

type billingLifecycleControlPlane struct {
	noopSource
	*billingLifecycleSink
	spec *model.NodeSpec
}

func (p *billingLifecycleControlPlane) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	spec := p.spec
	if spec == nil {
		spec = &model.NodeSpec{
			Protocol: "vless", ServerPort: 8443, TLS: 2, Network: "tcp",
			TLSSettings: map[string]any{"private_key": "synthetic-test-key", "server_name": "example.invalid"},
		}
	}
	return controlplane.Bootstrap{
		Config: spec,
		Users:  []model.UserSpec{{ID: 7, UUID: "billing-test-user"}},
	}, nil
}

func newBillingLifecycleService(shared *config.SharedRealityConfig, k *billingLifecycleKernel, sink *billingLifecycleSink) *Service {
	cfg := &config.Config{
		Kernel: config.KernelConfig{Type: "xray", SharedReality: shared, LogLevel: "none"},
		Cert:   config.CertConfig{CertMode: "none"},
		Node: config.NodeConfig{
			TrackInterval: 3600, PushInterval: 3600,
			PullInterval: 3600, DeviceReportInterval: 3600,
		},
		WS: config.WSConfig{DiscoveryInterval: 3600},
	}
	s := newService(cfg, &billingLifecycleControlPlane{billingLifecycleSink: sink})
	s.kernel = k
	return s
}

func TestBillingShutdownCollectsStoppedLedgerOnlyForSharedReality(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared *config.SharedRealityConfig
		want   [2]int64
		reads  int
		spec   *model.NodeSpec
	}{
		{"ordinary", nil, [2]int64{100, 200}, 0, nil},
		{"disabled", &config.SharedRealityConfig{}, [2]int64{100, 200}, 0, nil},
		{"shared", &config.SharedRealityConfig{Enabled: true}, [2]int64{140, 270}, 1, nil},
		{"non_reality", &config.SharedRealityConfig{Enabled: true}, [2]int64{100, 200}, 0,
			&model.NodeSpec{Protocol: "vless", ServerPort: 8443}},
		{"websocket", &config.SharedRealityConfig{Enabled: true}, [2]int64{100, 200}, 0,
			&model.NodeSpec{Protocol: "vless", ServerPort: 8443, TLS: 2, Network: "ws",
				TLSSettings: map[string]any{"private_key": "synthetic-test-key", "server_name": "example.invalid"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			k := &billingLifecycleKernel{
				final: map[int][2]int64{7: {140, 270}}, stopped: make(chan struct{}), onStart: cancel,
			}
			sink := &billingLifecycleSink{}
			s := newBillingLifecycleService(tc.shared, k, sink)
			s.source.(*billingLifecycleControlPlane).spec = tc.spec
			s.tracker.Process(map[int][2]int64{7: {100, 200}}, nil, 0)

			if err := s.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if len(sink.reports) != 1 || sink.reports[0][7] != tc.want {
				t.Fatalf("final reports = %v, want one report with %v", sink.reports, tc.want)
			}
			if k.finalReads != tc.reads || k.stopCalls != 1 {
				t.Fatalf("stopped ledger reads = %d, Stop calls = %d, want %d, 1", k.finalReads, k.stopCalls, tc.reads)
			}
			if pending := s.tracker.FlushTraffic(); len(pending) != 0 {
				t.Fatalf("successfully reported traffic remained pending: %v", pending)
			}
		})
	}
}

func TestSharedRealityBillingTracksStoppedKernelAfterEmptyConfigChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared *config.SharedRealityConfig
		tls    int
		want   map[int][2]int64
	}{
		{"ordinary", nil, 2, nil},
		{"disabled", &config.SharedRealityConfig{}, 2, nil},
		{"shared", &config.SharedRealityConfig{Enabled: true}, 2, map[int][2]int64{7: {40, 70}}},
		{"non_reality", &config.SharedRealityConfig{Enabled: true}, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			k := &billingLifecycleKernel{
				running: true, traffic: map[int][2]int64{7: {100, 200}},
				final: map[int][2]int64{7: {140, 270}}, stopped: make(chan struct{}),
			}
			sink := &billingLifecycleSink{}
			s := newBillingLifecycleService(tc.shared, k, sink)
			spec := &model.NodeSpec{Protocol: "vless", ServerPort: 8443, TLS: tc.tls, Network: "tcp"}
			s.lastConfig = spec
			s.appliedState.Config = spec
			s.appliedState.Users = []model.UserSpec{{ID: 7}}
			s.tracker.Process(map[int][2]int64{7: {100, 200}}, nil, 0)
			if got := s.tracker.FlushTraffic(); !maps.Equal(got, map[int][2]int64{7: {100, 200}}) {
				t.Fatalf("initial flushed traffic = %v, want [100 200]", got)
			}

			s.applyChanges(ctx, true, false)
			if k.IsRunning() || k.stopCalls != 1 || s.appliedState.Config != spec {
				t.Fatal("empty-user config change must stop the kernel and retain the applied config")
			}
			s.trackAndEnforce(ctx)
			s.trackAndEnforce(ctx)
			s.pushReportSync()
			if len(sink.reports) != 1 || !maps.Equal(sink.reports[0], tc.want) {
				t.Fatalf("traffic reported after empty-user config change = %v, want %v", sink.reports, tc.want)
			}

			s.trackAndEnforce(ctx)
			s.pushReportSync()
			if len(sink.reports) != 2 || len(sink.reports[1]) != 0 {
				t.Fatalf("repeated stopped-ledger read reported traffic again: %v", sink.reports)
			}
			if pending := s.tracker.FlushTraffic(); len(pending) != 0 {
				t.Fatalf("successfully reported stopped-ledger traffic remained pending: %v", pending)
			}
		})
	}
}

func TestSharedRealityBillingShutdownRestoresFailedFinalReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k := &billingLifecycleKernel{
		final:   map[int][2]int64{7: {140, 270}, 99: {15, 25}},
		stopped: make(chan struct{}), onStart: cancel,
	}
	sink := &billingLifecycleSink{finalErr: errors.New("report unavailable")}
	s := newBillingLifecycleService(&config.SharedRealityConfig{Enabled: true}, k, sink)
	s.tracker.Process(map[int][2]int64{7: {100, 200}}, nil, 0)

	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[int][2]int64{7: {140, 270}, 99: {15, 25}}
	if got := s.tracker.FlushTraffic(); !maps.Equal(got, want) {
		t.Fatalf("restored traffic = %v, want %v including retired users", got, want)
	}
}

func TestSharedRealityBillingShutdownWaitsForInflightReport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		firstErr  error
		wantFinal [2]int64
	}{
		{"success", nil, [2]int64{50, 80}},
		{"failure", errors.New("first report unavailable"), [2]int64{150, 280}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			k := &billingLifecycleKernel{
				final: map[int][2]int64{7: {150, 280}}, stopped: make(chan struct{}),
			}
			sink := &billingLifecycleSink{
				firstStarted: make(chan struct{}), releaseFirst: make(chan struct{}), firstErr: tc.firstErr,
			}
			defer sink.unblock()
			s := newBillingLifecycleService(&config.SharedRealityConfig{Enabled: true}, k, sink)
			s.tracker.Process(map[int][2]int64{7: {100, 200}}, nil, 0)
			k.onStart = func() {
				s.pushReportAsync()
				<-sink.firstStarted
				s.tracker.Process(map[int][2]int64{7: {130, 240}}, nil, 0)
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			select {
			case <-k.stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown did not stop the kernel while the report was in flight")
			}
			sink.unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown did not finish after the in-flight report completed")
			}
			deadline := time.Now().Add(5 * time.Second)
			for s.pushActive.Load() {
				if time.Now().After(deadline) {
					t.Fatal("asynchronous report did not complete")
				}
				time.Sleep(time.Millisecond)
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			if sink.maxActive != 1 {
				t.Fatalf("concurrent reports = %d, want 1", sink.maxActive)
			}
			if len(sink.reports) != 2 || sink.reports[0][7] != [2]int64{100, 200} || sink.reports[1][7] != tc.wantFinal {
				t.Fatalf("reports = %v, want initial [100 200] then %v", sink.reports, tc.wantFinal)
			}
			if pending := s.tracker.FlushTraffic(); len(pending) != 0 {
				t.Fatalf("final report left traffic pending: %v", pending)
			}
		})
	}
}
