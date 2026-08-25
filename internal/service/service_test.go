package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
	"golang.org/x/time/rate"
)

type fakeKernel struct {
	running bool

	startErr  error
	updateErr error
	addErr    error

	startCalls  int
	updateCalls int
	addCalls    int
	removeCalls int

	onUpdateUsers func([]model.UserSpec)
	onAddUsers    func([]model.UserSpec)
	onRemoveUsers func([]model.UserSpec)

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)
}

func (f *fakeKernel) Name() string                      { return "fake" }
func (f *fakeKernel) Protocols() []string               { return []string{"vless"} }
func (f *fakeKernel) Capabilities() kernel.Capabilities { return kernel.Capabilities{} }
func (f *fakeKernel) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}
func (f *fakeKernel) Stop()           { f.running = false }
func (f *fakeKernel) IsRunning() bool { return f.running }
func (f *fakeKernel) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	return nil
}
func (f *fakeKernel) AddUsers(users []model.UserSpec) (int, error) {
	f.addCalls++
	if f.onAddUsers != nil {
		f.onAddUsers(users)
	}
	if f.addErr != nil {
		return 0, f.addErr
	}
	return len(users), nil
}
func (f *fakeKernel) RemoveUsers(users []model.UserSpec) (int, error) {
	f.removeCalls++
	if f.onRemoveUsers != nil {
		f.onRemoveUsers(users)
	}
	return len(users), nil
}
func (f *fakeKernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	f.updateCalls++
	if f.onUpdateUsers != nil {
		f.onUpdateUsers(users)
	}
	if f.updateErr != nil {
		return 0, 0, f.updateErr
	}
	return len(users), 0, nil
}
func (f *fakeKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	_ = ctx
	return nil, nil, 0, nil
}
func (f *fakeKernel) CloseConnection(ctx context.Context, connID string) error {
	_, _ = ctx, connID
	return nil
}
func (f *fakeKernel) CloseUserConnections(ctx context.Context, uuid string) error {
	_, _ = ctx, uuid
	return nil
}
func (f *fakeKernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) { f.speedLimitFunc = fn }
func (f *fakeKernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool))  { f.deviceLimitFunc = fn }
func (f *fakeKernel) UpdateGlobalDevices(users map[int][]string)           { _ = users }
func (f *fakeKernel) ClearGlobalDevices()                                  {}

func newTestService(k *fakeKernel) *Service {
	sharedLimiter := limiter.New()
	s := &Service{
		kernel:       k,
		limiter:      sharedLimiter,
		speedTracker: limiter.NewSpeedTracker(sharedLimiter),
		cert:         cert.NewManager(config.CertConfig{}),
	}
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	return s
}

func TestApplyUserUpdatePreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)

	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to UpdateUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected new user's limiter to be visible before kernel UpdateUsers")
		}
	}

	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.updateCalls; got != 1 {
		t.Fatalf("UpdateUsers call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-new" {
		t.Fatalf("lastUsers = %#v, want new users", s.lastUsers)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for new user after successful update")
	}
}

func TestApplyUserUpdateRestoresStateWhenKernelAndRestartFail(t *testing.T) {
	k := &fakeKernel{
		running:   true,
		updateErr: errors.New("update failed"),
		startErr:  errors.New("restart failed"),
	}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)
	oldHash := s.lastUserHash

	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.startCalls; got != 1 {
		t.Fatalf("Start call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-old" {
		t.Fatalf("lastUsers = %#v, want restored old users", s.lastUsers)
	}
	if s.lastUserHash != oldHash {
		t.Fatalf("lastUserHash = %q, want %q", s.lastUserHash, oldHash)
	}
	if s.speedTracker.GetLimiter("uuid-old") == nil {
		t.Fatal("expected old limiter to be restored after rollback")
	}
	if s.speedTracker.GetLimiter("uuid-new") != nil {
		t.Fatal("expected new limiter to be removed after rollback")
	}
}

func TestApplyUserDeltaAddPreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)

	delta := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onAddUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to AddUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected delta user's limiter to be visible before kernel AddUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", delta)

	if got := k.addCalls; got != 1 {
		t.Fatalf("AddUsers call count = %d, want 1", got)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for delta-added user after successful update")
	}
}

func TestValidateNodeRuntimeRejectsUnsupportedDNSProvider(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"http"}, &model.NodeSpec{
		Protocol: "http",
		CertConfig: &config.CertConfig{
			CertMode:    "dns",
			DNSProvider: "3123123",
			Domain:      "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error")
	}
	if got := err.Error(); !strings.HasPrefix(got, `unsupported cert_config.dns_provider "3123123" (supported: `) {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeAllowsSelfManagedTLSBeforeFilesExist(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"anytls", "hysteria"}, &model.NodeSpec{
		Protocol: "anytls",
		CertConfig: &config.CertConfig{
			CertMode: "self",
			Domain:   "example.com",
		},
	}, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("expected self-managed TLS config to pass validation, got %v", err)
	}
}

func TestValidateNodeRuntimeAllowsSingboxRealityWithRequiredFields(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err != nil {
		t.Fatalf("expected sing-box reality validation to pass, got %v", err)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutTLSSettings(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutPrivateKey(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.private_key" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutServerNameOrDest(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.server_name or tls_settings.dest" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestWireKernelCallbacksDeviceLimitEnforcement(t *testing.T) {
	sharedLimiter := limiter.New()
	k := &fakeKernel{}
	s := &Service{
		kernel:       k,
		limiter:      sharedLimiter,
		speedTracker: limiter.NewSpeedTracker(sharedLimiter),
		cfg:          &config.Config{Kernel: config.KernelConfig{DeviceLimitEnforce: false}},
	}

	// Default (false): device limit lookup must NOT be registered.
	s.wireKernelCallbacks()
	if k.speedLimitFunc == nil {
		t.Fatal("speed limit callback should always be registered")
	}
	if k.deviceLimitFunc != nil {
		t.Fatal("device limit callback should not be registered when enforcement is disabled")
	}

	// Enabled: device limit lookup must be registered.
	k.deviceLimitFunc = nil
	s.cfg.Kernel.DeviceLimitEnforce = true
	s.wireKernelCallbacks()
	if k.deviceLimitFunc == nil {
		t.Fatal("device limit callback should be registered when enforcement is enabled")
	}
}

type fakePushClient struct {
	mu        sync.Mutex
	connected bool
	reports   []map[int][]string
}

func (f *fakePushClient) Run(ctx context.Context) { _ = ctx }
func (f *fakePushClient) IsConnected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected
}
func (f *fakePushClient) SendDeviceReport(devices map[int][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, devices)
}

type fakeSink struct {
	mu      sync.Mutex
	reports []map[int][]string
}

func (f *fakeSink) Report(payload controlplane.ReportPayload) error { return nil }
func (f *fakeSink) ReportDevices(push controlplane.PushClient, devices map[int][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, devices)
}
func (f *fakeSink) SupportsReporting() bool     { return true }
func (f *fakeSink) SupportsDeviceReports() bool { return true }

type noopSource struct{}

func (noopSource) Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- controlplane.Event, statuses chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	return controlplane.Bootstrap{}, nil
}
func (noopSource) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, nil
}
func (noopSource) Discover(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- controlplane.Event, statuses chan<- controlplane.StatusChange) (controlplane.PushClient, error) {
	return nil, nil
}
func (noopSource) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }
func (noopSource) SupportsPolling() bool            { return false }
func (noopSource) SupportsDiscovery() bool          { return false }

func TestSendDeviceReportForceReportsUnchangedSnapshot(t *testing.T) {
	tr := tracker.New()
	tr.Process(nil, map[int]map[string]bool{1: {"10.0.0.1": true}}, 0)

	if got := tr.FlushAliveIPs(); got == nil {
		t.Fatal("expected first flush to return alive IPs")
	}
	if got := tr.FlushAliveIPs(); got != nil {
		t.Fatal("expected duplicate flush to return nil")
	}

	push := &fakePushClient{connected: true}
	sink := &fakeSink{}
	s := &Service{tracker: tr, sink: sink, wsClient: push}

	s.sendDeviceReportForce(context.Background())

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.reports) != 1 {
		t.Fatalf("expected 1 forced device report, got %d", len(sink.reports))
	}
	if len(sink.reports[0][1]) != 1 || sink.reports[0][1][0] != "10.0.0.1" {
		t.Fatalf("unexpected forced report: %v", sink.reports[0])
	}
}

func TestSendDeviceBatchForcesReportOnReconnectTransition(t *testing.T) {
	tr := tracker.New()
	tr.Process(nil, map[int]map[string]bool{3: {"10.0.0.3": true}}, 0)
	if got := tr.FlushAliveIPs(); got == nil {
		t.Fatal("expected first flush to return alive IPs")
	}

	push := &fakePushClient{connected: true}
	sink := &fakeSink{}
	s := &Service{tracker: tr, sink: sink, wsClient: push}

	// First tick after (re)connect: report even though the snapshot is unchanged.
	s.sendDeviceBatch()
	if n := len(sink.reports); n != 1 {
		t.Fatalf("expected 1 report after reconnect transition, got %d", n)
	}

	// Still connected and unchanged: deduped.
	s.sendDeviceBatch()
	if n := len(sink.reports); n != 1 {
		t.Fatalf("expected no extra report while unchanged, got %d", n)
	}

	// Simulate a disconnect/reconnect cycle: the next tick must force a report.
	s.lastWSConnected.Store(false)
	s.sendDeviceBatch()
	if n := len(sink.reports); n != 2 {
		t.Fatalf("expected 1 report after disconnect/reconnect cycle, got %d", n)
	}
}

func TestHandleWSStatusConnectedSchedulesDeviceReport(t *testing.T) {
	tr := tracker.New()
	tr.Process(nil, map[int]map[string]bool{2: {"10.0.0.2": true}}, 0)
	if got := tr.FlushAliveIPs(); got == nil {
		t.Fatal("expected first flush to return alive IPs")
	}

	push := &fakePushClient{connected: true}
	sink := &fakeSink{}
	s := &Service{tracker: tr, sink: sink, wsClient: push, source: noopSource{}}

	s.handleWSStatus(context.Background(), controlplane.StatusChange{Connected: true})

	deadline := time.After(6 * time.Second) // wsPullJitter can delay up to 5s
	for {
		sink.mu.Lock()
		n := len(sink.reports)
		sink.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for device report after WS reconnect")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
