package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	panelapi "github.com/cedar2025/xboard-node/internal/panel"
)

func TestPanelControlPlaneInitialRejectsInvalidCustomOutbounds(t *testing.T) {
	server := newPanelTestServer(`{"protocol":"shadowsocks","server_port":8388,"custom_outbounds":[{"tag":"proxy","protocol":"socks","proxy_tag":"missing","settings":{"server":"2.2.2.2","server_port":1080}}]}`)
	defer server.Close()

	cp := NewPanelControlPlane(config.PanelConfig{URL: server.URL, Token: "token", NodeID: 1}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	_, err := cp.Initial(context.Background(), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `initial config normalize: validate custom outbounds: custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPanelControlPlanePollRejectsInvalidCustomOutbounds(t *testing.T) {
	server := newPanelTestServer(`{"protocol":"shadowsocks","server_port":8388,"custom_outbounds":[{"tag":"proxy","protocol":"socks","proxy_tag":"missing","settings":{"server":"2.2.2.2","server_port":1080}}]}`)
	defer server.Close()

	cp := NewPanelControlPlane(config.PanelConfig{URL: server.URL, Token: "token", NodeID: 1}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	snap, err := cp.Poll(context.Background())
	if err != nil {
		t.Fatalf("an invalid config must not fail the poll: %v", err)
	}
	if snap.ConfigErr == nil {
		t.Fatal("expected ConfigErr, got nil")
	}
	if !strings.Contains(snap.ConfigErr.Error(), `poll config normalize: validate custom outbounds: custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
		t.Fatalf("unexpected config error: %v", snap.ConfigErr)
	}
	if snap.Config != nil {
		t.Fatalf("config = %+v, want nil for an invalid config", snap.Config)
	}
	if len(snap.Users) != 1 {
		t.Fatalf("users = %#v, want the panel's user list", snap.Users)
	}
}

func TestTranslateWSEventRejectsInvalidCustomOutbounds(t *testing.T) {
	_, err := TranslateWSEvent(panelapi.WSEvent{
		Type: panelapi.WSEventSyncConfig,
		Config: &panelapi.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panelapi.OutboundConfig{
				{Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
		},
	}, config.KernelConfig{Type: "singbox"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `translate node config: validate custom outbounds: custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newPanelTestServer(configBody string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"websocket":{"enabled":false},"settings":{"push_interval":60,"pull_interval":60}}`))
	})
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(configBody))
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"11111111-1111-1111-1111-111111111111"}]}`))
	})
	return httptest.NewServer(mux)
}

func TestTranslateWSEventRejectsUnsupportedProtocolForKernel(t *testing.T) {
	_, err := TranslateWSEvent(panelapi.WSEvent{
		Type: panelapi.WSEventSyncConfig,
		Config: &panelapi.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panelapi.OutboundConfig{
				{Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443}},
			},
		},
	}, config.KernelConfig{Type: "xray"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `translate node config: validate custom outbounds: custom_outbounds[0].protocol "hysteria2" is not supported by kernel "xray"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTranslateWSEventKeepsEmptyUserListNonNil(t *testing.T) {
	translated, err := TranslateWSEvent(panelapi.WSEvent{Type: panelapi.WSEventSyncUsers, Users: []panelapi.User{}}, config.KernelConfig{Type: "singbox"})
	if err != nil {
		t.Fatal(err)
	}
	if translated.Users == nil || len(translated.Users) != 0 {
		t.Fatalf("users = %#v, want an empty non-nil list", translated.Users)
	}

	translated, err = TranslateWSEvent(panelapi.WSEvent{Type: panelapi.WSEventSyncUsers}, config.KernelConfig{Type: "singbox"})
	if err != nil {
		t.Fatal(err)
	}
	if translated.Users != nil {
		t.Fatalf("users = %#v, want nil for a missing list", translated.Users)
	}
}

// etagPanel serves config and users with fixed ETags and records the
// If-None-Match header of every request.
type etagPanel struct {
	mu          sync.Mutex
	configBody  string
	usersStatus int
	configINM   []string
	usersINM    []string
}

func (p *etagPanel) handler(machine bool) http.Handler {
	configPath, userPath := "/api/v1/server/UniProxy/config", "/api/v1/server/UniProxy/user"
	if machine {
		configPath, userPath = "/api/v2/server/config", "/api/v2/server/user"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(configPath, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		inm := r.Header.Get("If-None-Match")
		p.configINM = append(p.configINM, inm)
		if inm == `"c1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"c1"`)
		_, _ = w.Write([]byte(p.configBody))
	})
	mux.HandleFunc(userPath, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		inm := r.Header.Get("If-None-Match")
		p.usersINM = append(p.usersINM, inm)
		if p.usersStatus != 0 {
			w.WriteHeader(p.usersStatus)
			return
		}
		if inm == `"u1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"u1"`)
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"11111111-1111-1111-1111-111111111111"}]}`))
	})
	return mux
}

func (p *etagPanel) lastINM() (config, users string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.configINM) > 0 {
		config = p.configINM[len(p.configINM)-1]
	}
	if len(p.usersINM) > 0 {
		users = p.usersINM[len(p.usersINM)-1]
	}
	return config, users
}

func (p *etagPanel) set(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn()
}

func newETagTestSource(t *testing.T, machine bool, p *etagPanel) Source {
	t.Helper()
	server := httptest.NewServer(p.handler(machine))
	t.Cleanup(server.Close)
	kcfg := config.KernelConfig{Type: "singbox"}
	if machine {
		client := panelapi.NewClient(config.PanelConfig{URL: server.URL, Token: "token", NodeID: 1, MachineID: 7})
		return NewMachinePanelControlPlane(client, kcfg, nil, nil)
	}
	return NewPanelControlPlane(config.PanelConfig{URL: server.URL, Token: "token", NodeID: 1}, config.WSConfig{}, kcfg)
}

const validETagTestConfig = `{"protocol":"shadowsocks","server_port":8388,"cipher":"aes-128-gcm"}`

func etagTestModes() map[string]bool { return map[string]bool{"panel": false, "machine": true} }

// A config 200 followed by a failed users fetch drops the whole snapshot, so
// the config ETag stored by that poll must not survive: the next poll would
// get 304 for a config the service never received.
func TestPollRollsBackConfigETagWhenUsersFail(t *testing.T) {
	for name, machine := range etagTestModes() {
		t.Run(name, func(t *testing.T) {
			p := &etagPanel{configBody: validETagTestConfig, usersStatus: http.StatusInternalServerError}
			src := newETagTestSource(t, machine, p)

			if _, err := src.Poll(context.Background()); err == nil {
				t.Fatal("expected the users failure to fail the poll")
			}
			p.set(func() { p.usersStatus = 0 })
			snap, err := src.Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if inm, _ := p.lastINM(); inm != "" {
				t.Fatalf("config If-None-Match after a failed poll = %q, want none", inm)
			}
			if snap.Config == nil || snap.Users == nil {
				t.Fatalf("snapshot after a failed poll = %+v, want full config and users", snap)
			}

			// A successful poll commits both ETags.
			snap, err = src.Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if configINM, usersINM := p.lastINM(); configINM != `"c1"` || usersINM != `"u1"` {
				t.Fatalf("If-None-Match after a successful poll = %q/%q, want the stored ETags", configINM, usersINM)
			}
			if snap.Config != nil || snap.Users != nil {
				t.Fatalf("snapshot = %+v, want 304 for both", snap)
			}
		})
	}
}

// A config that fails normalization still returns the users and keeps their
// ETag; only the config ETag is dropped, so every poll re-checks the config
// until it is fixed.
func TestPollKeepsUsersWhenConfigNormalizeFails(t *testing.T) {
	for name, machine := range etagTestModes() {
		t.Run(name, func(t *testing.T) {
			p := &etagPanel{configBody: `{"protocol":"shadowsocks","server_port":8388,"custom_outbounds":[{"tag":"proxy","protocol":"socks","proxy_tag":"missing","settings":{"server":"2.2.2.2","server_port":1080}}]}`}
			src := newETagTestSource(t, machine, p)

			snap, err := src.Poll(context.Background())
			if err != nil {
				t.Fatalf("an invalid config must not fail the poll: %v", err)
			}
			if snap.ConfigErr == nil || !strings.Contains(snap.ConfigErr.Error(), "config normalize") {
				t.Fatalf("ConfigErr = %v, want a normalize error", snap.ConfigErr)
			}
			if snap.Config != nil || len(snap.Users) != 1 {
				t.Fatalf("snapshot = %+v, want no config and the users", snap)
			}

			// Still invalid: the config is fetched in full again, the users
			// ETag from the first poll is kept.
			snap, err = src.Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if configINM, usersINM := p.lastINM(); configINM != "" || usersINM != `"u1"` {
				t.Fatalf("If-None-Match after an invalid config = %q/%q, want none/\"u1\"", configINM, usersINM)
			}
			if snap.ConfigErr == nil || snap.Config != nil {
				t.Fatalf("snapshot = %+v, want the config error again", snap)
			}

			p.set(func() { p.configBody = validETagTestConfig })
			snap, err = src.Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if configINM, _ := p.lastINM(); configINM != "" {
				t.Fatalf("config If-None-Match after an invalid config = %q, want none", configINM)
			}
			if snap.Config == nil || snap.ConfigErr != nil {
				t.Fatalf("snapshot after the config was fixed = %+v, want the config", snap)
			}
		})
	}
}

func TestPollRollsBackETagsWhenContextDone(t *testing.T) {
	p := &etagPanel{configBody: validETagTestConfig}
	src := newETagTestSource(t, false, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := src.Poll(ctx); err == nil {
		t.Fatal("expected a cancelled poll to fail")
	}
	if _, err := src.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if configINM, usersINM := p.lastINM(); configINM != "" || usersINM != "" {
		t.Fatalf("If-None-Match after a cancelled poll = %q/%q, want none", configINM, usersINM)
	}
}
