package singbox

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBuildInboundAnyTLSProxyProtocol(t *testing.T) {
	for _, test := range []struct {
		name    string
		panel   bool
		network bool
		force   bool
		want    bool
	}{
		{name: "disabled"},
		{name: "panel", panel: true, want: true},
		{name: "network_settings", network: true, want: true},
		{name: "force", force: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := &model.NodeSpec{
				Protocol:            "anytls",
				ServerPort:          443,
				AcceptProxyProtocol: test.panel,
				NetworkSettings:     map[string]any{"acceptProxyProtocol": test.network},
			}
			inbound := buildInbound(node, testUsers, kernel.TLSCert{
				CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"),
			}, config.KernelConfig{ForceProxyProtocol: test.force})
			for _, key := range []string{"proxy_protocol", "proxy_protocol_accept_no_header"} {
				value, exists := inbound[key]
				if test.want {
					if !exists || value != true {
						t.Errorf("%s = %v (present %v), want true", key, value, exists)
					}
				} else if exists {
					t.Errorf("%s must be omitted when disabled, got %v", key, value)
				}
			}
		})
	}
}

func TestBuildConfigAnyTLSForceProxyProtocolFromPanel(t *testing.T) {
	kcfg := config.KernelConfig{Type: "singbox", ForceProxyProtocol: true}
	node, err := model.NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol: "anytls", ServerPort: 443, TLS: 1,
	}, kcfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := buildConfig(kcfg, node, testUsers, kernel.TLSCert{
		CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"),
	})
	inbound := cfg["inbounds"].([]M)[0]
	assertMapValue(t, inbound, "type", "anytls")
	assertMapValue(t, inbound, "proxy_protocol", true)
	assertMapValue(t, inbound, "proxy_protocol_accept_no_header", true)
}

func TestForceProxyProtocolDoesNotEnableOtherSingboxProtocols(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan", "hysteria2", "tuic", "socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			inbound := buildInbound(&model.NodeSpec{
				Protocol: protocol, ServerPort: 443, AcceptProxyProtocol: true,
			}, testUsers, kernel.TLSCert{
				CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"),
			}, config.KernelConfig{ForceProxyProtocol: true})
			for _, key := range []string{"proxy_protocol", "proxy_protocol_accept_no_header"} {
				if value, exists := inbound[key]; exists {
					t.Errorf("%s: %s must remain omitted, got %v", protocol, key, value)
				}
			}
		})
	}
}
