package singbox

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBuildInboundSNIWhitelistOnlyForHysteria2TUICAndAnyTLS(t *testing.T) {
	cert := kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}
	whitelist := config.ServerNameList{"iosapps.itunes.apple.com", "www.apple.com"}
	kcfg := config.KernelConfig{SNIWhitelist: whitelist}
	for _, tc := range []struct {
		node *panel.NodeConfig
		want bool
	}{
		{&panel.NodeConfig{Protocol: "hysteria2", ServerPort: 8443}, true},
		{&panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 8443}, true},
		{&panel.NodeConfig{Protocol: "hy2", ServerPort: 8443}, true},
		{&panel.NodeConfig{Protocol: "tuic", ServerPort: 8443}, true},
		{&panel.NodeConfig{Protocol: "hysteria", Version: 1, ServerPort: 8443}, false},
		{&panel.NodeConfig{Protocol: "trojan", ServerPort: 8443}, false},
		{&panel.NodeConfig{Protocol: "anytls", ServerPort: 8443}, true},
		{&panel.NodeConfig{Protocol: "anytls", ServerPort: 8443, AcceptProxyProtocol: true}, true},
	} {
		t.Run(tc.node.Protocol, func(t *testing.T) {
			inbound := buildInbound(testNodeSpec(tc.node), testUsers, cert, kcfg)
			tls, ok := inbound["tls"].(M)
			if !ok {
				t.Fatal("inbound has no TLS")
			}
			got, exists := tls["server_name_allowlist"]
			if exists != tc.want {
				t.Fatalf("server_name_allowlist present = %v, want %v", exists, tc.want)
			}
			if tc.want && !reflect.DeepEqual(got, []string(whitelist)) {
				t.Fatalf("server_name_allowlist = %v, want %v", got, whitelist)
			}
			unrestricted := buildInbound(testNodeSpec(tc.node), testUsers, cert, config.KernelConfig{})
			if _, exists := unrestricted["tls"].(M)["server_name_allowlist"]; exists {
				t.Fatal("server_name_allowlist set without kernel.sni_whitelist")
			}
		})
	}
	if whitelist[0] != "iosapps.itunes.apple.com" {
		t.Fatal("building an inbound mutated the configured whitelist")
	}
}
