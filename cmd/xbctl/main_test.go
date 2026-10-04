package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"gopkg.in/yaml.v3"
)

// xbctl rewrites config.yml when it adds or removes a node; the audit uploader
// settings must survive that rewrite or log upload silently stops.
func TestWriteRootConfigPreservesAuditSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	input := `
audit:
  url: "https://flux.example/api/node-audit/ingest"
  site: "98k"
  secret_env: "NODE_AUDIT_SECRET"
  agent_id: "jp-edge-1"
  queue_size: 4096
instances:
  - id: "a"
    panel:
      url: "https://panel.example.com"
      token_env: "PANEL_TOKEN_A"
      node_id: 1
    kernel:
      type: xray
    audit:
      site: "mg"
      batch_size: 256
  - id: "b"
    panel:
      url: "https://panel.example.com"
      token_env: "PANEL_TOKEN_B"
      node_id: 2
    kernel:
      type: singbox
`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := &config.RootConfig{}
	if err := yaml.Unmarshal(data, rewritten); err != nil {
		t.Fatal(err)
	}

	wantTop := config.AuditConfig{
		URL: "https://flux.example/api/node-audit/ingest", Site: "98k",
		SecretEnv: "NODE_AUDIT_SECRET", AgentID: "jp-edge-1", QueueSize: 4096,
	}
	if rewritten.Audit != wantTop {
		t.Fatalf("top-level audit = %+v, want %+v", rewritten.Audit, wantTop)
	}
	if len(rewritten.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(rewritten.Instances))
	}
	wantFirst := config.AuditConfig{Site: "mg", BatchSize: 256}
	if rewritten.Instances[0].Audit != wantFirst {
		t.Fatalf("instance a audit = %+v, want %+v", rewritten.Instances[0].Audit, wantFirst)
	}
	if rewritten.Instances[1].Audit != (config.AuditConfig{}) {
		t.Fatalf("instance b gained audit settings: %+v", rewritten.Instances[1].Audit)
	}
}

type sharedRealityFileSettings struct {
	Enabled    bool   `yaml:"enabled"`
	ListenIP   string `yaml:"listen_ip"`
	ListenPort int    `yaml:"listen_port"`
}

type sharedRealityFileView struct {
	Kernel struct {
		SharedReality *sharedRealityFileSettings `yaml:"shared_reality"`
	} `yaml:"kernel"`
	Instances []sharedRealityFileView `yaml:"instances"`
	Nodes     []sharedRealityFileView `yaml:"nodes"`
	NodeID    int                     `yaml:"node_id"`
}

func readSharedRealityFile(t *testing.T, path string) *sharedRealityFileView {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result sharedRealityFileView
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

func rewriteSharedRealityFile(t *testing.T, input string) *sharedRealityFileView {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	return readSharedRealityFile(t, path)
}

func requireFileSharedReality(t *testing.T, got *sharedRealityFileSettings, want sharedRealityFileSettings) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("rewritten shared_reality = %+v, want %+v", got, want)
	}
}

func TestWriteRootConfigPreservesSharedRealitySettings(t *testing.T) {
	rewritten := rewriteSharedRealityFile(t, `
kernel:
  type: xray
  shared_reality:
    enabled: true
    listen_ip: '2001:db8::1'
    listen_port: 7443
instances:
  - panel:
      url: https://panel.example.com
      token_env: PANEL_A_TOKEN
      node_id: 1
  - panel:
      url: https://panel.example.com
      token_env: PANEL_B_TOKEN
      node_id: 2
    kernel:
      type: singbox
      shared_reality:
        enabled: false
  - panel:
      url: https://panel.example.com
      token_env: PANEL_C_TOKEN
    kernel:
      type: xray
      shared_reality:
        enabled: true
        listen_ip: 127.0.0.1
        listen_port: 8443
    nodes:
      - node_id: 10
      - node_id: 11
        kernel:
          shared_reality:
            enabled: false
      - node_id: 12
        kernel:
          shared_reality:
            enabled: true
            listen_ip: '::1'
            listen_port: 9443
`)
	requireFileSharedReality(t, rewritten.Kernel.SharedReality, sharedRealityFileSettings{true, "2001:db8::1", 7443})
	if len(rewritten.Instances) != 3 {
		t.Fatalf("instances = %d, want 3", len(rewritten.Instances))
	}
	if rewritten.Instances[0].Kernel.SharedReality != nil {
		t.Fatal("rewrite materialized an inherited shared_reality setting")
	}
	requireFileSharedReality(t, rewritten.Instances[1].Kernel.SharedReality, sharedRealityFileSettings{})
	requireFileSharedReality(t, rewritten.Instances[2].Kernel.SharedReality, sharedRealityFileSettings{true, "127.0.0.1", 8443})
	nodes := rewritten.Instances[2].Nodes
	if len(nodes) != 3 || nodes[0].NodeID != 10 || nodes[1].NodeID != 11 || nodes[2].NodeID != 12 {
		t.Fatalf("node bindings changed during rewrite: %+v", nodes)
	}
	if nodes[0].Kernel.SharedReality != nil {
		t.Fatal("rewrite materialized a per-node shared_reality override")
	}
	requireFileSharedReality(t, nodes[1].Kernel.SharedReality, sharedRealityFileSettings{})
	requireFileSharedReality(t, nodes[2].Kernel.SharedReality, sharedRealityFileSettings{true, "::1", 9443})
}

func TestWriteRootConfigPreservesSharedRealityWithoutKernelType(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			rewritten := rewriteSharedRealityFile(t, fmt.Sprintf(`
kernel:
  shared_reality:
    enabled: %t
instances:
  - panel:
      url: https://panel.example.com
      token_env: PANEL_TOKEN
      node_id: 1
    kernel:
      type: xray
`, enabled))
			requireFileSharedReality(t, rewritten.Kernel.SharedReality, sharedRealityFileSettings{Enabled: enabled})
		})
	}
}

func TestWriteRootConfigPreservesSharedRealityLegacyConfig(t *testing.T) {
	rewritten := rewriteSharedRealityFile(t, `
panel:
  url: https://panel.example.com
  token_env: PANEL_TOKEN
  node_id: 1
kernel:
  type: xray
  shared_reality:
    enabled: true
    listen_ip: 192.0.2.10
    listen_port: 443
`)
	want := sharedRealityFileSettings{true, "192.0.2.10", 443}
	requireFileSharedReality(t, rewritten.Kernel.SharedReality, want)
	if len(rewritten.Instances) != 1 {
		t.Fatalf("legacy instances = %d, want 1", len(rewritten.Instances))
	}
	requireFileSharedReality(t, rewritten.Instances[0].Kernel.SharedReality, want)
}

func TestWriteRootConfigOmitsAbsentSharedReality(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	root := &config.RootConfig{Instances: []config.Config{{
		Panel:  config.PanelConfig{URL: "https://panel.example.com", NodeID: 1, TokenEnv: "PANEL_TOKEN"},
		Kernel: config.KernelConfig{Type: "singbox"},
	}}}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "shared_reality:") {
		t.Fatal("ordinary singbox config gained a shared_reality field")
	}
}

func TestConfigInitPreservesSharedRealityWhenAddingBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	input := `
kernel:
  type: xray
  shared_reality:
    enabled: true
    listen_ip: 192.0.2.10
    listen_port: 7443
instances:
  - panel:
      url: https://panel.example.com
      token_env: PANEL_TOKEN
      node_id: 1
    kernel:
      shared_reality:
        enabled: false
`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runConfigInit([]string{
		"--config", path, "--output", path, "--mode", "node",
		"--panel-url", "https://new-panel.example.com", "--node-id", "2", "--kernel", "xray",
		"--install-root", t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	rewritten := readSharedRealityFile(t, path)
	requireFileSharedReality(t, rewritten.Kernel.SharedReality, sharedRealityFileSettings{true, "192.0.2.10", 7443})
	if len(rewritten.Instances) != 2 {
		t.Fatalf("instances after add = %d, want 2", len(rewritten.Instances))
	}
	requireFileSharedReality(t, rewritten.Instances[0].Kernel.SharedReality, sharedRealityFileSettings{})
	if rewritten.Instances[1].Kernel.SharedReality != nil {
		t.Fatal("new binding should inherit shared_reality without an explicit override")
	}
}
