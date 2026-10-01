package main

import (
	"os"
	"path/filepath"
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
