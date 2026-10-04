package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"gopkg.in/yaml.v3"
)

type nodeGroupFileView struct {
	Nodes443      []int                    `yaml:"nodes_443"`
	NodesDirect   []int                    `yaml:"nodes_direct"`
	NodeOverrides map[int]config.NodeEntry `yaml:"node_overrides"`
	Nodes         []config.NodeEntry       `yaml:"nodes"`
	Instances     []nodeGroupFileView      `yaml:"instances"`
}

func writeNodeGroupFixture(t *testing.T) string {
	t.Helper()
	t.Setenv("PANEL_A_TOKEN", "test-panel-a-token")
	t.Setenv("PANEL_B_TOKEN", "test-panel-b-token")
	t.Setenv("NODE_GROUP_AUDIT_SECRET", "test-audit-secret-not-for-production")
	path := filepath.Join(t.TempDir(), "config.yml")
	input := `kernel:
  type: xray
  shared_reality:
    enabled: true
    listen_ip: 127.0.0.1
    listen_port: 7443
audit:
  url: https://audit.example.com/api/node-audit/ingest
  secret_env: NODE_GROUP_AUDIT_SECRET
  agent_id: test-agent
  queue_size: 4096
instances:
  - panel:
      url: https://panel-a.example.com
      token_env: PANEL_A_TOKEN
      node_id: 999
    kernel:
      config_dir: /data/site-a
      shared_reality:
        enabled: false
        listen_ip: 127.0.0.2
        listen_port: 8443
    audit:
      site: site-a
      batch_size: 256
    nodes_443: [101, 102]
    nodes_direct: [103]
    node_overrides:
      102:
        node_type: vless
        kernel:
          config_dir: /data/site-a/special-102
          geo_data_dir: /data/site-a/geo
          custom_config: /data/site-a/node-102.json
        cert:
          cert_mode: file
          cert_file: /data/site-a/node-102.crt
          key_file: /data/site-a/node-102.key
          cert_dir: /data/site-a/certs-102
          dns_provider: cloudflare
          dns_env:
            CF_DNS_API_TOKEN: test-only-dns-token
  - panel:
      url: https://panel-b.example.com
      token_env: PANEL_B_TOKEN
      node_id: 998
    kernel:
      config_dir: /data/site-b
    audit:
      site: site-b
    nodes_443: []
    nodes_direct: [101]
`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readNodeGroupFile(t *testing.T, path string) nodeGroupFileView {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result nodeGroupFileView
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWriteRootConfigPreservesNodeGroups(t *testing.T) {
	path := writeNodeGroupFixture(t)
	want := readNodeGroupFile(t, path)
	root, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	got := readNodeGroupFile(t, path)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("node groups changed during CLI rewrite: got %+v, want %+v", got, want)
	}

	loaded, err := config.LoadRoot(path)
	if err != nil {
		t.Fatalf("load rewritten node groups: %v", err)
	}
	instances, err := loaded.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(instances))
	}
	wants := [][]struct {
		id      int
		enabled bool
		ip      string
		port    int
		site    string
		dir     string
	}{
		{
			{101, true, "127.0.0.2", 8443, "site-a", filepath.Join("/data/site-a", "node-101")},
			{102, true, "127.0.0.2", 8443, "site-a", "/data/site-a/special-102"},
			{103, false, "127.0.0.2", 8443, "site-a", filepath.Join("/data/site-a", "node-103")},
		},
		{{101, false, "127.0.0.1", 7443, "site-b", filepath.Join("/data/site-b", "node-101")}},
	}
	for i, instance := range instances {
		if instance.Nodes != nil {
			t.Fatalf("instance[%d] materialized legacy nodes", i)
		}
		nodes := instance.ExpandNodes()
		if len(nodes) != len(wants[i]) {
			t.Fatalf("instance[%d] expanded %d nodes, want %d", i, len(nodes), len(wants[i]))
		}
		for j, want := range wants[i] {
			node := nodes[j]
			if node.Panel.NodeID != want.id || node.Kernel.ConfigDir != want.dir || node.Audit.Site != want.site {
				t.Fatalf("instance[%d] node[%d]: id=%d dir=%q site=%q, want %+v", i, j, node.Panel.NodeID, node.Kernel.ConfigDir, node.Audit.Site, want)
			}
			shared := node.Kernel.SharedReality
			if shared == nil || shared.Enabled != want.enabled || shared.ListenIP != want.ip || shared.ListenPort != want.port {
				t.Fatalf("instance[%d] node[%d] listener = %+v, want %+v", i, j, shared, want)
			}
			if node.Audit.URL != "https://audit.example.com/api/node-audit/ingest" || node.Audit.AgentID != "test-agent" || node.Audit.QueueSize != 4096 || node.Audit.Secret == "" {
				t.Fatalf("instance[%d] node[%d] lost inherited audit settings", i, j)
			}
			wantPanel := "https://panel-a.example.com"
			wantToken := "test-panel-a-token"
			if i == 1 {
				wantPanel, wantToken = "https://panel-b.example.com", "test-panel-b-token"
			}
			if node.Panel.URL != wantPanel || node.Panel.Token != wantToken {
				t.Fatalf("instance[%d] node[%d] changed panel identity", i, j)
			}
		}
		if i == 0 {
			special := nodes[1]
			if special.Cert.DNSProvider != "cloudflare" || special.Cert.DNSEnv["CF_DNS_API_TOKEN"] != "test-only-dns-token" {
				t.Fatal("exceptional node lost DNS certificate provider settings")
			}
			if special.Panel.NodeType != "vless" || special.Kernel.GeoDataDir != "/data/site-a/geo" || special.Kernel.CustomConfig != "/data/site-a/node-102.json" || special.Cert.CertDir != "/data/site-a/certs-102" || special.Cert.CertFile != "/data/site-a/node-102.crt" || special.Cert.KeyFile != "/data/site-a/node-102.key" || special.Cert.CertMode != "file" || special.Audit.BatchSize != 256 {
				t.Fatal("exceptional node lost kernel, certificate, or audit overrides")
			}
		}
	}

	before := instances
	root, err = loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	loaded, err = config.LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := loaded.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("instance count changed on second reload: %d, want %d", len(after), len(before))
	}
	for i := range before {
		if after[i].InstanceID != before[i].InstanceID || !reflect.DeepEqual(after[i].ExpandNodes(), before[i].ExpandNodes()) {
			t.Fatalf("instance[%d] identity or expanded config changed on second reload", i)
		}
	}
}

func TestWriteRootConfigPreservesExplicitEmptyNodeGroups(t *testing.T) {
	for _, groups := range []string{
		"nodes_443: []\nnodes_direct: [101]\n",
		"nodes_443: [101]\nnodes_direct: []\n",
		"nodes_443: []\nnodes_direct: []\n",
	} {
		t.Run(groups, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			input := fmt.Sprintf("panel:\n  url: https://panel.example.com\n  token_env: PANEL_TOKEN\n  node_id: 999\nkernel:\n  type: xray\n%s", groups)
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			want := readNodeGroupFile(t, path)
			root, err := loadWritableRootConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeRootConfig(path, root); err != nil {
				t.Fatal(err)
			}
			got := readNodeGroupFile(t, path)
			if len(got.Instances) != 1 || !reflect.DeepEqual(got.Instances[0].Nodes443, want.Nodes443) || !reflect.DeepEqual(got.Instances[0].NodesDirect, want.NodesDirect) {
				t.Fatalf("explicit empty lists lost during legacy conversion: got %+v, want %+v", got, want)
			}
			if got.Nodes443 != nil || got.NodesDirect != nil {
				t.Fatal("legacy conversion left node groups at the root")
			}
		})
	}
}

func TestConfigInitPreservesNodeGroupsWhenAddingBinding(t *testing.T) {
	path := writeNodeGroupFixture(t)
	want := readNodeGroupFile(t, path)
	if err := runConfigInit([]string{
		"--config", path, "--output", path, "--mode", "node",
		"--panel-url", "https://panel-c.example.com", "--node-id", "104", "--kernel", "xray",
		"--install-root", t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	got := readNodeGroupFile(t, path)
	if len(got.Instances) != 3 || !reflect.DeepEqual(got.Instances[:2], want.Instances) {
		t.Fatalf("adding a binding changed existing node groups: got %+v, want %+v", got, want)
	}
	if got.Instances[2].Nodes443 != nil || got.Instances[2].NodesDirect != nil || got.Instances[2].NodeOverrides != nil {
		t.Fatal("new single-node binding inherited another site's groups")
	}
}
