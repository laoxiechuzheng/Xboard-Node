package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func nodeGroupsValidationClearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"apiHost", "API_HOST", "apiKey", "API_KEY", "nodeID", "NODE_ID",
		"nodeType", "NODE_TYPE", "kernel", "KERNEL_TYPE",
		"certFile", "CERT_FILE", "keyFile", "KEY_FILE", "domain", "DOMAIN",
		"logLevel", "LOG_LEVEL", "MACHINE_ID", "MACHINE_TOKEN",
		"AUDIT_URL", "AUDIT_SITE", "AUDIT_SECRET", "AUDIT_AGENT_ID",
	} {
		t.Setenv(name, "")
	}
}

func nodeGroupsValidationLoaders() []struct {
	name string
	load func(*testing.T, string) (*Config, error)
} {
	loadRoot := func(t *testing.T, content string) (*Config, error) {
		t.Helper()
		root, err := LoadRoot(writeTemp(t, content))
		if err != nil {
			return nil, err
		}
		instances, err := root.NormalizeInstances()
		if err != nil {
			return nil, err
		}
		if len(instances) != 1 {
			return nil, fmt.Errorf("normalized instances = %d, want 1", len(instances))
		}
		return instances[0], nil
	}
	return []struct {
		name string
		load func(*testing.T, string) (*Config, error)
	}{
		{"Load", func(t *testing.T, content string) (*Config, error) {
			t.Helper()
			return Load(writeTemp(t, content))
		}},
		{"LoadRoot", loadRoot},
		{"LoadRoot/instance", func(t *testing.T, content string) (*Config, error) {
			t.Helper()
			content = "instances:\n  -\n    " + strings.ReplaceAll(strings.TrimSpace(content), "\n", "\n    ") + "\n"
			return loadRoot(t, content)
		}},
	}
}

func nodeGroupsValidationRequireCleared(t *testing.T, cfg *Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var groups struct {
		Nodes443      []int             `yaml:"nodes_443"`
		NodesDirect   []int             `yaml:"nodes_direct"`
		NodeOverrides map[int]NodeEntry `yaml:"node_overrides"`
	}
	if err := yaml.Unmarshal(data, &groups); err != nil {
		t.Fatal(err)
	}
	if groups.Nodes443 != nil || groups.NodesDirect != nil || groups.NodeOverrides != nil {
		t.Fatalf("expanded node retained compact configuration: %+v", groups)
	}
	if expanded := cfg.ExpandNodes(); len(expanded) != 1 || expanded[0] != cfg {
		t.Fatal("expanded node must remain a single-node config on repeated expansion")
	}
}

func nodeGroupsValidationExpandedByID(t *testing.T, cfg *Config) map[int]*Config {
	t.Helper()
	byID := make(map[int]*Config)
	for _, node := range cfg.ExpandNodes() {
		if _, exists := byID[node.Panel.NodeID]; exists {
			t.Fatalf("expanded node ID %d more than once", node.Panel.NodeID)
		}
		nodeGroupsValidationRequireCleared(t, node)
		byID[node.Panel.NodeID] = node
	}
	return byID
}

func TestNodeGroupsValidationRejectsInvalidConfig(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	cases := []struct {
		name   string
		fields string
		kernel string
		want   []string
	}{
		{name: "duplicate shared ID", fields: "nodes_443: [17, 17]", want: []string{"duplicate", "17"}},
		{name: "duplicate direct ID", fields: "nodes_direct: [17, 17]", want: []string{"duplicate", "17"}},
		{name: "ID in both groups", fields: "nodes_443: [17]\nnodes_direct: [17]", want: []string{"duplicate", "17"}},
		{name: "zero shared ID", fields: "nodes_443: [0]", want: []string{"nodes_443", "positive"}},
		{name: "negative shared ID", fields: "nodes_443: [-17]", want: []string{"nodes_443", "positive"}},
		{name: "zero direct ID", fields: "nodes_direct: [0]", want: []string{"nodes_direct", "positive"}},
		{name: "negative direct ID", fields: "nodes_direct: [-17]", want: []string{"nodes_direct", "positive"}},
		{name: "fractional shared ID", fields: "nodes_443: [1.5]", want: []string{"parse"}},
		{name: "fractional direct ID", fields: "nodes_direct: [17.5]", want: []string{"parse"}},
		{name: "integral float direct ID", fields: "nodes_direct: [17.0]", want: []string{"parse"}},
		{name: "scientific notation direct ID", fields: "nodes_direct: [1.7e1]", want: []string{"parse"}},
		{name: "string direct ID", fields: "nodes_direct: [not-an-id]", want: []string{"parse"}},
		{name: "empty shared group does not fall back", fields: "nodes_443: []", want: []string{"nodes_"}},
		{name: "empty direct group does not fall back", fields: "nodes_direct: []", want: []string{"nodes_"}},
		{name: "both empty groups do not fall back", fields: "nodes_443: []\nnodes_direct: []", want: []string{"nodes_"}},
		{name: "empty group and null companion", fields: "nodes_443: []\nnodes_direct: null", want: []string{"nodes_"}},
		{name: "shared group with legacy nodes", fields: "nodes_443: [17]\nnodes:\n  - node_id: 22", want: []string{"nodes"}},
		{name: "direct group with legacy nodes", fields: "nodes_direct: [17]\nnodes:\n  - node_id: 22", want: []string{"nodes"}},
		{name: "shared group with machine", fields: "nodes_443: [17]\nmachine:\n  machine_id: 1\n  token: test-only-machine-token", want: []string{"machine"}},
		{name: "direct group with machine", fields: "nodes_direct: [17]\nmachine:\n  machine_id: 1\n  token: test-only-machine-token", want: []string{"machine"}},
		{name: "shared group with standalone", fields: "nodes_443: [17]\nstandalone:\n  enabled: true\n  node:\n    protocol: vless\n    server_port: 8443\n  users:\n    - id: 1\n      uuid: 11111111-1111-1111-1111-111111111111", want: []string{"standalone"}},
		{name: "direct group with standalone", fields: "nodes_direct: [17]\nstandalone:\n  enabled: true\n  node:\n    protocol: vless\n    server_port: 8443\n  users:\n    - id: 1\n      uuid: 11111111-1111-1111-1111-111111111111", want: []string{"standalone"}},
		{name: "overrides without compact groups", fields: "node_overrides:\n  17:\n    node_type: vless", want: []string{"node_overrides"}},
		{name: "empty overrides without compact groups", fields: "node_overrides: {}", want: []string{"node_overrides"}},
		{name: "overrides with null groups", fields: "nodes_443: null\nnodes_direct: null\nnode_overrides:\n  17: {}", want: []string{"node_overrides"}},
		{name: "overrides with legacy nodes", fields: "nodes:\n  - node_id: 17\nnode_overrides:\n  17: {}", want: []string{"node_overrides"}},
		{name: "zero override key", fields: "nodes_direct: [17]\nnode_overrides:\n  0: {}", want: []string{"node_overrides", "positive"}},
		{name: "negative override key", fields: "nodes_443: [17]\nnode_overrides:\n  -17: {}", want: []string{"node_overrides", "positive"}},
		{name: "unlisted override key", fields: "nodes_direct: [17]\nnode_overrides:\n  22: {}", want: []string{"node_overrides", "22"}},
		{name: "fractional override key selects listed ID", fields: "nodes_direct: [17]\nnode_overrides: {17.5: {node_type: vless}}", want: []string{"parse"}},
		{name: "integral float override key selects listed ID", fields: "nodes_direct: [17]\nnode_overrides: {17.0: {node_type: vless}}", want: []string{"parse"}},
		{name: "scientific notation override key selects listed ID", fields: "nodes_direct: [17]\nnode_overrides: {1.7e1: {node_type: vless}}", want: []string{"parse"}},
		{name: "matching override node ID is forbidden", fields: "nodes_443: [17]\nnode_overrides:\n  17:\n    node_id: 17", want: []string{"node_overrides", "node_id"}},
		{name: "different override node ID is forbidden", fields: "nodes_direct: [17]\nnode_overrides:\n  17:\n    node_id: 22", want: []string{"node_overrides", "node_id"}},
		{name: "negative override node ID is forbidden", fields: "nodes_direct: [17]\nnode_overrides:\n  17:\n    node_id: -1", want: []string{"node_overrides", "node_id"}},
		{name: "override cannot disable shared membership", fields: "nodes_443: [17]\nnode_overrides:\n  17:\n    kernel:\n      shared_reality:\n        enabled: false", want: []string{"node_overrides", "shared_reality"}},
		{name: "override cannot enable direct membership", fields: "nodes_direct: [17]\nnode_overrides:\n  17:\n    kernel:\n      shared_reality:\n        enabled: true", want: []string{"node_overrides", "shared_reality"}},
		{name: "empty shared override is forbidden", fields: "nodes_direct: [17]\nnode_overrides:\n  17:\n    kernel:\n      shared_reality: {}", want: []string{"node_overrides", "shared_reality"}},
		{name: "override cannot change listener", fields: "nodes_443: [17]\nnode_overrides:\n  17:\n    kernel:\n      shared_reality:\n        listen_port: 8443", want: []string{"node_overrides", "shared_reality"}},
		{name: "shared group requires xray", fields: "nodes_443: [17]", kernel: "type: singbox\n  shared_reality:\n    enabled: false", want: []string{"xray"}},
		{name: "shared group rejects default singbox", fields: "nodes_443: [17]", kernel: "{}", want: []string{"xray"}},
		{name: "shared group validates disabled listener IP", fields: "nodes_443: [17]", kernel: "type: xray\n  shared_reality:\n    enabled: false\n    listen_ip: not-an-ip", want: []string{"listen_ip"}},
		{name: "shared group validates negative listener port", fields: "nodes_443: [17]", kernel: "type: xray\n  shared_reality:\n    enabled: false\n    listen_port: -1", want: []string{"listen_port"}},
		{name: "shared group validates excessive listener port", fields: "nodes_443: [17]", kernel: "type: xray\n  shared_reality:\n    enabled: false\n    listen_port: 65536", want: []string{"listen_port"}},
	}
	for _, loader := range nodeGroupsValidationLoaders() {
		for _, tc := range cases {
			t.Run(loader.name+"/"+tc.name, func(t *testing.T) {
				kernel := tc.kernel
				if kernel == "" {
					kernel = "type: xray"
				}
				content := "panel:\n  url: https://panel.example.test\n  token: test-only-panel-token\n  node_id: 999\nkernel:\n  " + kernel + "\n" + tc.fields + "\n"
				_, err := loader.load(t, content)
				if err == nil {
					t.Fatal("invalid compact configuration was accepted; panel.node_id must not mask it")
				}
				for _, want := range tc.want {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %v, want substring %q", err, want)
					}
				}
			})
		}
	}
}

func TestNodeGroupsValidationDirectOnlyDoesNotStartPanelFallback(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	cases := []struct {
		name   string
		fields string
	}{
		{"direct group only", "nodes_direct: [17]"},
		{"empty shared companion", "nodes_443: []\nnodes_direct: [17]"},
		{"null shared companion", "nodes_443: null\nnodes_direct: [17]"},
		{"empty legacy nodes", "nodes: []\nnodes_direct: [17]"},
		{"null legacy nodes", "nodes: null\nnodes_direct: [17]"},
		{"empty compact overrides", "nodes_direct: [17]\nnode_overrides: {}"},
	}
	for _, loader := range nodeGroupsValidationLoaders() {
		for _, tc := range cases {
			t.Run(loader.name+"/"+tc.name, func(t *testing.T) {
				cfg, err := loader.load(t, "panel:\n  url: https://panel.example.test\n  token: test-only-panel-token\n  node_id: 999\n"+tc.fields+"\n")
				if err != nil {
					t.Fatal(err)
				}
				nodes := nodeGroupsValidationExpandedByID(t, cfg)
				if len(nodes) != 1 || nodes[17] == nil {
					t.Fatalf("expanded nodes = %v, want only listed node 17, never fallback 999", nodes)
				}
				if nodes[17].Kernel.Type != "singbox" {
					t.Fatalf("direct-only kernel.type = %q, want default singbox", nodes[17].Kernel.Type)
				}
				if shared := nodes[17].Kernel.SharedReality; shared != nil && shared.Enabled {
					t.Fatal("direct-only node unexpectedly enabled shared REALITY")
				}
			})
		}
	}
}

func TestNodeGroupsValidationAcceptsIntegerAliasesAndHex(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	for _, loader := range nodeGroupsValidationLoaders() {
		t.Run(loader.name, func(t *testing.T) {
			cfg, err := loader.load(t, `
panel:
  url: https://panel.example.test
  token: test-only-panel-token
  node_id: &listed_id 17
nodes_direct: [*listed_id, 0x16]
node_overrides:
  *listed_id :
    node_type: vless
  0x16:
    node_type: trojan
`)
			if err != nil {
				t.Fatalf("valid integer aliases and hex values rejected: %v", err)
			}
			nodes := nodeGroupsValidationExpandedByID(t, cfg)
			if len(nodes) != 2 || nodes[17] == nil || nodes[22] == nil {
				t.Fatalf("expanded integer aliases and hex IDs = %v, want 17 and 22", nodes)
			}
			if nodes[17].Panel.NodeType != "vless" || nodes[22].Panel.NodeType != "trojan" {
				t.Fatal("integer alias and hex override keys must select their listed nodes")
			}
		})
	}
}

func TestNodeGroupsValidationNullGroupsKeepLegacySingleNode(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	for _, loader := range nodeGroupsValidationLoaders() {
		t.Run(loader.name, func(t *testing.T) {
			cfg, err := loader.load(t, `
panel:
  url: https://panel.example.test
  token: test-only-panel-token
  node_id: 999
nodes_443: null
nodes_direct: null
node_overrides: null
`)
			if err != nil {
				t.Fatal(err)
			}
			nodes := nodeGroupsValidationExpandedByID(t, cfg)
			if len(nodes) != 1 || nodes[999] != cfg {
				t.Fatal("null compact fields must preserve legacy single-node expansion")
			}
		})
	}
}

func TestNodeGroupsValidationInstanceListsAndOverridesStayLocal(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	path := writeTemp(t, `
nodes_443: null
nodes_direct: null
node_overrides: null
kernel:
  type: xray
  shared_reality:
    enabled: true
    listen_ip: 192.0.2.10
    listen_port: 7443
instances:
  - panel:
      url: https://panel-a.example.test
      token: test-only-panel-token
    nodes_443: [7]
    nodes_direct: [3]
    node_overrides:
      3:
        node_type: trojan
        kernel:
          log_level: error
  - panel:
      url: https://panel-b.example.test
      token: test-only-panel-token
    nodes_direct: [7]
    kernel:
      type: singbox
  - panel:
      url: https://panel-c.example.test
      token: test-only-panel-token
      node_id: 999
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 3 {
		t.Fatalf("normalized instances = %d, want 3", len(instances))
	}
	if err := ValidateStartupLayout(instances); err != nil {
		t.Fatalf("same node IDs on distinct panels must be accepted: %v", err)
	}
	first := nodeGroupsValidationExpandedByID(t, instances[0])
	if len(first) != 2 || first[7] == nil || first[3] == nil {
		t.Fatalf("first instance nodes = %v, want 7 and 3", first)
	}
	if shared := first[7].Kernel.SharedReality; shared == nil || !shared.Enabled {
		t.Fatal("shared membership lost inherited REALITY")
	}
	if shared := first[3].Kernel.SharedReality; shared != nil && shared.Enabled {
		t.Fatal("direct membership must disable inherited shared REALITY")
	}
	if first[3].Panel.NodeType != "trojan" || first[3].Kernel.LogLevel != "error" {
		t.Fatal("first instance lost its local node override")
	}
	second := nodeGroupsValidationExpandedByID(t, instances[1])
	if len(second) != 1 || second[7] == nil {
		t.Fatalf("second instance nodes = %v, want only its local node 7", second)
	}
	if second[7].Kernel.Type != "singbox" || second[7].Kernel.LogLevel != "warn" || second[7].Panel.NodeType != "" {
		t.Fatal("direct-only singbox instance inherited another instance's override")
	}
	if shared := second[7].Kernel.SharedReality; shared != nil && shared.Enabled {
		t.Fatal("direct-only singbox instance retained enabled inherited shared REALITY")
	}
	third := nodeGroupsValidationExpandedByID(t, instances[2])
	if len(third) != 1 || third[999] == nil {
		t.Fatalf("legacy instance nodes = %v, want only its panel.node_id 999", third)
	}
	if shared := third[999].Kernel.SharedReality; shared == nil || !shared.Enabled {
		t.Fatal("compact groups must not disable a sibling legacy instance's inherited REALITY")
	}
	if shared := root.Kernel.SharedReality; shared == nil || !shared.Enabled || shared.ListenPort != 7443 {
		t.Fatal("instance group expansion mutated top-level listener defaults")
	}
}

func TestNodeGroupsValidationOverridesPreserveLegacySettings(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	common := `
panel:
  url: https://panel.example.test
  token: test-only-panel-token
  node_id: 999
kernel:
  type: xray
  config_dir: /fixture/base
  geo_data_dir: /fixture/global-geo
  log_level: warn
  custom_config: /fixture/base-custom.json
  shared_reality:
    enabled: true
    listen_ip: 192.0.2.10
    listen_port: 7443
cert:
  cert_mode: file
  cert_dir: /fixture/base-certs
  cert_file: /fixture/base-cert.pem
  key_file: /fixture/base-key.pem
`
	cases := []struct {
		name   string
		fields string
	}{
		{"legacy nodes", `nodes:
  - node_id: 17
    node_type: vless
    kernel:
      config_dir: /fixture/node-17
      geo_data_dir: /fixture/node-17-geo
      log_level: error
      custom_config: /fixture/node-17-custom.json
    cert:
      cert_mode: file
      cert_dir: /fixture/node-17-certs
      cert_file: /fixture/node-17-cert.pem
      key_file: /fixture/node-17-key.pem
  - node_id: 22
    node_type: trojan
    kernel:
      config_dir: /fixture/node-22
      shared_reality:
        enabled: false
`},
		{"compact overrides", `nodes_443: [17]
nodes_direct: [22]
node_overrides:
  17:
    node_type: vless
    kernel:
      config_dir: /fixture/node-17
      geo_data_dir: /fixture/node-17-geo
      log_level: error
      custom_config: /fixture/node-17-custom.json
    cert:
      cert_mode: file
      cert_dir: /fixture/node-17-certs
      cert_file: /fixture/node-17-cert.pem
      key_file: /fixture/node-17-key.pem
  22:
    node_type: trojan
    kernel:
      config_dir: /fixture/node-22
`},
	}
	for _, loader := range nodeGroupsValidationLoaders() {
		for _, tc := range cases {
			t.Run(loader.name+"/"+tc.name, func(t *testing.T) {
				cfg, err := loader.load(t, common+tc.fields)
				if err != nil {
					t.Fatal(err)
				}
				nodes := nodeGroupsValidationExpandedByID(t, cfg)
				if len(nodes) != 2 || nodes[17] == nil || nodes[22] == nil {
					t.Fatalf("expanded nodes = %v, want 17 and 22", nodes)
				}
				first := nodes[17]
				if first.Panel.NodeType != "vless" || first.Kernel.ConfigDir != "/fixture/node-17" || first.Kernel.GeoDataDir != "/fixture/node-17-geo" || first.Kernel.LogLevel != "error" || first.Kernel.CustomConfig != "/fixture/node-17-custom.json" {
					t.Fatalf("node 17 lost explicit type, directory or custom config: panel = %+v, kernel = %+v", first.Panel, first.Kernel)
				}
				if first.Cert.CertMode != "file" || first.Cert.CertDir != "/fixture/node-17-certs" || first.Cert.CertFile != "/fixture/node-17-cert.pem" || first.Cert.KeyFile != "/fixture/node-17-key.pem" {
					t.Fatalf("node 17 lost explicit certificate settings: %+v", first.Cert)
				}
				if shared := first.Kernel.SharedReality; shared == nil || !shared.Enabled || shared.ListenIP != "192.0.2.10" || shared.ListenPort != 7443 {
					t.Fatalf("node 17 shared listener = %+v, want inherited enabled listener", shared)
				}
				second := nodes[22]
				if second.Panel.NodeType != "trojan" || second.Kernel.ConfigDir != "/fixture/node-22" || second.Kernel.GeoDataDir != "/fixture/global-geo" || second.Kernel.LogLevel != "warn" || second.Kernel.CustomConfig != "/fixture/base-custom.json" {
					t.Fatalf("node 22 lost explicit directory or inherited defaults: panel = %+v, kernel = %+v", second.Panel, second.Kernel)
				}
				if second.Cert.CertMode != "file" || second.Cert.CertDir != "/fixture/base-certs" || second.Cert.CertFile != "/fixture/base-cert.pem" || second.Cert.KeyFile != "/fixture/base-key.pem" {
					t.Fatalf("node 22 lost inherited certificate settings: %+v", second.Cert)
				}
				if shared := second.Kernel.SharedReality; shared != nil && shared.Enabled {
					t.Fatal("node 22 must remain an ordinary direct node")
				}
			})
		}
	}
}

func TestNodeGroupsValidationIdentityAndDefaultDirsMatchLegacyNodeSet(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	legacyPath := writeTemp(t, `
kernel:
  type: xray
instances:
  - panel:
      url: https://panel.example.test
      token: test-only-panel-token
      node_id: 999
    nodes:
      - node_id: 22
      - node_id: 3
      - node_id: 17
  - panel:
      url: https://other-panel.example.test
      token: test-only-other-panel-token
      node_id: 55
`)
	legacy, err := LoadRoot(legacyPath)
	if err != nil {
		t.Fatalf("LoadRoot legacy reference: %v", err)
	}
	legacyInstances, err := legacy.NormalizeInstances()
	if err != nil || len(legacyInstances) != 2 {
		t.Fatalf("NormalizeInstances legacy reference: %v, instances = %d", err, len(legacyInstances))
	}
	wantID := legacyInstances[0].InstanceID
	if wantID == "" {
		t.Fatal("legacy reference has no instance identity")
	}
	cases := []struct {
		name    string
		fields  string
		reverse bool
	}{
		{"legacy unordered", "nodes:\n  - node_id: 22\n  - node_id: 3\n  - node_id: 17", false},
		{"legacy reordered", "nodes:\n  - node_id: 17\n  - node_id: 22\n  - node_id: 3", true},
		{"compact unordered", "nodes_443: [22, 17]\nnodes_direct: [3]", false},
		{"compact reordered", "nodes_direct: [3]\nnodes_443: [17, 22]", true},
		{"compact regrouped", "nodes_443: [3]\nnodes_direct: [22, 17]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := "  - panel:\n      url: https://panel.example.test\n      token: test-only-panel-token\n      node_id: 999\n    " + strings.ReplaceAll(tc.fields, "\n", "\n    ") + "\n"
			second := "  - panel:\n      url: https://other-panel.example.test\n      token: test-only-other-panel-token\n      node_id: 55\n"
			if tc.reverse {
				first, second = second, first
			}
			path := writeTemp(t, "kernel:\n  type: xray\ninstances:\n"+first+second)
			root, err := LoadRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			instances, err := root.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) != 2 {
				t.Fatalf("normalized instances = %d, want 2", len(instances))
			}
			var cfg *Config
			for _, instance := range instances {
				if instance.Panel.URL == "https://panel.example.test" {
					cfg = instance
				}
			}
			if cfg == nil || cfg.InstanceID == "" {
				t.Fatal("missing instance or automatically derived identity")
			}
			if cfg.InstanceID != wantID {
				t.Fatalf("instance ID = %q, want legacy node-set identity %q", cfg.InstanceID, wantID)
			}
			id, err := cfg.AutoInstanceID()
			if err != nil || id != cfg.InstanceID {
				t.Fatalf("AutoInstanceID after normalization = %q, %v; assigned ID = %q", id, err, cfg.InstanceID)
			}
			wantDir := filepath.Join(filepath.Dir(path), wantID)
			if filepath.Clean(cfg.Kernel.ConfigDir) != wantDir || filepath.Clean(cfg.Cert.CertDir) != filepath.Join(wantDir, "certs") || filepath.Clean(cfg.Kernel.GeoDataDir) != wantDir {
				t.Fatalf("default directories must use the legacy node-set identity before expansion: kernel = %+v, cert_dir = %q, want base %q", cfg.Kernel, cfg.Cert.CertDir, wantDir)
			}
			nodes := nodeGroupsValidationExpandedByID(t, cfg)
			if len(nodes) != 3 || nodes[17] == nil || nodes[22] == nil || nodes[3] == nil {
				t.Fatalf("expanded nodes = %v, want the same legacy set 17, 22, 3", nodes)
			}
		})
	}
}

func TestNodeGroupsValidationCustomConfigOverridesUseStartupValidation(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	for _, group := range []string{"nodes_443", "nodes_direct"} {
		for _, exists := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/exists=%t", group, exists), func(t *testing.T) {
				customPath := filepath.Join(t.TempDir(), "missing-custom.json")
				if exists {
					customPath = writeTemp(t, "{}\n")
				}
				path := writeTemp(t, fmt.Sprintf(`
panel:
  url: https://panel.example.test
  token: test-only-panel-token
kernel:
  type: xray
%s: [17]
node_overrides:
  17:
    kernel:
      custom_config: %q
`, group, filepath.ToSlash(customPath)))
				root, err := LoadRoot(path)
				if err != nil {
					t.Fatal(err)
				}
				instances, err := root.NormalizeInstances()
				if err != nil {
					t.Fatal(err)
				}
				err = ValidateStartupLayout(instances)
				if exists {
					if err != nil {
						t.Fatalf("existing compact custom_config rejected: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "custom_config") || !strings.Contains(err.Error(), "missing-custom.json") {
					t.Fatalf("error = %v, want missing overridden custom_config startup error", err)
				}
			})
		}
	}
}

func TestNodeGroupsValidationRootYAMLRoundTripPreservesCompactBehavior(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	path := writeTemp(t, `
kernel:
  type: xray
  shared_reality:
    enabled: false
    listen_ip: 192.0.2.10
    listen_port: 7443
instances:
  - panel:
      url: https://panel-a.example.test
      token: test-only-panel-token
      node_id: 999
    nodes_443: [17, 3]
    nodes_direct: [22]
    node_overrides:
      17:
        node_type: vless
        kernel:
          config_dir: /fixture/roundtrip-node-17
          geo_data_dir: /fixture/roundtrip-geo-17
          log_level: error
          custom_config: /fixture/roundtrip-custom-17.json
        cert:
          cert_mode: file
          cert_dir: /fixture/roundtrip-certs-17
          cert_file: /fixture/roundtrip-cert-17.pem
          key_file: /fixture/roundtrip-key-17.pem
      22:
        node_type: trojan
        kernel:
          config_dir: /fixture/roundtrip-node-22
  - panel:
      url: https://panel-b.example.test
      token: test-only-panel-token
      node_id: 1000
    kernel:
      type: singbox
    nodes_direct: [17]
`)
	before, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("initial LoadRoot: %v", err)
	}
	data, err := yaml.Marshal(before)
	if err != nil {
		t.Fatalf("marshal loaded root: %v", err)
	}
	after, err := LoadRoot(writeTemp(t, string(data)))
	if err != nil {
		t.Fatalf("LoadRoot after YAML round-trip: %v", err)
	}
	wants := map[string]map[int]bool{
		"https://panel-a.example.test": {17: true, 3: true, 22: false},
		"https://panel-b.example.test": {17: false},
	}
	ids := make(map[string]string)
	initialInstances, err := before.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances before round-trip: %v", err)
	}
	for _, instance := range initialInstances {
		ids[instance.Panel.URL] = instance.InstanceID
	}
	for _, stage := range []struct {
		name string
		root *RootConfig
	}{{"before", before}, {"after", after}} {
		t.Run(stage.name, func(t *testing.T) {
			instances, err := stage.root.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) != len(wants) {
				t.Fatalf("normalized instances = %d, want %d", len(instances), len(wants))
			}
			seen := make(map[string]bool)
			for _, instance := range instances {
				url := instance.Panel.URL
				want, ok := wants[url]
				if !ok || seen[url] {
					t.Fatalf("unexpected or duplicated instance panel %q", url)
				}
				seen[url] = true
				if instance.InstanceID == "" {
					t.Fatal("missing instance identity")
				}
				if instance.InstanceID != ids[url] {
					t.Fatalf("instance ID after round-trip = %q, want %q", instance.InstanceID, ids[url])
				}
				nodes := nodeGroupsValidationExpandedByID(t, instance)
				if len(nodes) != len(want) {
					t.Fatalf("%s expanded %d nodes, want literal set %v", url, len(nodes), want)
				}
				for id, enabled := range want {
					node := nodes[id]
					if node == nil {
						t.Fatalf("%s lost intended node %d", url, id)
					}
					shared := node.Kernel.SharedReality
					if got := shared != nil && shared.Enabled; got != enabled {
						t.Fatalf("%s node %d shared enabled = %t, want %t", url, id, got, enabled)
					}
				}
				if url == "https://panel-b.example.test" {
					if nodes[17].Kernel.Type != "singbox" || nodes[17].Panel.NodeType != "" {
						t.Fatal("round-trip lost direct-only kernel or leaked site-local overrides")
					}
					continue
				}
				first := nodes[17]
				if first.Panel.NodeType != "vless" || first.Kernel.ConfigDir != "/fixture/roundtrip-node-17" || first.Kernel.GeoDataDir != "/fixture/roundtrip-geo-17" || first.Kernel.LogLevel != "error" || first.Kernel.CustomConfig != "/fixture/roundtrip-custom-17.json" {
					t.Fatalf("round-trip lost per-node kernel overrides: %+v", first.Kernel)
				}
				if first.Cert.CertMode != "file" || first.Cert.CertDir != "/fixture/roundtrip-certs-17" || first.Cert.CertFile != "/fixture/roundtrip-cert-17.pem" || first.Cert.KeyFile != "/fixture/roundtrip-key-17.pem" {
					t.Fatalf("round-trip lost per-node certificate overrides: %+v", first.Cert)
				}
				if second := nodes[22]; second.Panel.NodeType != "trojan" || second.Kernel.ConfigDir != "/fixture/roundtrip-node-22" || second.Kernel.LogLevel != "warn" || second.Kernel.CustomConfig != "" {
					t.Fatalf("round-trip lost direct-node overrides or leaked another node's settings: %+v", second.Kernel)
				}
			}
		})
	}
}

func TestNodeGroupsValidationRejectsTopLevelFieldsWithInstances(t *testing.T) {
	nodeGroupsValidationClearEnv(t)
	cases := []struct {
		name   string
		fields string
		want   string
	}{
		{"shared IDs", "nodes_443: [17]", "nodes_443"},
		{"empty shared IDs", "nodes_443: []", "nodes_443"},
		{"direct IDs", "nodes_direct: [17]", "nodes_direct"},
		{"empty direct IDs", "nodes_direct: []", "nodes_direct"},
		{"overrides", "node_overrides:\n  17:\n    node_type: vless", "node_overrides"},
		{"empty overrides", "node_overrides: {}", "node_overrides"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.fields+`
kernel:
  type: xray
instances:
  - panel:
      url: https://panel.example.test
      token: test-only-panel-token
      node_id: 999
    nodes_direct: [17]
`)
			_, err := LoadRoot(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "instances") {
				t.Fatalf("error = %v, want %s rejected in top-level instances configuration", err, tc.want)
			}
		})
	}
}
