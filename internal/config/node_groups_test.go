package config

import (
	"path/filepath"
	"testing"
)

func TestLoadNodeGroups(t *testing.T) {
	loaders := []struct {
		name string
		load func(string) (*Config, error)
	}{
		{"single", Load},
		{"root", func(path string) (*Config, error) {
			root, err := LoadRoot(path)
			if err != nil {
				return nil, err
			}
			instances, err := root.NormalizeInstances()
			if err != nil {
				return nil, err
			}
			return instances[0], nil
		}},
	}
	for _, loader := range loaders {
		t.Run(loader.name, func(t *testing.T) {
			path := writeTemp(t, `panel:
  url: https://panel.example.com
  token: test-token
  node_id: 999
kernel:
  type: xray
  config_dir: /data/panel
  shared_reality:
    enabled: false
    listen_ip: 127.0.0.1
    listen_port: 8443
nodes_443: [810, 811]
nodes_direct: [800]
`)
			cfg, err := loader.load(path)
			if err != nil {
				t.Fatal(err)
			}
			nodes := cfg.ExpandNodes()
			if len(nodes) != 3 {
				t.Fatalf("expanded %d nodes, want 3 explicitly listed nodes", len(nodes))
			}
			wants := []struct {
				id      int
				enabled bool
				dir     string
			}{
				{810, true, "node-810"},
				{811, true, "node-811"},
				{800, false, "node-800"},
			}
			for i, want := range wants {
				got := nodes[i]
				if got.Panel.NodeID != want.id {
					t.Fatalf("node[%d] ID = %d, want %d", i, got.Panel.NodeID, want.id)
				}
				requireSharedRealitySettings(t, got.Kernel, sharedRealityTestSettings{want.enabled, "127.0.0.1", 8443})
				if got.Kernel.ConfigDir != filepath.Join("/data/panel", want.dir) {
					t.Fatalf("node[%d] config_dir = %q, want a unique per-node directory", i, got.Kernel.ConfigDir)
				}
				if got.Kernel.GeoDataDir != "/data/panel" || got.Panel.Token != "test-token" {
					t.Fatalf("node[%d] changed inherited panel or geo settings", i)
				}
			}
		})
	}
}
