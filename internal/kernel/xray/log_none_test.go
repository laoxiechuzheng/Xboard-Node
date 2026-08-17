package xray

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestBuildConfigLogLevelNone(t *testing.T) {
	kcfg := testKernelCfg
	kcfg.LogLevel = "none"
	nc := &panel.NodeConfig{Protocol: "vmess", ServerPort: 10086}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	logCfg := cfg["log"].(M)

	for key, want := range map[string]string{
		"loglevel": "none",
		"error":    "none",
		"access":   "none",
	} {
		if got := logCfg[key]; got != want {
			t.Fatalf("log.%s = %v, want %q", key, got, want)
		}
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal xray config: %v", err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("xray rejected log_level none config: %v", err)
	}
}

func TestNewWithLogLevelNoneDoesNotCreateAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-audit.log")
	x := New(config.KernelConfig{Type: "xray", LogLevel: "none", AuditLog: path})
	if x.audit != nil {
		t.Fatal("audit logger must be nil when kernel.log_level is none")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("none audit logger created %q, stat error = %v", path, err)
	}
}
