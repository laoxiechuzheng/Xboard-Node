package singbox

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
)

func TestBuildConfigLogLevelNone(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "none"}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
	}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	logCfg := cfg["log"].(M)

	if got := logCfg["disabled"]; got != true {
		t.Fatalf("log.disabled = %v, want true", got)
	}
	if _, ok := logCfg["level"]; ok {
		t.Fatal("disabled sing-box logger must not include a log level")
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal sing-box config: %v", err)
	}
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), data)
	if err != nil {
		t.Fatalf("sing-box rejected log_level none config: %v", err)
	}
	if opts.Log == nil || !opts.Log.Disabled {
		t.Fatalf("parsed sing-box log options = %#v, want disabled", opts.Log)
	}
}
