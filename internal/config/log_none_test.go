package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

func TestInitLoggerNoneDoesNotCreateOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xboard-node.log")
	InitLogger(LogConfig{Level: "none", Output: path})
	defer InitLogger(LogConfig{Level: "info", Output: "stdout"})

	nlog.Core().Error("this message must be discarded")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("none logger created %q, stat error = %v", path, err)
	}
}

func TestIsLogLevelDisabled(t *testing.T) {
	for _, level := range []string{"none", "NONE", " none "} {
		if !IsLogLevelDisabled(level) {
			t.Fatalf("IsLogLevelDisabled(%q) = false, want true", level)
		}
	}
	if IsLogLevelDisabled("error") {
		t.Fatal("error log level must remain enabled")
	}
}
