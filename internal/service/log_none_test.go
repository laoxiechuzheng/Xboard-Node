package service

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestApplyRemoteOverridesPreservesLocalKernelLogLevelNone(t *testing.T) {
	s := newTestService(&fakeKernel{})
	s.cfg = &config.Config{Kernel: config.KernelConfig{LogLevel: "none"}}

	s.applyRemoteOverrides(context.Background(), &model.NodeSpec{KernelLogLevel: "warn"})

	if got := s.cfg.Kernel.LogLevel; got != "none" {
		t.Fatalf("kernel log level = %q, want none", got)
	}
}
