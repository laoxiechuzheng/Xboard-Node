package service

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestNewServiceAuditInitFailureKeepsProxyRunning(t *testing.T) {
	cfg := &config.Config{
		Kernel: config.KernelConfig{Type: "singbox"},
		// Plain HTTP to a remote host is rejected by the audit uploader.
		Audit: config.AuditConfig{URL: "http://flux.example/api/node-audit/ingest", Site: "jpxd", Secret: "s"},
	}
	s := newService(cfg, nil)
	if s.auditClient != nil {
		t.Fatal("failed audit initialisation must not leave an audit client")
	}
	if s.kernel == nil {
		t.Fatal("kernel must still be created when audit initialisation fails")
	}
}

func TestNewServiceAuditSinkIsAttachedWhenConfigured(t *testing.T) {
	cfg := &config.Config{
		Kernel: config.KernelConfig{Type: "singbox"},
		Audit:  config.AuditConfig{URL: "https://flux.example/api/node-audit/ingest", Site: "jpxd", Secret: "s"},
	}
	s := newService(cfg, nil)
	if s.auditClient == nil {
		t.Fatal("valid audit config must create an audit client")
	}
	s.auditClient.Close()
}

func TestValidateTLSRequirementsAcceptsHy2Alias(t *testing.T) {
	for _, protocol := range []string{"hysteria", "hysteria2", "hy2", "tuic", "anytls"} {
		if err := validateTLSRequirements(&model.NodeSpec{Protocol: protocol}, kernel.TLSCert{}, "singbox"); err == nil {
			t.Fatalf("%s without a certificate must be rejected", protocol)
		}
	}
}
