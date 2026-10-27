package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSNIWhitelistAcceptsCommaStringAndList(t *testing.T) {
	want := ServerNameList{"iosapps.itunes.apple.com", "apple.com", "www.apple.com"}
	for name, value := range map[string]string{
		"comma string": `" iosapps.itunes.apple.com, Apple.com ,www.apple.com,"`,
		"list":         `["iosapps.itunes.apple.com", "apple.com,www.apple.com"]`,
	} {
		t.Run(name, func(t *testing.T) {
			var kernel KernelConfig
			if err := yaml.Unmarshal([]byte("sni_whitelist: "+value), &kernel); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(kernel.SNIWhitelist, want) {
				t.Fatalf("sni_whitelist = %q, want %q", kernel.SNIWhitelist, want)
			}
		})
	}
	var kernel KernelConfig
	if err := yaml.Unmarshal([]byte("sni_whitelist:\n"), &kernel); err != nil || len(kernel.SNIWhitelist) != 0 {
		t.Fatalf("empty sni_whitelist = %q, %v; want no restriction", kernel.SNIWhitelist, err)
	}
	if err := yaml.Unmarshal([]byte("sni_whitelist: {a: b}\n"), &kernel); err == nil {
		t.Fatal("a mapping was accepted as sni_whitelist")
	}
}

func TestSNIWhitelistInheritedAndOverriddenPerNode(t *testing.T) {
	root, err := LoadRoot(writeTemp(t, `
kernel:
  type: singbox
  sni_whitelist: "iosapps.itunes.apple.com,apple.com"
instances:
  - panel:
      url: "https://a.example.com"
      token: "t"
    nodes:
      - node_id: 1500
      - node_id: 901
        kernel:
          sni_whitelist: [www.apple.com]
  - panel:
      url: "https://b.example.com"
      token: "t"
    kernel:
      sni_whitelist: "b.example.net"
    nodes:
      - node_id: 1500
`))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	nodesA := instances[0].ExpandNodes()
	if got := nodesA[0].Kernel.SNIWhitelist; !reflect.DeepEqual(got, ServerNameList{"iosapps.itunes.apple.com", "apple.com"}) {
		t.Fatalf("inherited sni_whitelist = %q", got)
	}
	if got := nodesA[1].Kernel.SNIWhitelist; !reflect.DeepEqual(got, ServerNameList{"www.apple.com"}) {
		t.Fatalf("per-node sni_whitelist = %q", got)
	}
	if got := instances[1].ExpandNodes()[0].Kernel.SNIWhitelist; !reflect.DeepEqual(got, ServerNameList{"b.example.net"}) {
		t.Fatalf("instance sni_whitelist = %q", got)
	}
}

func TestSNIWhitelistValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"xray kernel":     {"kernel:\n  type: xray\n  sni_whitelist: a.example.com\n", "requires kernel.type 'singbox'"},
		"ip address":      {"kernel:\n  sni_whitelist: 1.2.3.4\n", "invalid server name"},
		"port":            {"kernel:\n  sni_whitelist: a.example.com:443\n", "invalid server name"},
		"bad wildcard":    {"kernel:\n  sni_whitelist: a.*.example.com\n", "invalid server name"},
		"per-node xray":   {"kernel:\n  type: xray\nnodes:\n  - node_id: 1\n    kernel:\n      sni_whitelist: a.example.com\n", "nodes[0]: kernel.sni_whitelist requires"},
		"per-node format": {"nodes:\n  - node_id: 1\n    kernel:\n      sni_whitelist: \"a b.example.com\"\n", "nodes[0]: kernel.sni_whitelist: invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadRoot(writeTemp(t, "panel:\n  url: https://a.example.com\n  token: t\n  node_id: 1\n"+tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
	root, err := LoadRoot(writeTemp(t, "panel:\n  url: https://a.example.com\n  token: t\n  node_id: 1\nkernel:\n  sni_whitelist: \"*.apple.com,iosapps.itunes.apple.com\"\n"))
	if err != nil {
		t.Fatalf("valid whitelist rejected: %v", err)
	}
	if root.Config.Kernel.Type != "singbox" {
		t.Fatal("whitelist must work with the default sing-box kernel")
	}
}
