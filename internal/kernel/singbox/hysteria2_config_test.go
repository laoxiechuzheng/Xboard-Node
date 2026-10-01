package singbox

import (
	"strconv"
	"testing"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/sagernet/sing-box/option"
)

func TestBuildInboundHysteria2PanelAliases(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		version  int
	}{
		{"hysteria", 2},
		{"hysteria2", 0},
		{"hysteria2", 1},
		{"hy2", 0},
	} {
		t.Run(tc.protocol+"-v"+strconv.Itoa(tc.version), func(t *testing.T) {
			node := testNodeSpec(&panel.NodeConfig{Protocol: tc.protocol, Version: tc.version, ServerPort: 8443})
			inbound := buildInbound(node, testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
			if inbound == nil {
				t.Fatal("HY2 alias produced no inbound")
			}
			assertMapValue(t, inbound, "type", "hysteria2")
			assertMapValue(t, inbound, "tag", "hysteria2-in")
			users := inbound["users"].([]M)
			if len(users) != len(testUsers) {
				t.Fatalf("users = %d, want %d", len(users), len(testUsers))
			}
			for i, user := range users {
				if user["name"] != testUsers[i].UUID || user["password"] != testUsers[i].UUID {
					t.Fatal("HY2 name/password must use the panel UUID")
				}
			}
			if _, exists := users[0]["auth_str"]; exists {
				t.Fatal("HY2 must not use Hysteria1 auth_str")
			}
			tls := inbound["tls"].(M)
			assertMapValue(t, tls, "enabled", true)
			assertMapValue(t, tls, "alpn", []string{"h3"})
			for _, field := range []string{"certificate_path", "key_path"} {
				if _, exists := tls[field]; exists {
					t.Fatalf("in-memory TLS unexpectedly uses %s", field)
				}
			}
			if node.Protocol != tc.protocol || node.Version != tc.version {
				t.Fatal("building an alias must not mutate the panel node")
			}
		})
	}
}

func TestHysteria2UserSlotsPreserveAuthenticatedSessionIdentity(t *testing.T) {
	previous := []option.Hysteria2User{{Name: "user-a", Password: "test-a"}, {Name: "user-b", Password: "test-b"}}
	want := []option.Hysteria2User{{Name: "user-b", Password: "test-b"}, {Name: "user-c", Password: "test-c"}}
	slots := stableHysteria2Users(previous, want)
	if len(slots) != 3 || slots[0].Name != "user-a" || slots[1].Name != "user-b" || slots[2].Name != "user-c" {
		t.Fatal("removing or adding users must not reuse a live QUIC authentication index")
	}
	if slots[0].Password == "" || slots[0].Password == "test-a" || slots[0].Password == "test-b" || slots[0].Password == "test-c" {
		t.Fatal("retired slot must have a nonempty, disabled authentication credential")
	}
	if slots[1].Password != "test-b" || slots[2].Password != "test-c" {
		t.Fatal("active slot credentials changed")
	}
	if previous[0].Password != "test-a" || len(want) != 2 {
		t.Fatal("stable slot preparation mutated its inputs")
	}
	updated := stableHysteria2Users(slots, []option.Hysteria2User{{Name: "user-c", Password: "test-c"}, {Name: "user-b", Password: "test-b-new"}})
	if len(updated) != 3 || updated[1].Name != "user-b" || updated[1].Password != "test-b-new" || updated[2].Name != "user-c" {
		t.Fatal("reordering or changing credentials must preserve authentication indices")
	}
	restored := stableHysteria2Users(updated, previous)
	if restored[0] != previous[0] || restored[1] != previous[1] || restored[2].Name != "user-c" || restored[2].Password == "test-c" {
		t.Fatal("reactivating users must restore their original slots and disable removed credentials")
	}
}

func TestBuildUserMapRejectsAmbiguousIdentities(t *testing.T) {
	users := []model.UserSpec{
		{ID: 7, UUID: "known"}, {ID: 42, UUID: "duplicate"}, {ID: 43, UUID: "duplicate"},
		{ID: 44, UUID: "duplicate"}, {ID: 0, UUID: "invalid-id"}, {ID: 45, UUID: ""},
	}
	got := buildUserMap(users)
	if got["known"] != 7 || got["duplicate"] != 0 {
		t.Fatal("duplicate UUIDs must not select an arbitrary account")
	}
	if _, ok := got[""]; ok {
		t.Fatal("empty authentication identity must not become an account")
	}
	if _, ok := got["invalid-id"]; ok {
		t.Fatal("nonpositive user IDs must not become accounts")
	}
	if users[0] != (model.UserSpec{ID: 7, UUID: "known"}) {
		t.Fatal("building a user map mutated users")
	}
}
