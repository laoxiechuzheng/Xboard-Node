package xray

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/http"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// accountUserContext builds the inbound context of a session that
// authenticated with account.
func accountUserContext(userID int, account protocol.Account) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.9"), 40000),
		User:   &protocol.MemoryUser{Email: userEmail(userID), Account: account},
	})
}

// nodeUserContext builds the inbound context the node's inbound produces for
// u, from the same account constructor the kernel adds users with.
func nodeUserContext(t *testing.T, node *model.NodeSpec, u model.UserSpec) context.Context {
	t.Helper()
	mu, err := toMemoryUser(node.Protocol, node, u)
	if err != nil {
		t.Fatal(err)
	}
	return accountUserContext(u.ID, mu.Account)
}

// The credential a session presents must equal the one pinned for its user,
// for every protocol with a per-user secret.
func TestAccountCredentialMatchesConfiguredUUID(t *testing.T) {
	upper := "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
	for _, node := range []*model.NodeSpec{
		{Protocol: "vless"},
		{Protocol: "vmess"},
		{Protocol: "trojan"},
		{Protocol: "shadowsocks", Cipher: "aes-128-gcm"},
		{Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm"},
		{Protocol: "shadowsocks", Cipher: "2022-blake3-aes-256-gcm"},
	} {
		mu, err := toMemoryUser(node.Protocol, node, model.UserSpec{ID: 1, UUID: upper})
		if err != nil {
			t.Fatal(err)
		}
		got, want := accountCredential(mu.Account), credentialFor(node)(upper)
		if got == "" || got != want {
			t.Fatalf("%s/%s: session credential %q, pinned %q", node.Protocol, node.Cipher, got, want)
		}
	}
	hysteria := &model.NodeSpec{Protocol: "hysteria"}
	if got, want := accountCredential(&hysteriaaccount.MemoryAccount{Auth: upper}), credentialFor(hysteria)(upper); got != want {
		t.Fatalf("hysteria: session credential %q, pinned %q", got, want)
	}

	// VLESS identifies users by the UUID's bytes: the case of the panel
	// string does not matter. Trojan compares the exact password: it does.
	lower := strings.ToLower(upper)
	vless := &model.NodeSpec{Protocol: "vless"}
	if credentialFor(vless)(lower) != credentialFor(vless)(upper) {
		t.Fatal("vless credential depends on the UUID string's case")
	}
	trojan := &model.NodeSpec{Protocol: "trojan"}
	if credentialFor(trojan)(lower) == credentialFor(trojan)(upper) {
		t.Fatal("trojan credential ignores the password's case")
	}
	// Account types without a per-user secret stay unchecked.
	if got := accountCredential(&http.Account{Username: upper, Password: upper}); got != "" {
		t.Fatalf("http credential = %q, want unchecked", got)
	}
}

// A user added hitlessly through the UserManager must get the same SS2022 key
// the config gives it: the inbound decodes it, and the dispatcher pins it.
func TestShadowsocks2022MemoryUserKeyMatchesConfig(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		node := &model.NodeSpec{Protocol: "shadowsocks", Cipher: cipher}
		user := model.UserSpec{ID: 7, UUID: removalUUID1}
		settings := buildShadowsocks(M{}, node, []model.UserSpec{user})["settings"].(M)
		configured := settings["clients"].([]M)[0]["password"].(string)

		mu, err := toMemoryUser("shadowsocks", node, user)
		if err != nil {
			t.Fatal(err)
		}
		account, ok := mu.Account.(*ss2022.MemoryAccount)
		if !ok {
			t.Fatalf("%s: account type %T", cipher, mu.Account)
		}
		if account.Key != configured {
			t.Fatalf("%s: UserManager key %q, config key %q", cipher, account.Key, configured)
		}
		raw, err := base64.StdEncoding.DecodeString(account.Key)
		if err != nil || len(raw) != ss2022Methods[cipher].size {
			t.Fatalf("%s: key %q decodes to %d bytes (%v), want %d", cipher, account.Key, len(raw), err, ss2022Methods[cipher].size)
		}
	}
}

// Shadowsocks sessions carry the configured password (AEAD) or derived key
// (2022): a UUID reset must cut the old UUID's links and refuse new
// sub-streams of its session, as it does for VLESS.
func TestLimitDispatcherShadowsocksUUIDResetCutsOldCredential(t *testing.T) {
	for name, cipher := range map[string]string{"aead": "aes-128-gcm", "2022": "2022-blake3-aes-128-gcm"} {
		t.Run(name, func(t *testing.T) {
			node := &model.NodeSpec{NodeID: 7, Protocol: "shadowsocks", Cipher: cipher}
			ld, _ := newRemovalTestDispatcher()
			x := New(config.KernelConfig{Type: "xray"})
			x.limitDispatcher = ld
			x.nodeConfig = node

			before := model.UserSpec{ID: 1, UUID: removalUUID1}
			other := model.UserSpec{ID: 2, UUID: removalUUID2}
			x.updateDispatcherLimits([]model.UserSpec{before, other})
			oldLink, err := ld.Dispatch(nodeUserContext(t, node, before), removalDest)
			if err != nil {
				t.Fatal(err)
			}
			otherLink, err := ld.Dispatch(nodeUserContext(t, node, other), removalDest)
			if err != nil {
				t.Fatal(err)
			}

			after := model.UserSpec{ID: 1, UUID: removalUUID3}
			x.updateDispatcherLimits([]model.UserSpec{after, other})
			if !linkInterrupted(oldLink) {
				t.Fatal("link of the old UUID survived the reset")
			}
			if linkInterrupted(otherLink) {
				t.Fatal("unrelated user's link was interrupted")
			}
			if _, err := ld.Dispatch(nodeUserContext(t, node, before), removalDest); err == nil {
				t.Fatal("new sub-stream of a session authenticated with the old UUID was accepted")
			}
			newLink, err := ld.Dispatch(nodeUserContext(t, node, after), removalDest)
			if err != nil {
				t.Fatalf("new UUID refused: %v", err)
			}
			// Re-installing the same set must not cut the new UUID's link.
			x.updateDispatcherLimits([]model.UserSpec{after, other})
			if linkInterrupted(newLink) {
				t.Fatal("link of the current UUID was interrupted")
			}
			// CloseUUID matches by the protocol's credential too.
			if n := ld.CloseUUID(after.UUID); n != 1 || !linkInterrupted(newLink) || linkInterrupted(otherLink) {
				t.Fatalf("CloseUUID(new UUID) = %d, want exactly the new UUID's link", n)
			}
		})
	}
}

// Trojan compares the exact password string, so a case-only change of the
// UUID string is a different password (UserDiff swaps the account): the old
// password's session must go. For VLESS it is the same ID and must stay.
func TestLimitDispatcherCaseOnlyUUIDChange(t *testing.T) {
	const lower = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	upper := strings.ToUpper(lower)

	t.Run("trojan", func(t *testing.T) {
		node := &model.NodeSpec{Protocol: "trojan"}
		ld, _ := newRemovalTestDispatcher()
		installNodeUsers(ld, node, model.UserSpec{ID: 1, UUID: lower})
		oldLink, err := ld.Dispatch(nodeUserContext(t, node, model.UserSpec{ID: 1, UUID: lower}), removalDest)
		if err != nil {
			t.Fatal(err)
		}

		installNodeUsers(ld, node, model.UserSpec{ID: 1, UUID: upper})
		if !linkInterrupted(oldLink) {
			t.Fatal("live link of the replaced trojan password survived a case-only reset")
		}
		if _, err := ld.Dispatch(nodeUserContext(t, node, model.UserSpec{ID: 1, UUID: lower}), removalDest); err == nil {
			t.Fatal("new sub-stream of a session authenticated with the replaced password was accepted")
		}
		newLink, err := ld.Dispatch(nodeUserContext(t, node, model.UserSpec{ID: 1, UUID: upper}), removalDest)
		if err != nil {
			t.Fatalf("new trojan password refused: %v", err)
		}
		// CloseUUID of the old password must not hit the new one's links.
		ld.CloseUUID(lower)
		if linkInterrupted(newLink) {
			t.Fatal("CloseUUID of the old password interrupted a link of the new password")
		}
	})

	t.Run("vless", func(t *testing.T) {
		node := &model.NodeSpec{Protocol: "vless"}
		ld, _ := newRemovalTestDispatcher()
		installNodeUsers(ld, node, model.UserSpec{ID: 1, UUID: lower})
		link, err := ld.Dispatch(vlessUserContext(t, 1, lower), removalDest)
		if err != nil {
			t.Fatal(err)
		}
		installNodeUsers(ld, node, model.UserSpec{ID: 1, UUID: upper})
		if linkInterrupted(link) {
			t.Fatal("vless link was cut by a case-only change of the same UUID")
		}
		if _, err := ld.Dispatch(vlessUserContext(t, 1, lower), removalDest); err != nil {
			t.Fatalf("vless session refused after a case-only change: %v", err)
		}
	})
}

// Links of account types without a credential (http, socks) cannot be told
// apart by it: when the user's pinned credential changes they belong to the
// old account and are cut, and only then.
func TestLimitDispatcherRekeyCutsCredentiallessLinks(t *testing.T) {
	node := &model.NodeSpec{Protocol: "http"}
	httpContext := func(u model.UserSpec) context.Context {
		return accountUserContext(u.ID, &http.Account{Username: u.UUID, Password: u.UUID})
	}
	ld, _ := newRemovalTestDispatcher()
	user := model.UserSpec{ID: 1, UUID: removalUUID1}
	other := model.UserSpec{ID: 2, UUID: removalUUID2}
	installNodeUsers(ld, node, user, other)
	oldLink, err := ld.Dispatch(httpContext(user), removalDest)
	if err != nil {
		t.Fatal(err)
	}
	otherLink, err := ld.Dispatch(httpContext(other), removalDest)
	if err != nil {
		t.Fatal(err)
	}

	// Same set again (limits refresh): nothing changes.
	installNodeUsers(ld, node, user, other)
	if linkInterrupted(oldLink) || linkInterrupted(otherLink) {
		t.Fatal("re-installing an unchanged user set cut a credential-less link")
	}

	rekeyed := model.UserSpec{ID: user.ID, UUID: removalUUID3}
	installNodeUsers(ld, node, rekeyed, other)
	if !linkInterrupted(oldLink) {
		t.Fatal("credential-less link of the re-keyed user survived the reset")
	}
	if linkInterrupted(otherLink) {
		t.Fatal("unrelated user's credential-less link was cut")
	}
	newLink, err := ld.Dispatch(httpContext(rekeyed), removalDest)
	if err != nil {
		t.Fatal(err)
	}
	installNodeUsers(ld, node, rekeyed, other)
	if linkInterrupted(newLink) {
		t.Fatal("re-installing the new set cut the new account's link")
	}
}
