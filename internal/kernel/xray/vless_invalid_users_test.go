package xray

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestBuildVLESSSkipsInvalidUUIDWithoutRejectingValidUsers(t *testing.T) {
	users := []model.UserSpec{
		{ID: 1, UUID: "279d4f89-3a2c-488d-a67c-2d39a72acdde"},
		{ID: 2, UUID: "j79d4f89-3a2c-488d-a67c-2d39a72acdde"},
		{ID: 3, UUID: "named-valid-client"},
		{ID: 4, UUID: ""},
		{ID: 5, UUID: "4d5965c8a60c452aa943af83ec0bb0db"},
		{ID: 6, UUID: strings.Repeat("j", 31)},
	}
	original := append([]model.UserSpec(nil), users...)
	node := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 18043}
	data, err := marshalConfig(testKernelCfg, node, users, kernel.TLSCert{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("invalid upstream user must not prevent other VLESS users from starting: %v", err)
	}
	inbound := buildVLESS(M{}, node, users, kernel.TLSCert{})
	clients := inbound["settings"].(M)["clients"].([]M)
	want := []M{
		{"id": "279d4f89-3a2c-488d-a67c-2d39a72acdde", "email": "user@1"},
		{"id": "named-valid-client", "email": "user@3"},
		{"id": "4d5965c8a60c452aa943af83ec0bb0db", "email": "user@5"},
	}
	if !reflect.DeepEqual(clients, want) {
		t.Fatalf("valid user identities or billing emails changed: got %+v, want %+v", clients, want)
	}
	if !reflect.DeepEqual(users, original) {
		t.Fatal("builder mutated the control-plane user snapshot")
	}
}
