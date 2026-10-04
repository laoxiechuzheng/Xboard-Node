package xray_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	panelapi "github.com/cedar2025/xboard-node/internal/panel"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"gopkg.in/yaml.v3"
)

// Exercise the shipped main's YAML inheritance, startup and signal shutdown.
func TestSharedRealityBinarySmoke(t *testing.T) {
	binary := os.Getenv("XBOARD_SHARED_REALITY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XBOARD_SHARED_REALITY_TEST_BINARY to a Linux xboard-node executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("real binary signal lifecycle requires Linux")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatalf("resolve binary path: %v", err)
	}
	dir := t.TempDir()
	requested := 0
	if raw := os.Getenv("XBOARD_SHARED_REALITY_TEST_PORT"); raw != "" {
		requested, err = strconv.Atoi(raw)
		if err != nil || requested < 1 || requested > 65535 {
			t.Fatal("XBOARD_SHARED_REALITY_TEST_PORT must be an integer in 1..65535")
		}
	}
	var reservations []net.Listener
	var ports []int
	for i := 0; i < 3; i++ {
		port := 0
		if i == 0 {
			port = requested
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("reserve smoke listener %d: %v", i, err)
		}
		t.Cleanup(func() { listener.Close() })
		reservations = append(reservations, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	// Neither instance sets type or shared_reality: both must inherit them.
	root := config.RootConfig{Config: config.Config{
		Kernel: config.KernelConfig{
			Type: "xray", LogLevel: "none",
			SharedReality: &config.SharedRealityConfig{
				Enabled: true, ListenIP: "127.0.0.1", ListenPort: ports[0],
			},
		},
		Node: config.NodeConfig{TrackInterval: 1, PushInterval: 60, PullInterval: 60},
		Log:  config.LogConfig{Level: "error", Output: "stdout"},
	}}
	var panels []*srBinaryPanel
	var clients []srClientOptions
	var redactions []string
	for i := 0; i < 2; i++ {
		serverName := fmt.Sprintf("binary-cover-%d.test", i+1)
		cover := srCoverTarget(t, serverName)
		region := srNewRegion(t, i)
		regionalProxy := srBinaryRegionalProxy(t, region.address)
		privateKey, publicKey := srRealityKeys(t)
		options := srClientOptions{
			address: "127.0.0.1", uuid: srUUID(t), publicKey: publicKey,
			serverName: serverName, shortID: fmt.Sprintf("%016x", i+1),
		}
		if i == 1 {
			options.flow = srVision
		}
		clients = append(clients, options)
		mock := srNewBinaryPanel(t, panelapi.NodeConfig{
			NodeID: i + 1, Protocol: "vless", ListenIP: "127.0.0.1",
			ServerPort: ports[i+1], Network: "tcp", TLS: 2, Flow: options.flow,
			BaseConfig: panelapi.BaseConfig{PushInterval: 60, PullInterval: 60},
			TLSSettings: map[string]any{
				"private_key": privateKey, "dest": cover,
				"server_name": serverName, "short_id": options.shortID,
			},
			CustomOutbounds: []panelapi.OutboundConfig{{
				Tag: "region-egress", Protocol: "socks",
				Settings: map[string]any{"servers": []map[string]any{{"address": "127.0.0.1", "port": regionalProxy}}},
			}},
			CustomRoutes: []map[string]any{{
				"type": "field", "network": "tcp", "outboundTag": "region-egress",
			}},
		}, panelapi.User{ID: 1, UUID: options.uuid})
		for _, value := range []string{privateKey, publicKey, options.uuid, mock.token} {
			redactions = append(redactions, value, "<synthetic-secret>")
		}
		panels = append(panels, mock)
		root.Instances = append(root.Instances, config.Config{
			Panel: config.PanelConfig{
				URL: mock.server.URL, Token: mock.token, NodeID: i + 1, NodeType: "vless",
			},
		})
	}
	encoded, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal("could not encode synthetic smoke configuration")
	}
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatalf("write private temporary configuration: %v", err)
	}
	for _, listener := range reservations {
		if err := listener.Close(); err != nil {
			t.Fatalf("release smoke reservation: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary, "-c", configPath)
	cmd.Dir = dir
	// Never inherit API/AUDIT/certificate overrides from the test host.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir}
	var childOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childOutput, &childOutput
	childDiagnostic := func() string {
		output := strings.NewReplacer(redactions...).Replace(childOutput.String())
		if len(output) > 16*1024 {
			output = output[:16*1024]
		}
		return output
	}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start smoke binary: %v", err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			return
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("smoke subprocess was not reaped after forced cleanup")
		}
	})
	readyDeadline := time.Now().Add(15 * time.Second)
	for i, port := range ports {
		for {
			select {
			case <-done:
				t.Fatalf("smoke binary exited during startup: %v; sanitized child output: %s", waitErr, childDiagnostic())
			default:
			}
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(readyDeadline) {
				t.Fatalf("smoke listener %d did not become ready (child output suppressed)", i)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	f := &srFixture{}
	for i, client := range clients {
		for _, entry := range []struct {
			name string
			port int
		}{{"alias", ports[0]}, {"direct", ports[i+1]}} {
			options := client
			options.port = entry.port
			request := f.request()
			raw, err := f.exchange(t, options, request)
			if err != nil {
				t.Fatalf("node %d %s real HTTP exchange: %v", i+1, entry.name, err)
			}
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatalf("node %d %s parse HTTP response: %v", i+1, entry.name, err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			marker := fmt.Sprintf("region-%d", i+1)
			want := []byte(fmt.Sprintf("region=%s\ntoken=%s\nrequest=%s\n", marker, request.token, request.body))
			if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Region") != marker || !bytes.Equal(body, want) {
				t.Fatalf("node %d %s HTTP region/body mismatch", i+1, entry.name)
			}
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to smoke binary: %v", err)
	}
	select {
	case <-done:
		if waitErr != nil || cmd.ProcessState.ExitCode() != 0 {
			t.Fatalf("smoke binary did not exit zero after SIGTERM: %v; sanitized child output: %s", waitErr, childDiagnostic())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("smoke binary did not exit within the SIGTERM deadline")
	}
	for _, port := range ports {
		srAssertPortReleased(t, "127.0.0.1", port)
	}
	for i, mock := range panels {
		if mock.rejected.Load() != 0 || mock.finalReports.Load() == 0 {
			t.Fatalf("mock panel %d rejected a request or missed the final stopped-kernel report", i+1)
		}
		for route := 0; route < len(mock.calls); route++ {
			if mock.calls[route].Load() == 0 {
				t.Fatalf("mock panel %d bootstrap/report route %d was not exercised", i+1, route)
			}
		}
	}
}

func srBinaryRegionalProxy(t *testing.T, region string) int {
	t.Helper()
	port := srFreePort(t, 0)
	encoded, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "none", "error": "none", "access": "none"},
		"inbounds": []map[string]any{{
			"listen": "127.0.0.1", "port": port, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []map[string]any{{
			"protocol": "freedom", "settings": map[string]any{"redirect": region},
		}},
	})
	if err != nil {
		t.Fatalf("marshal regional proxy: %v", err)
	}
	pb, err := serial.LoadJSONConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("parse regional proxy: %v", err)
	}
	core, err := xraycore.New(pb)
	if err != nil {
		t.Fatalf("create regional proxy: %v", err)
	}
	t.Cleanup(func() { core.Close() })
	if err := core.Start(); err != nil {
		t.Fatalf("start regional proxy: %v", err)
	}
	return port
}

type srBinaryPanel struct {
	server       *httptest.Server
	token        string
	calls        [4]atomic.Int64
	finalReports atomic.Int64
	rejected     atomic.Int64
}

func srNewBinaryPanel(t *testing.T, node panelapi.NodeConfig, user panelapi.User) *srBinaryPanel {
	t.Helper()
	p := &srBinaryPanel{token: "binary-smoke-" + srUUID(t)}
	reject := func(w http.ResponseWriter, status int) {
		p.rejected.Add(1)
		http.Error(w, "invalid synthetic panel request", status)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		route, method := -1, http.MethodPost
		switch request.URL.Path {
		case "/api/v2/server/handshake":
			route = 0
		case "/api/v1/server/UniProxy/config":
			route, method = 1, http.MethodGet
		case "/api/v1/server/UniProxy/user":
			route, method = 2, http.MethodGet
		case "/api/v2/server/report":
			route = 3
		}
		if route < 0 || request.Method != method || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			reject(w, http.StatusBadRequest)
			return
		}
		var envelope struct {
			Token     string                     `json:"token"`
			NodeID    int                        `json:"node_id"`
			NodeType  string                     `json:"node_type"`
			MachineID json.RawMessage            `json:"machine_id"`
			Status    map[string]json.RawMessage `json:"status"`
			Metrics   struct {
				KernelRunning *bool `json:"kernel_status"`
			} `json:"metrics"`
		}
		if method == http.MethodGet {
			query := request.URL.Query()
			envelope.Token, envelope.NodeType = query.Get("token"), query.Get("node_type")
			envelope.NodeID, _ = strconv.Atoi(query.Get("node_id"))
			if len(query) != 3 {
				reject(w, http.StatusBadRequest)
				return
			}
		} else {
			decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, srMaxResponseBytes))
			if request.URL.RawQuery != "" || decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
				reject(w, http.StatusBadRequest)
				return
			}
		}
		// Only this fixture's random token and node identity can receive success.
		if envelope.Token != p.token || envelope.NodeID != node.NodeID || envelope.NodeType != "vless" || len(envelope.MachineID) != 0 {
			reject(w, http.StatusUnauthorized)
			return
		}
		var response any
		switch route {
		case 0:
			response = panelapi.HandshakeResponse{Settings: panelapi.Settings{PushInterval: 60, PullInterval: 60}}
		case 1:
			response = node
		case 2:
			response = panelapi.UsersResponse{Users: []panelapi.User{user}}
		case 3:
			if len(envelope.Status) != 4 || envelope.Metrics.KernelRunning == nil {
				reject(w, http.StatusBadRequest)
				return
			}
			for _, field := range []string{"cpu", "mem", "swap", "disk"} {
				if _, ok := envelope.Status[field]; !ok {
					reject(w, http.StatusBadRequest)
					return
				}
			}
			if !*envelope.Metrics.KernelRunning {
				p.finalReports.Add(1)
			}
			response = map[string]bool{"data": true}
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(response) == nil {
			p.calls[route].Add(1)
		}
	})
	p.server = httptest.NewUnstartedServer(handler)
	p.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.server.Config.ReadHeaderTimeout = 2 * time.Second
	p.server.Config.ReadTimeout, p.server.Config.WriteTimeout = 5*time.Second, 5*time.Second
	p.server.Start()
	t.Cleanup(p.server.Close)
	return p
}
