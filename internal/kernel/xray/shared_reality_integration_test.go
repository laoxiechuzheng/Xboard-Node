package xray_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/audit"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	xray "github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/tracker"
	xraynet "github.com/xtls/xray-core/common/net"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const (
	srSites              = 3
	srRegions            = 8
	srVision             = "xtls-rprx-vision"
	srClientIP           = "127.0.0.2"
	srExchangeTimeout    = 15 * time.Second
	srObservationTimeout = 5 * time.Second
	srMaxResponseBytes   = 1 << 20
)

// One serial fixture preserves 24 original TCP ports and adds one alias
// entry. All traffic and the TLS 1.3/h2 cover targets are loopback.
func TestXraySharedRealityIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listener ownership requires Linux /proc; run in the isolated Go 1.26 container")
	}
	// Include the three external panel stand-ins in the listener baseline.
	reportSites := srNewReportSites(t)
	f := srNewFixture(t)
	reporting := srNewReportChain(t, f, reportSites)
	if !t.Run("24_shortids_route_and_bill_exact_application_bytes", func(t *testing.T) {
		for i, node := range f.nodes {
			if !t.Run(node.name, func(t *testing.T) {
				f.success(t, i, node.primary, node.region)
				f.assertBilling(t)
				options := f.directOptions(i, node.primary)
				f.successWithOptions(t, i, node.primary, node.region, options)
				f.assertBilling(t)
			}) {
				return
			}
		}
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("foreign_site_uuid_cannot_use_another_sites_shortid", func(t *testing.T) {
		for site := 0; site < srSites; site++ {
			for region := 0; region < srRegions; region++ {
				index := site*srRegions + region
				options := f.options(index, f.nodes[index].primary)
				options.uuid = f.nodes[((site+1)%srSites)*srRegions+region].primary.UUID
				f.assertDenied(t, options)
			}
		}
	}) {
		return
	}

	if !t.Run("same_site_uuid_must_be_in_the_selected_nodes_validator", func(t *testing.T) {
		selected, authorized := 0, 1
		user := model.UserSpec{ID: 2, UUID: srUUID(t)}
		f.addUser(t, authorized, user)
		f.assertDenied(t, f.options(selected, user))
		f.success(t, authorized, user, f.nodes[authorized].region)
		f.assertBilling(t)
		f.removeUser(t, authorized, user)
		f.assertDenied(t, f.options(authorized, user))
	}) {
		return
	}

	if !t.Run("unknown_shortid_empty_shortid_wrong_key_and_wrong_sni_are_unbilled", func(t *testing.T) {
		options := f.options(2, f.nodes[2].primary)
		cases := []struct {
			name   string
			change func(*srClientOptions)
		}{
			{"unknown_shortid", func(o *srClientOptions) { o.shortID = "ffffffffffffffff" }},
			{"empty_shortid", func(o *srClientOptions) { o.shortID = "" }},
			{"wrong_public_key", func(o *srClientOptions) { _, o.publicKey = srRealityKeys(t) }},
			{"wrong_server_name", func(o *srClientOptions) { o.serverName = "unregistered.cover.test" }},
		}
		for _, tc := range cases {
			if !t.Run(tc.name, func(t *testing.T) {
				changed := options
				tc.change(&changed)
				f.assertDenied(t, changed)
			}) {
				return
			}
		}
	}) {
		return
	}

	if !t.Run("duplicate_shortid_start_is_rejected_without_leaking_or_stealing_listeners", func(t *testing.T) {
		original := f.nodes[0]
		duplicateSpec := srCloneNode(t, original.spec)
		duplicateSpec.NodeID = 9001
		duplicateSpec.ServerPort = srFreePort(t, f.port)
		intruder := model.UserSpec{ID: 1, UUID: srUUID(t)}
		duplicate := xray.New(f.config)
		t.Cleanup(duplicate.Stop)
		if err := duplicate.Start(duplicateSpec, []model.UserSpec{intruder}, kernel.TLSCert{}); err == nil {
			duplicate.Stop()
			t.Fatal("Start accepted a duplicate ShortID belonging to an existing node")
		}
		duplicate.Stop()
		f.assertSharedListener(t)
		srAssertPortReleased(t, "127.0.0.1", duplicateSpec.ServerPort)
		f.assertDenied(t, f.options(0, intruder))
		f.success(t, 0, original.primary, original.region)
		f.successWithOptions(t, 0, original.primary, original.region, f.directOptions(0, original.primary))
		f.assertBilling(t)
	}) {
		return
	}

	if !t.Run("duplicate_shortid_reload_failure_keeps_original_config_connections_and_bytes", func(t *testing.T) {
		index := 1
		node := f.nodes[index]
		flight := f.beginFlight(t, index, node.primary)
		f.assertBilling(t)
		invalid := srCloneNode(t, node.spec)
		invalid.TLSSettings["short_id"] = f.nodes[0].sid
		if err := node.kernel.Reload(invalid, node.userList(), kernel.TLSCert{}); err == nil {
			t.Fatal("Reload accepted a ShortID already registered by another node")
		}
		if !node.kernel.IsRunning() {
			t.Fatal("failed Reload stopped the original logical node")
		}
		f.assertBilling(t)
		f.success(t, index, node.primary, node.region)
		f.successWithOptions(t, index, node.primary, node.region, f.directOptions(index, node.primary))
		f.success(t, 0, f.nodes[0].primary, 0)
		f.assertBilling(t)
		flight.finish(t)
		f.assertBilling(t)
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("dynamic_node_add_and_stop_preserve_existing_original_ports_and_alias", func(t *testing.T) {
		privateKey, publicKey := srRealityKeys(t)
		region := 5
		user := model.UserSpec{ID: 1, UUID: f.nodes[0].primary.UUID}
		spec := srCloneNode(t, f.nodes[0].spec)
		spec.NodeID = 9002
		spec.ServerPort = srFreePort(t, f.port)
		spec.Network, spec.Flow = "raw", srVision
		spec.TLSSettings = map[string]any{
			"private_key": privateKey, "dest": f.covers[2],
			"server_name": "cover.site3.test", "short_id": "1000000000000001",
		}
		spec.CustomOutbounds[0].Settings["redirect"] = f.regions[region].address
		node := &srNode{
			name: "dynamic_node", region: region, sid: "1000000000000001",
			publicKey: publicKey, serverName: "cover.site3.test", spec: spec, primary: user,
			users: map[int]model.UserSpec{1: user}, want: make(map[int][2]int64), last: make(map[int][2]int64),
			flux: new(srFluxSink),
		}
		cfg := f.config
		cfg.AuditSink = node.flux
		node.kernel = xray.New(cfg)
		t.Cleanup(node.kernel.Stop)
		index := len(f.nodes)
		f.nodes = append(f.nodes, node)
		if err := node.kernel.Start(spec, []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
			t.Fatalf("dynamically Start another original port plus existing alias: %v", err)
		}
		node.running = true
		f.assertSharedListener(t)
		f.success(t, index, user, region)
		f.successWithOptions(t, index, user, region, f.directOptions(index, user))
		f.success(t, 0, f.nodes[0].primary, 0)
		f.assertBilling(t)
		node.kernel.Stop()
		node.running = false
		if node.kernel.IsRunning() {
			t.Fatal("dynamic node still running after Stop")
		}
		f.assertSharedListener(t)
		srAssertPortReleased(t, "127.0.0.1", spec.ServerPort)
		f.assertDenied(t, f.options(index, user))
		f.assertDenied(t, f.directOptions(index, user))
		f.success(t, 0, f.nodes[0].primary, 0)
		f.assertBilling(t)
	}) {
		return
	}

	if !t.Run("cross_site_identical_uuid_and_userid_keep_independent_ledgers", func(t *testing.T) {
		first, second := 3, 2*srRegions+7
		node := f.nodes[second]
		original := node.primary
		keeper := model.UserSpec{ID: 2, UUID: srUUID(t)}
		f.addUser(t, second, keeper)
		f.removeUser(t, second, original)
		collision := model.UserSpec{ID: 1, UUID: f.nodes[first].primary.UUID}
		f.addUser(t, second, collision)
		f.assertDenied(t, f.options(second, original))
		for _, index := range []int{first, second, first, second} {
			f.success(t, index, collision, f.nodes[index].region)
			f.assertBilling(t)
			options := f.directOptions(index, collision)
			f.successWithOptions(t, index, collision, f.nodes[index].region, options)
			f.assertBilling(t)
		}
		f.removeUser(t, second, collision)
		f.addUser(t, second, original)
		f.removeUser(t, second, keeper)
		f.success(t, second, original, node.region)
		f.assertBilling(t)
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("hot_remove_and_readd_are_node_local_and_preserve_billing", func(t *testing.T) {
		index := srRegions + 2
		node := f.nodes[index]
		keeper := model.UserSpec{ID: 2, UUID: srUUID(t)}
		f.addUser(t, index, keeper)
		f.success(t, index, keeper, node.region)
		f.assertBilling(t)
		for round := 0; round < 2; round++ {
			f.removeUser(t, index, node.primary)
			if !node.kernel.IsRunning() {
				t.Fatal("removing one user stopped a node that still has another user")
			}
			f.assertDenied(t, f.options(index, node.primary))
			direct := f.directOptions(index, node.primary)
			f.assertDenied(t, direct)
			f.success(t, index+1, f.nodes[index+1].primary, f.nodes[index+1].region)
			f.success(t, index, keeper, node.region)
			f.assertBilling(t)
			f.addUser(t, index, node.primary)
			f.success(t, index, node.primary, node.region)
			direct = f.directOptions(index, node.primary)
			f.successWithOptions(t, index, node.primary, node.region, direct)
			f.assertBilling(t)
		}
		f.removeUser(t, index, keeper)
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("reload_preserves_polled_unpolled_and_old_vision_connection_tail_bytes", func(t *testing.T) {
		index := 7
		node := f.nodes[index]
		originalPort := node.spec.ServerPort
		f.assertBilling(t)
		flight := f.beginFlight(t, index, node.primary)
		f.assertBilling(t)
		// No GetUserTraffic call may occur between this completed request
		// and Reload: both upload and download are still native deltas.
		f.successUnpolled(t, index, node.primary, node.region)
		reloaded := srCloneNode(t, node.spec)
		// tcp/raw normalize to the same wire transport, but this NodeSpec
		// change forces a real config Reload without changing routes/users.
		reloaded.Network = "tcp"
		if err := node.kernel.Reload(reloaded, node.userList(), kernel.TLSCert{}); err != nil {
			t.Fatalf("Reload existing original port plus alias: %v", err)
		}
		// Only the old flight is connected: a new client's IP must not mask
		// missing connection state from the retired core generation.
		f.assertSourceIP(t, index, flight.user.ID)
		node.spec = reloaded
		if node.spec.ServerPort != originalPort {
			t.Fatal("Reload changed the original node port")
		}
		f.assertBilling(t)
		f.success(t, index, node.primary, node.region)
		direct := f.directOptions(index, node.primary)
		f.successWithOptions(t, index, node.primary, node.region, direct)
		f.success(t, srRegions+7, f.nodes[srRegions+7].primary, 7)
		f.assertBilling(t)
		f.assertSourceIP(t, index, node.primary.ID)
		flight.finish(t)
		f.assertBilling(t)
		// Old-core recycling must not erase its final counter increments.
		time.Sleep(100 * time.Millisecond)
		f.assertBilling(t)
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("stop_one_node_preserves_other_original_ports_aliases_and_open_connections", func(t *testing.T) {
		stopped, survivor := srRegions+7, 2*srRegions+6
		node := f.nodes[stopped]
		flight := f.beginFlight(t, survivor, f.nodes[survivor].primary)
		f.assertBilling(t)
		node.kernel.Stop()
		node.running = false
		if node.kernel.IsRunning() {
			t.Fatal("Stop left the selected logical node running")
		}
		f.assertSharedListener(t)
		f.assertDenied(t, f.options(stopped, node.primary))
		direct := f.directOptions(stopped, node.primary)
		f.assertDenied(t, direct)
		f.assertSourceIP(t, survivor, f.nodes[survivor].primary.ID)
		flight.finish(t)
		f.assertBilling(t)
		for i, other := range f.nodes {
			if i == stopped || !other.running {
				continue
			}
			f.success(t, i, other.primary, other.region)
			f.assertBilling(t)
			direct := f.directOptions(i, other.primary)
			f.successWithOptions(t, i, other.primary, other.region, direct)
			f.assertBilling(t)
		}
		f.assertSharedListener(t)
	}) {
		return
	}

	if !t.Run("v2_report_chain_exact_incremental_traffic_for_3_sites_8_regions", reporting.run) {
		return
	}

	t.Run("last_stop_releases_original_and_alias_listeners", func(t *testing.T) {
		f.stopNodes()
		f.awaitListeners(t, false)
		// Shutdown must retain every original node's ledger for final reports.
		reporting.poll(t)
		reporting.flush(t)
		reporting.assertQuiet(t)
		ports := []int{f.port}
		for _, node := range f.nodes {
			ports = append(ports, node.spec.ServerPort)
		}
		for _, port := range ports {
			listenIP := "127.0.0.1"
			if port == f.port {
				listenIP = f.listenIP
			}
			listener, err := net.Listen("tcp4", net.JoinHostPort(listenIP, strconv.Itoa(port)))
			if err != nil {
				t.Fatalf("port %d remains occupied after the last Stop: %v", port, err)
			}
			listener.Close()
		}
	})
}

// Only the remote panel boundary is a stand-in. Kernels, Xray clients,
// trackers, JSON serialization and HTTP reporting are the real implementations.
type srReceivedReport struct {
	nodeID         int
	traffic        map[int][2]int64
	trafficPresent bool
	kernelRunning  bool
}

type srReportSite struct {
	server  *httptest.Server
	token   string
	mu      sync.Mutex
	reports map[int][]srReceivedReport
	totals  map[int]map[int][2]int64
	issues  []string
}

func srNewReportSites(t *testing.T) []*srReportSite {
	t.Helper()
	sites := make([]*srReportSite, srSites)
	for site := range sites {
		receiver := &srReportSite{
			token:   fmt.Sprintf("local-report-site-%d-token", site+1),
			reports: make(map[int][]srReceivedReport),
			totals:  make(map[int]map[int][2]int64),
		}
		receiver.server = httptest.NewServer(http.HandlerFunc(receiver.serveHTTP))
		t.Cleanup(receiver.server.Close)
		sites[site] = receiver
	}
	return sites
}

func (s *srReportSite) reject(w http.ResponseWriter, status int, problem string) {
	s.mu.Lock()
	s.issues = append(s.issues, problem)
	s.mu.Unlock()
	http.Error(w, problem, status)
}

func (s *srReportSite) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/api/v2/server/report" || request.URL.RawQuery != "" {
		s.reject(w, http.StatusBadRequest, "expected authenticated JSON POST /api/v2/server/report")
		return
	}
	if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
		s.reject(w, http.StatusBadRequest, "report did not use the real panel JSON HTTP headers")
		return
	}
	var envelope struct {
		Token    string              `json:"token"`
		NodeID   int                 `json:"node_id"`
		NodeType string              `json:"node_type"`
		Traffic  json.RawMessage     `json:"traffic"`
		Alive    map[string][]string `json:"alive"`
		Online   map[string]int      `json:"online"`
		Status   json.RawMessage     `json:"status"`
		Metrics  struct {
			KernelRunning *bool `json:"kernel_status"`
		} `json:"metrics"`
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, srMaxResponseBytes+1))
	if err != nil || len(body) > srMaxResponseBytes {
		s.reject(w, http.StatusBadRequest, "report body could not be read within the fixture limit")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		s.reject(w, http.StatusBadRequest, fmt.Sprintf("invalid V2 report JSON: %v", err))
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		s.reject(w, http.StatusBadRequest, "report contains trailing JSON")
		return
	}
	if envelope.Token != s.token {
		s.reject(w, http.StatusUnauthorized, "report token belongs to another site")
		return
	}
	if envelope.NodeID < 1 || envelope.NodeID > srRegions || envelope.NodeType != "vless" {
		s.reject(w, http.StatusBadRequest, "report node_id/node_type is not a registered original node")
		return
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Status, &status); err != nil || len(status) != 4 || envelope.Metrics.KernelRunning == nil {
		s.reject(w, http.StatusBadRequest, "missing real Client.Report status or kernel_status")
		return
	}
	for _, field := range []string{"cpu", "mem", "swap", "disk"} {
		if _, exists := status[field]; !exists {
			s.reject(w, http.StatusBadRequest, "report status field missing: "+field)
			return
		}
	}
	traffic := make(map[int][2]int64)
	if envelope.Traffic != nil {
		var rawTraffic map[string][]int64
		if err := json.Unmarshal(envelope.Traffic, &rawTraffic); err != nil || len(rawTraffic) == 0 {
			s.reject(w, http.StatusBadRequest, "zero-delta reports must OMIT traffic; nonzero traffic must be an object")
			return
		}
		for key, delta := range rawTraffic {
			uid, err := strconv.Atoi(key)
			if err != nil || uid <= 0 || strconv.Itoa(uid) != key || len(delta) != 2 || delta[0] < 0 || delta[1] < 0 || (delta[0] == 0 && delta[1] == 0) {
				s.reject(w, http.StatusBadRequest, "traffic must use a canonical UID and exactly [upload, download] nonnegative increments")
				return
			}
			traffic[uid] = [2]int64{delta[0], delta[1]}
		}
	}
	for _, ips := range envelope.Alive {
		for _, ip := range ips {
			if ip != srClientIP {
				s.reject(w, http.StatusBadRequest, "panel alive report lost the real client source IP")
				return
			}
		}
	}
	s.mu.Lock()
	s.reports[envelope.NodeID] = append(s.reports[envelope.NodeID], srReceivedReport{
		nodeID: envelope.NodeID, traffic: traffic, trafficPresent: envelope.Traffic != nil,
		kernelRunning: *envelope.Metrics.KernelRunning,
	})
	if s.totals[envelope.NodeID] == nil {
		s.totals[envelope.NodeID] = make(map[int][2]int64)
	}
	for uid, delta := range traffic {
		current := s.totals[envelope.NodeID][uid]
		s.totals[envelope.NodeID][uid] = [2]int64{current[0] + delta[0], current[1] + delta[1]}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"data":true}`)
}

func (s *srReportSite) nodeReports(nodeID int) []srReceivedReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]srReceivedReport(nil), s.reports[nodeID]...)
}

func (s *srReportSite) snapshot() (map[int]map[int][2]int64, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	totals := make(map[int]map[int][2]int64, len(s.totals))
	for nodeID, users := range s.totals {
		totals[nodeID] = maps.Clone(users)
	}
	return totals, append([]string(nil), s.issues...)
}

type srNodeReporter struct {
	tracker  *tracker.Tracker
	client   *panel.Client
	sent     map[int][2]int64
	observed map[int][2]int64
}

type srReportChain struct {
	fixture   *srFixture
	sites     []*srReportSite
	reporters []*srNodeReporter
}

func srNewReportChain(t *testing.T, f *srFixture, sites []*srReportSite) *srReportChain {
	t.Helper()
	if len(f.nodes) != srSites*srRegions || len(sites) != srSites {
		t.Fatal("report chain requires exactly three original eight-region sites")
	}
	r := &srReportChain{fixture: f, sites: sites}
	for index, node := range f.nodes {
		site := sites[index/srRegions]
		r.reporters = append(r.reporters, &srNodeReporter{
			tracker: tracker.New(),
			client: panel.NewClient(config.PanelConfig{
				URL: site.server.URL, Token: site.token, NodeID: node.spec.NodeID, NodeType: "vless",
			}),
			sent: make(map[int][2]int64), observed: make(map[int][2]int64),
		})
	}
	return r
}

// Process only the public kernel's real cumulative results. No wanted bytes,
// active-user filters or synthetic counters may be fed into a Tracker.
func (r *srReportChain) poll(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(srObservationTimeout)
	stable := 0
	var pending string
	for {
		complete := true
		for index, reporter := range r.reporters {
			node := r.fixture.nodes[index]
			traffic, alive, count, err := node.kernel.GetUserTraffic(context.Background())
			if err != nil {
				t.Fatalf("%s report-chain GetUserTraffic: %v", node.name, err)
			}
			for uid, current := range traffic {
				previous, want := reporter.observed[uid], node.want[uid]
				if current[0] < previous[0] || current[1] < previous[1] || current[0] > want[0] || current[1] > want[1] {
					t.Fatalf("%s report-chain uid=%d cumulative=%v, previous=%v, EXACT HTTP want=%v", node.name, uid, current, previous, want)
				}
				reporter.observed[uid] = current
			}
			reporter.tracker.Process(traffic, alive, count)
			for uid, want := range node.want {
				// Removed users and stopped nodes must remain billable immediately,
				// even without readding a UUID or restarting its kernel.
				if traffic[uid] != want {
					complete = false
					pending = fmt.Sprintf("%s uid=%d running=%t cumulative=%v, want EXACT %v", node.name, uid, node.running, traffic[uid], want)
				}
			}
		}
		if complete {
			stable++
			if stable == 2 {
				return
			}
		} else {
			stable = 0
		}
		if time.Now().After(deadline) {
			t.Fatalf("real kernel -> Tracker ledger did not converge: %s", pending)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (r *srReportChain) flush(t *testing.T) {
	t.Helper()
	for index, reporter := range r.reporters {
		node := r.fixture.nodes[index]
		want := make(map[int][2]int64)
		for uid, cumulative := range node.want {
			previous := reporter.sent[uid]
			delta := [2]int64{cumulative[0] - previous[0], cumulative[1] - previous[1]}
			if delta[0] < 0 || delta[1] < 0 {
				t.Fatalf("%s reporting expectation reset for uid=%d", node.name, uid)
			}
			if delta[0] > 0 || delta[1] > 0 {
				want[uid] = delta
			}
		}
		traffic := reporter.tracker.FlushTraffic()
		if !maps.Equal(traffic, want) {
			t.Fatalf("%s real Tracker.FlushTraffic=%v, want EXACT HTTP increments %v (not cumulative totals)", node.name, traffic, want)
		}
		site, nodeID := r.sites[index/srRegions], index%srRegions+1
		before := len(site.nodeReports(nodeID))
		if err := reporter.client.Report(traffic, reporter.tracker.FlushAliveIPs(), reporter.tracker.CurrentOnline(),
			0, [2]uint64{}, [2]uint64{}, [2]uint64{}, map[string]interface{}{"kernel_status": node.kernel.IsRunning()}); err != nil {
			t.Fatalf("%s real panel.Client.Report: %v", node.name, err)
		}
		received := site.nodeReports(nodeID)
		if len(received) != before+1 {
			t.Fatalf("%s report reached a different site/node_id or was sent more than once: records %d -> %d", node.name, before, len(received))
		}
		wire := received[before]
		if wire.nodeID != nodeID || wire.trafficPresent != (len(want) > 0) || !maps.Equal(wire.traffic, want) || wire.kernelRunning != node.running {
			t.Fatalf("%s wrong actual V2 body: %+v, want delta=%v, node_id=%d, kernel_status=%t", node.name, wire, want, nodeID, node.running)
		}
		for uid, delta := range traffic {
			previous := reporter.sent[uid]
			reporter.sent[uid] = [2]int64{previous[0] + delta[0], previous[1] + delta[1]}
		}
		if reporter.tracker.HasTraffic() {
			t.Fatalf("%s traffic remained pending after a successful report", node.name)
		}
		if extra := reporter.tracker.FlushTraffic(); len(extra) != 0 {
			t.Fatalf("%s repeated FlushTraffic returned already reported bytes: %v", node.name, extra)
		}
	}
	r.assertTotals(t)
}

func (r *srReportChain) assertTotals(t *testing.T) {
	t.Helper()
	for siteIndex, site := range r.sites {
		received, issues := site.snapshot()
		if len(issues) != 0 {
			t.Fatalf("site %d rejected or misattributed report requests: %v", siteIndex+1, issues)
		}
		wantAggregate, actualAggregate := make(map[int][2]int64), make(map[int][2]int64)
		for region := 0; region < srRegions; region++ {
			index := siteIndex*srRegions + region
			node := r.fixture.nodes[index]
			if !maps.Equal(received[region+1], node.want) {
				t.Fatalf("site %d node_id=%d server received total=%v, want EXACT raw HTTP total=%v", siteIndex+1, region+1, received[region+1], node.want)
			}
			for uid, total := range node.want {
				previous := wantAggregate[uid]
				wantAggregate[uid] = [2]int64{previous[0] + total[0], previous[1] + total[1]}
			}
		}
		for _, users := range received {
			for uid, total := range users {
				previous := actualAggregate[uid]
				actualAggregate[uid] = [2]int64{previous[0] + total[0], previous[1] + total[1]}
			}
		}
		if !maps.Equal(actualAggregate, wantAggregate) {
			t.Fatalf("site %d eight-region UID aggregation=%v, want EXACT independent site totals=%v", siteIndex+1, actualAggregate, wantAggregate)
		}
	}
}

func (r *srReportChain) assertQuiet(t *testing.T) {
	t.Helper()
	for repeat := 0; repeat < 2; repeat++ {
		for index, reporter := range r.reporters {
			if !maps.Equal(reporter.sent, r.fixture.nodes[index].want) {
				t.Fatalf("%s repeat poll started before its pending traffic was reported", r.fixture.nodes[index].name)
			}
		}
		r.poll(t)
		// Every Client.Report still sends a real status request, but traffic
		// must be absent and all three server-side totals must stay unchanged.
		r.flush(t)
	}
}

func (r *srReportChain) run(t *testing.T) {
	f := r.fixture
	if !t.Run("24_node_alias_and_direct_bytes_reach_only_their_site_and_node", func(t *testing.T) {
		for index, node := range f.nodes[:srSites*srRegions] {
			// The normal full suite reuses the first 24-node case's real bytes.
			// A -run filter selecting only this case still generates both paths.
			if node.want[node.primary.ID] == [2]int64{} {
				if !node.running {
					t.Fatalf("%s has no prior traffic and is already stopped", node.name)
				}
				f.success(t, index, node.primary, node.region)
				f.successWithOptions(t, index, node.primary, node.region, f.directOptions(index, node.primary))
			}
		}
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
	}) {
		return
	}
	if !t.Run("successive_polls_accumulate_increments_until_flush_not_full_totals", func(t *testing.T) {
		// Deliberately give the three sites different new byte totals while
		// reusing UID=1, node_id=4 and Vision, so identity bleed cannot cancel.
		for site := 0; site < srSites; site++ {
			index := site*srRegions + 3
			node := f.nodes[index]
			for visit := 0; visit <= site; visit++ {
				options := f.options(index, node.primary)
				if visit%2 != 0 {
					options = f.directOptions(index, node.primary)
				}
				f.successWithOptions(t, index, node.primary, node.region, options)
				r.poll(t)
			}
		}
		r.flush(t)
		r.assertQuiet(t)
	}) {
		return
	}
	if !t.Run("cross_site_identical_uuid_uid_and_nodeid_reports_stay_site_local", func(t *testing.T) {
		first, second := 3, 2*srRegions+3
		node := f.nodes[second]
		keeper := model.UserSpec{ID: 78, UUID: srUUID(t)}
		collision := model.UserSpec{ID: 1, UUID: f.nodes[first].primary.UUID}
		f.addUser(t, second, keeper)
		f.removeUser(t, second, node.primary)
		f.addUser(t, second, collision)
		r.assertQuiet(t)
		f.assertDenied(t, f.options(second, node.primary))
		for _, index := range []int{first, second} {
			selected := f.nodes[index]
			f.success(t, index, collision, selected.region)
			r.poll(t)
			f.successWithOptions(t, index, collision, selected.region, f.directOptions(index, collision))
			r.poll(t)
		}
		r.flush(t)
		r.assertQuiet(t)
		f.removeUser(t, second, collision)
		f.addUser(t, second, node.primary)
		f.removeUser(t, second, keeper)
		r.assertQuiet(t)
		f.success(t, second, node.primary, node.region)
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
	}) {
		return
	}
	if !t.Run("removed_user_unpolled_bytes_report_before_readd_without_rebilling_history", func(t *testing.T) {
		index := 4
		node := f.nodes[index]
		keeper := model.UserSpec{ID: 77, UUID: srUUID(t)}
		f.addUser(t, index, keeper)
		// No kernel poll or tracker Process between the HTTP exchange and removal.
		f.successUnpolled(t, index, node.primary, node.region)
		f.removeUser(t, index, node.primary)
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
		f.assertDenied(t, f.options(index, node.primary))
		f.assertDenied(t, f.directOptions(index, node.primary))
		r.assertQuiet(t)
		// The same site's UUID on another region remains authorized and billable.
		f.success(t, index+1, f.nodes[index+1].primary, f.nodes[index+1].region)
		r.poll(t)
		r.flush(t)
		f.addUser(t, index, node.primary)
		f.success(t, index, node.primary, node.region)
		r.poll(t)
		f.successWithOptions(t, index, node.primary, node.region, f.directOptions(index, node.primary))
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
		f.removeUser(t, index, keeper)
		r.assertQuiet(t)
	}) {
		return
	}
	t.Run("stopped_vision_node_reports_unpolled_direct_bytes_and_keeps_final_ledger", func(t *testing.T) {
		index := 2*srRegions + 3
		node := f.nodes[index]
		// Stop must harvest this last real direct-port exchange before closing
		// the native stats manager; the Tracker has not seen it yet.
		f.successUnpolledWithOptions(t, index, node.primary, node.region, f.directOptions(index, node.primary))
		node.kernel.Stop()
		node.running = false
		if node.kernel.IsRunning() {
			t.Fatal("report-case Stop left the selected Vision node running")
		}
		f.assertSharedListener(t)
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
		f.assertDenied(t, f.options(index, node.primary))
		f.assertDenied(t, f.directOptions(index, node.primary))
		r.assertQuiet(t)
		f.success(t, 0, f.nodes[0].primary, f.nodes[0].region)
		f.successWithOptions(t, srRegions, f.nodes[srRegions].primary, f.nodes[srRegions].region, f.directOptions(srRegions, f.nodes[srRegions].primary))
		r.poll(t)
		r.flush(t)
		r.assertQuiet(t)
		f.assertSharedListener(t)
	})
}

type srNode struct {
	name       string
	region     int
	sid        string
	publicKey  string
	serverName string
	spec       *model.NodeSpec
	kernel     *xray.Xray
	primary    model.UserSpec
	running    bool
	users      map[int]model.UserSpec
	want       map[int][2]int64
	last       map[int][2]int64
	flux       *srFluxSink
}

func (n *srNode) credit(uid, upload, download int) {
	total := n.want[uid]
	total[0] += int64(upload)
	total[1] += int64(download)
	n.want[uid] = total
}

func (n *srNode) userList() []model.UserSpec {
	users := make([]model.UserSpec, 0, len(n.users))
	for _, user := range n.users {
		users = append(users, user)
	}
	return users
}

type srFixture struct {
	nodes         []*srNode
	regions       []*srRegion
	config        config.KernelConfig
	covers        []string
	port          int
	listenIP      string
	aliasAddress  string
	sequence      int
	baseline      map[string]srSocket
	listenerInode string
}

func srNewFixture(t *testing.T) *srFixture {
	t.Helper()
	f := &srFixture{}
	serverNames := []string{"cover.test", "cover.site2.test", "cover.site3.test"}
	covers := make([]string, srSites)
	for site, serverName := range serverNames {
		covers[site] = srCoverTarget(t, serverName)
	}
	f.covers = covers
	for region := 0; region < srRegions; region++ {
		f.regions = append(f.regions, srNewRegion(t, region))
	}
	f.listenIP = os.Getenv("XBOARD_SHARED_REALITY_TEST_LISTEN_IP")
	if f.listenIP == "" {
		f.listenIP = "127.0.0.1"
	}
	parsedIP := net.ParseIP(f.listenIP)
	if parsedIP == nil || parsedIP.To4() == nil {
		t.Fatalf("XBOARD_SHARED_REALITY_TEST_LISTEN_IP=%q must be IPv4 for this 127.0.0.2-source fixture", f.listenIP)
	}
	f.listenIP = parsedIP.To4().String()
	f.aliasAddress = f.listenIP
	if f.aliasAddress == "0.0.0.0" {
		f.aliasAddress = "127.0.0.1"
	}
	requestedPort := 0
	if value := os.Getenv("XBOARD_SHARED_REALITY_TEST_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			t.Fatalf("XBOARD_SHARED_REALITY_TEST_PORT=%q must be an integer in 1..65535", value)
		}
		requestedPort = parsed
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(f.listenIP, strconv.Itoa(requestedPort)))
	if err != nil {
		t.Fatalf("reserve shared port: %v", err)
	}
	f.port = listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release shared port reservation: %v", err)
	}
	f.baseline, err = srOwnedListeners()
	if err != nil {
		t.Fatalf("read fixture listener baseline: %v", err)
	}
	if len(f.baseline) < srRegions+srSites {
		t.Fatalf("listener inventory missed fixture sockets: got %d, want at least %d", len(f.baseline), srRegions+srSites)
	}
	kcfg := config.KernelConfig{
		Type:       "xray",
		LogLevel:   "none",
		ConfigDir:  t.TempDir(),
		XrayPolicy: config.XrayPolicyConfig{Handshake: 4, ConnIdle: 60, UplinkOnly: 1, DownlinkOnly: 1},
		SharedReality: &config.SharedRealityConfig{
			Enabled:    true,
			ListenIP:   f.listenIP,
			ListenPort: f.port,
		},
	}
	f.config = kcfg
	t.Cleanup(f.stopNodes)
	for site := 0; site < srSites; site++ {
		user := model.UserSpec{ID: 1, UUID: srUUID(t)}
		for region := 0; region < srRegions; region++ {
			privateKey, publicKey := srRealityKeys(t)
			originalPort := srFreePort(t, f.port)
			network, flow := "tcp", ""
			if region%2 != 0 {
				network = "raw"
			}
			if region == 3 || region == 7 {
				flow = srVision
			}
			// NodeID is also reused across sites; only ShortID/Kernel owns
			// a validator, routes and the native user@1 accounting context.
			node := &srNode{
				name:       fmt.Sprintf("site_%d_region_%d_%s", site+1, region+1, network),
				region:     region,
				sid:        fmt.Sprintf("%016x", site*srRegions+region+1),
				publicKey:  publicKey,
				serverName: serverNames[site],
				primary:    user,
				users:      map[int]model.UserSpec{1: user},
				want:       make(map[int][2]int64),
				last:       make(map[int][2]int64),
				flux:       new(srFluxSink),
			}
			nodeConfig := kcfg
			nodeConfig.AuditSink = node.flux
			node.kernel = xray.New(nodeConfig)
			node.spec = &model.NodeSpec{
				NodeID:     region + 1,
				Protocol:   "vless",
				ListenIP:   "127.0.0.1",
				ServerPort: originalPort,
				Network:    network,
				TLS:        2,
				Flow:       flow,
				TLSSettings: map[string]any{
					"private_key": privateKey,
					"dest":        covers[site],
					"server_name": node.serverName,
					"short_id":    node.sid,
				},
				CustomOutbounds: []model.OutboundConfig{{
					Tag:      "local-region",
					Protocol: "freedom",
					Settings: map[string]any{"redirect": f.regions[region].address},
				}},
				// Explicitly outrank the generated private-IP block rule.
				CustomRoutes: []map[string]any{{
					"type":        "field",
					"network":     "tcp",
					"outboundTag": "local-region",
				}},
			}
			f.nodes = append(f.nodes, node)
			if err := node.kernel.Start(node.spec, []model.UserSpec{user}, kernel.TLSCert{}); err != nil {
				t.Fatalf("Start %s on original port %d plus alias %d: %v", node.name, originalPort, f.port, err)
			}
			node.running = true
			if !node.kernel.IsRunning() {
				t.Fatalf("%s did not enter the running state", node.name)
			}
			f.assertSharedListener(t)
		}
	}
	f.assertBilling(t)
	t.Logf("24 original ports + alias %d, 24 different REALITY keys, 3 local TLS 1.3/h2 covers/SNIs, 8 HTTP regions, 6 Vision nodes", f.port)
	return f
}

func (f *srFixture) stopNodes() {
	for _, node := range f.nodes {
		if node.running {
			node.kernel.Stop()
			node.running = false
		}
	}
}

func (f *srFixture) addUser(t *testing.T, index int, user model.UserSpec) {
	t.Helper()
	node := f.nodes[index]
	added, err := node.kernel.AddUsers([]model.UserSpec{user})
	if err != nil || added != 1 {
		t.Fatalf("%s AddUsers(uid=%d) = (%d, %v), want (1, nil)", node.name, user.ID, added, err)
	}
	node.users[user.ID] = user
}

func (f *srFixture) removeUser(t *testing.T, index int, user model.UserSpec) {
	t.Helper()
	node := f.nodes[index]
	removed, err := node.kernel.RemoveUsers([]model.UserSpec{user})
	if err != nil || removed != 1 {
		t.Fatalf("%s RemoveUsers(uid=%d) = (%d, %v), want (1, nil)", node.name, user.ID, removed, err)
	}
	delete(node.users, user.ID)
}

func srCloneNode(t *testing.T, node *model.NodeSpec) *model.NodeSpec {
	t.Helper()
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshal NodeSpec clone: %v", err)
	}
	cloned := new(model.NodeSpec)
	if err := json.Unmarshal(data, cloned); err != nil {
		t.Fatalf("unmarshal NodeSpec clone: %v", err)
	}
	return cloned
}

func srRealityKeys(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate REALITY X25519 key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func srUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatalf("generate UUID: %v", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func srCoverTarget(t *testing.T, serverName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cover certificate key: %v", err)
	}
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cover certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cover certificate: %v", err)
	}
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != serverName {
			http.Error(w, "wrong SNI", http.StatusBadRequest)
			return
		}
		w.Write([]byte("local cover target\n"))
	}))
	cover.EnableHTTP2 = true
	cover.Config.ErrorLog = log.New(io.Discard, "", 0)
	cover.TLS = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf,
		}},
	}
	cover.StartTLS()
	t.Cleanup(cover.Close)
	address := cover.Listener.Addr().String()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("cover TLS 1.3/h2 self-check: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		t.Fatalf("cover negotiated version=%x ALPN=%q, want TLS 1.3/h2", state.Version, state.NegotiatedProtocol)
	}
	return address
}

type srStream struct {
	first       []byte
	tail        []byte
	requestBody []byte
	gate        chan struct{}
	once        sync.Once
}

func (s *srStream) release() { s.once.Do(func() { close(s.gate) }) }

type srRegion struct {
	marker  string
	address string
	hits    atomic.Int64
	mu      sync.Mutex
	streams map[string]*srStream
}

func srHTTPHead(marker string, bodyLength int) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\nX-Region: %s\r\n\r\n", bodyLength, marker))
}

func (r *srRegion) newStream(token string, requestBody []byte) *srStream {
	firstBody := []byte(fmt.Sprintf("region=%s\ntoken=%s\nrequest=%s\n", r.marker, token, requestBody) + strings.Repeat("P", 4099))
	tail := []byte(strings.Repeat("T", 65539) + "\nend\n")
	stream := &srStream{
		first:       append(srHTTPHead(r.marker, len(firstBody)+len(tail)), firstBody...),
		tail:        tail,
		gate:        make(chan struct{}),
		requestBody: append([]byte(nil), requestBody...),
	}
	r.mu.Lock()
	r.streams[token] = stream
	r.mu.Unlock()
	return stream
}

func srNewRegion(t *testing.T, index int) *srRegion {
	t.Helper()
	region := &srRegion{marker: fmt.Sprintf("region-%d", index+1), streams: make(map[string]*srStream)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		region.hits.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, srMaxResponseBytes))
		if err != nil || r.Method != http.MethodPost {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, "/")
		region.mu.Lock()
		stream := region.streams[token]
		region.mu.Unlock()
		if stream != nil && !bytes.Equal(body, stream.requestBody) {
			http.Error(w, "request body corrupted", http.StatusBadRequest)
			return
		}
		conn, writer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Emit deterministic raw HTTP, avoiding Date/chunking and flushing
		// a known byte boundary for the old-connection Reload assertion.
		if stream != nil {
			if _, err := writer.Write(stream.first); err != nil {
				return
			}
			if err := writer.Flush(); err != nil {
				return
			}
			<-stream.gate
			writer.Write(stream.tail)
			writer.Flush()
			return
		}
		responseBody := []byte(fmt.Sprintf("region=%s\ntoken=%s\nrequest=", region.marker, token))
		responseBody = append(responseBody, body...)
		responseBody = append(responseBody, '\n')
		writer.Write(srHTTPHead(region.marker, len(responseBody)))
		writer.Write(responseBody)
		writer.Flush()
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	region.address = server.Listener.Addr().String()
	t.Cleanup(func() {
		region.mu.Lock()
		for _, stream := range region.streams {
			stream.release()
		}
		region.mu.Unlock()
		server.CloseClientConnections()
		server.Close()
	})
	return region
}

type srSocket struct {
	protocol string
	address  string
	port     int
}

// Match kernel socket inodes to this Go test process's FDs, rather than
// counting other processes in the container or guessing from port probes.
func srOwnedListeners() (map[string]srSocket, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	owned := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	result := make(map[string]srSocket)
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		data, err := os.ReadFile(filepath.Join("/proc/self/net", protocol))
		if err != nil {
			if os.IsNotExist(err) && strings.HasSuffix(protocol, "6") {
				continue
			}
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if protocol == "unix" {
				if len(fields) >= 7 && fields[3] == "00010000" && owned[fields[6]] {
					address := ""
					if len(fields) >= 8 {
						address = fields[7]
					}
					result[fields[6]] = srSocket{protocol: protocol, address: address}
				}
				continue
			}
			if len(fields) < 10 || !owned[fields[9]] {
				continue
			}
			if strings.HasPrefix(protocol, "tcp") && fields[3] != "0A" {
				continue
			}
			address, encodedPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				return nil, fmt.Errorf("malformed %s local endpoint %q", protocol, fields[1])
			}
			port, err := strconv.ParseUint(encodedPort, 16, 16)
			if err != nil {
				return nil, err
			}
			result[fields[9]] = srSocket{protocol: protocol, address: address, port: int(port)}
		}
	}
	return result, nil
}

func (f *srFixture) assertSharedListener(t *testing.T) {
	t.Helper()
	f.awaitListeners(t, true)
}

func (f *srFixture) awaitListeners(t *testing.T, shared bool) {
	t.Helper()
	deadline := time.Now().Add(srObservationTimeout)
	var problem string
	for {
		current, err := srOwnedListeners()
		if err != nil {
			t.Fatalf("read owned listener sockets: %v", err)
		}
		problem = ""
		for inode := range f.baseline {
			if _, exists := current[inode]; !exists {
				problem = fmt.Sprintf("fixture listener %s disappeared", inode)
			}
		}
		extra := make(map[string]srSocket)
		for inode, socket := range current {
			if _, exists := f.baseline[inode]; !exists {
				extra[inode] = socket
			}
		}
		if shared {
			ports := map[int]int{f.port: 0}
			for _, node := range f.nodes {
				if node.running {
					ports[node.spec.ServerPort] = 0
				}
			}
			if len(extra) != len(ports) {
				problem = fmt.Sprintf("got %d physical sockets %v, want %d original listeners plus ONE alias, without relay listeners", len(extra), extra, len(ports)-1)
			}
			for inode, socket := range extra {
				address := "0100007F"
				if socket.port == f.port {
					ip := net.ParseIP(f.listenIP).To4()
					address = strings.ToUpper(hex.EncodeToString([]byte{ip[3], ip[2], ip[1], ip[0]}))
				}
				if _, exists := ports[socket.port]; !exists || socket.protocol != "tcp" || socket.address != address {
					problem = fmt.Sprintf("unexpected listener %v", socket)
					continue
				}
				ports[socket.port]++
				if socket.port == f.port {
					if f.listenerInode != "" && f.listenerInode != inode {
						problem = fmt.Sprintf("alias listener changed inode %s -> %s", f.listenerInode, inode)
					} else {
						f.listenerInode = inode
					}
				}
			}
			for port, count := range ports {
				if count != 1 {
					problem = fmt.Sprintf("port %d has %d physical listeners, want 1", port, count)
				}
			}
		} else if len(extra) != 0 {
			problem = fmt.Sprintf("listeners leaked after the last Stop: %v", extra)
		}
		if problem == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(problem)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func srFreePort(t *testing.T, excluded int) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve original node port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatalf("release original node port reservation: %v", err)
		}
		if port != excluded {
			return port
		}
	}
	t.Fatal("could not reserve a port distinct from the alias")
	return 0
}

func srAssertPortReleased(t *testing.T, listenIP string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(listenIP, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listener %s:%d was not released: %v", listenIP, port, err)
	}
	listener.Close()
}

type srFluxSink struct {
	mu     sync.Mutex
	events []audit.Event
}

// This observes the real Xray audit emitter at its public Flux Sink boundary;
// it neither grants authentication nor supplies traffic counters or routes.
func (s *srFluxSink) Record(event audit.Event) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *srFluxSink) forTarget(target string) []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []audit.Event
	for _, event := range s.events {
		if event.Target == target {
			result = append(result, event)
		}
	}
	return result
}

type srRequest struct {
	token      string
	body       []byte
	raw        []byte
	targetPort int
}

func (f *srFixture) request() srRequest {
	f.sequence++
	token := fmt.Sprintf("request-%04d", f.sequence)
	body := []byte(token + ":" + strings.Repeat("q", 97+f.sequence%11*37))
	header := fmt.Sprintf("POST /%s HTTP/1.1\r\nHost: destination.test\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n", token, len(body))
	return srRequest{token: token, body: body, raw: append([]byte(header), body...), targetPort: 10000 + f.sequence}
}

type srClientOptions struct {
	port       int
	address    string
	uuid       string
	shortID    string
	publicKey  string
	serverName string
	flow       string
	targetPort int
}

func (f *srFixture) options(index int, user model.UserSpec) srClientOptions {
	node := f.nodes[index]
	return srClientOptions{
		port: f.port, address: f.aliasAddress, uuid: user.UUID, shortID: node.sid, publicKey: node.publicKey,
		serverName: node.serverName, flow: node.spec.Flow, targetPort: 1,
	}
}

func (f *srFixture) directOptions(index int, user model.UserSpec) srClientOptions {
	options := f.options(index, user)
	options.port = f.nodes[index].spec.ServerPort
	options.address = "127.0.0.1"
	return options
}

type srSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      net.Conn
	core      *xraycore.Instance
	stopWatch func() bool
	connOnce  sync.Once
	coreOnce  sync.Once
}

func (s *srSession) closeConn() { s.connOnce.Do(func() { s.conn.Close() }) }
func (s *srSession) closeCore() { s.coreOnce.Do(func() { s.core.Close() }) }

func (s *srSession) close() {
	s.stopWatch()
	s.cancel()
	s.closeConn()
	s.closeCore()
}

func (f *srFixture) openSession(t *testing.T, options srClientOptions, timeout time.Duration) *srSession {
	t.Helper()
	clientConfig := map[string]any{
		"log": map[string]any{"loglevel": "none", "error": "none", "access": "none"},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"handshake": 4, "connIdle": 30, "uplinkOnly": 1, "downlinkOnly": 1,
		}}},
		"outbounds": []map[string]any{{
			"tag": "real-client", "protocol": "vless", "sendThrough": srClientIP,
			"settings": map[string]any{
				"address": options.address, "port": options.port,
				"id": options.uuid, "encryption": "none", "flow": options.flow,
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"fingerprint": "chrome", "serverName": options.serverName,
					"publicKey": options.publicKey, "shortId": options.shortID,
				},
			},
		}},
	}
	encoded, err := json.Marshal(clientConfig)
	if err != nil {
		t.Fatalf("marshal real Xray client: %v", err)
	}
	protobufConfig, err := serial.LoadJSONConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("parse real Xray client config (not an authentication failure): %v", err)
	}
	instance, err := xraycore.New(protobufConfig)
	if err != nil {
		t.Fatalf("create real Xray client (not an authentication failure): %v", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatalf("start real Xray client (not an authentication failure): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	conn, err := xraycore.Dial(ctx, instance, xraynet.TCPDestination(xraynet.ParseAddress("127.0.0.1"), xraynet.Port(options.targetPort)))
	if err != nil {
		cancel()
		instance.Close()
		t.Fatalf("core.Dial local destination: %v", err)
	}
	session := &srSession{ctx: ctx, cancel: cancel, conn: conn, core: instance}
	// core.Dial's cnc.Conn SetDeadline methods are no-ops in this fork.
	// Cancellation MUST interrupt the pipes and close the client's core.
	session.stopWatch = context.AfterFunc(ctx, func() {
		session.closeConn()
		session.closeCore()
	})
	t.Cleanup(session.close)
	return session
}

func (f *srFixture) exchange(t *testing.T, options srClientOptions, request srRequest) ([]byte, error) {
	t.Helper()
	options.targetPort = request.targetPort
	session := f.openSession(t, options, srExchangeTimeout)
	defer session.close()
	if n, err := session.conn.Write(request.raw); err != nil || n != len(request.raw) {
		return nil, fmt.Errorf("write raw HTTP request: wrote %d/%d: %v", n, len(request.raw), err)
	}
	response, err := io.ReadAll(io.LimitReader(session.conn, srMaxResponseBytes))
	if session.ctx.Err() != nil {
		return response, session.ctx.Err()
	}
	if len(response) == srMaxResponseBytes {
		return response, fmt.Errorf("HTTP response exceeded fixture limit")
	}
	return response, err
}

func (f *srFixture) success(t *testing.T, index int, user model.UserSpec, region int) {
	t.Helper()
	f.successWithOptions(t, index, user, region, f.options(index, user))
}

func (f *srFixture) successWithOptions(t *testing.T, index int, user model.UserSpec, region int, options srClientOptions) {
	t.Helper()
	request := f.request()
	stream := f.regions[region].newStream(request.token, request.body)
	defer stream.release()
	options.targetPort = request.targetPort
	session := f.openSession(t, options, srExchangeTimeout)
	defer session.close()
	if n, err := session.conn.Write(request.raw); err != nil || n != len(request.raw) {
		t.Fatalf("%s write request = (%d, %v), want (%d, nil)", f.nodes[index].name, n, err, len(request.raw))
	}
	first := make([]byte, len(stream.first))
	if _, err := io.ReadFull(session.conn, first); err != nil {
		t.Fatalf("%s REALITY HTTP prefix: %v (context: %v)", f.nodes[index].name, err, session.ctx.Err())
	}
	if !bytes.Equal(first, stream.first) {
		t.Fatalf("%s routed to the wrong region or corrupted the raw HTTP prefix", f.nodes[index].name)
	}
	f.assertSourceIP(t, index, user.ID)
	stream.release()
	tail, err := io.ReadAll(io.LimitReader(session.conn, srMaxResponseBytes))
	if err != nil || session.ctx.Err() != nil {
		t.Fatalf("%s REALITY HTTP tail: %v (context: %v)", f.nodes[index].name, err, session.ctx.Err())
	}
	if !bytes.Equal(tail, stream.tail) {
		t.Fatalf("%s HTTP tail = %d bytes, want %d exact bytes", f.nodes[index].name, len(tail), len(stream.tail))
	}
	responseBytes := append(first, tail...)
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseBytes)), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("parse real HTTP response: %v", err)
	}
	body, bodyErr := io.ReadAll(response.Body)
	response.Body.Close()
	marker := fmt.Sprintf("region-%d", region+1)
	if bodyErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Region") != marker || !bytes.HasPrefix(body, []byte("region="+marker+"\ntoken="+request.token+"\n")) {
		t.Fatalf("%s HTTP region/token mismatch: status=%d, region=%q, read=%v", f.nodes[index].name, response.StatusCode, response.Header.Get("X-Region"), bodyErr)
	}
	session.close()
	f.nodes[index].credit(user.ID, len(request.raw), len(responseBytes))
	f.assertFlux(t, index, user, request.targetPort)
}

func (f *srFixture) assertSourceIP(t *testing.T, index, uid int) {
	t.Helper()
	node := f.nodes[index]
	deadline := time.Now().Add(srObservationTimeout)
	for {
		_, alive, count, err := node.kernel.GetUserTraffic(context.Background())
		if err != nil {
			t.Fatalf("%s GetUserTraffic while connected: %v", node.name, err)
		}
		for ip, active := range alive[uid] {
			if active && ip != srClientIP {
				t.Fatalf("%s alive IP = %s, want real client %s, not a loopback relay address", node.name, ip, srClientIP)
			}
		}
		if alive[uid][srClientIP] && count >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s active UID %d missing real source IP: alive=%v, connections=%d", node.name, uid, alive, count)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *srFixture) assertFlux(t *testing.T, index int, user model.UserSpec, targetPort int) {
	t.Helper()
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort))
	deadline := time.Now().Add(srObservationTimeout)
	for {
		var selected []audit.Event
		for i, node := range f.nodes {
			events := node.flux.forTarget(target)
			if i != index && len(events) != 0 {
				t.Fatalf("Flux target %s attributed to %s instead of %s", target, node.name, f.nodes[index].name)
			}
			if i == index {
				selected = events
			}
		}
		if len(selected) > 1 {
			t.Fatalf("Flux recorded %d accepted events for one target %s", len(selected), target)
		}
		if len(selected) == 1 {
			event := selected[0]
			if event.Event != "accepted" || event.NodeID != f.nodes[index].spec.NodeID || event.UserID != user.ID || event.UUID != user.UUID || event.SourceIP != srClientIP || event.Core != "xray" || event.Protocol != "vless" || event.Network != "tcp" {
				t.Fatalf("wrong native Flux identity/source metadata: %+v", event)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no native Flux accepted event for %s/%s", f.nodes[index].name, target)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The pinned fork's VLESS DispatchLink uses a decoded body reader and a
// pre-encoding body writer. Vision removes/adds padding outside these native
// user counters. HTTP headers ARE payload; VLESS/REALITY headers and Vision
// padding ARE NOT. No protocol-byte allowance or percentage tolerance is used.
func (f *srFixture) assertBilling(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(srObservationTimeout)
	stable := 0
	var pending string
	for {
		complete := true
		for _, node := range f.nodes {
			if !node.running {
				continue
			}
			traffic, _, _, err := node.kernel.GetUserTraffic(context.Background())
			if err != nil {
				t.Fatalf("%s GetUserTraffic: %v", node.name, err)
			}
			for uid, actual := range traffic {
				want, previous := node.want[uid], node.last[uid]
				if actual[0] < previous[0] || actual[1] < previous[1] {
					t.Fatalf("%s uid=%d cumulative bytes RESET: got %v, previous %v", node.name, uid, actual, previous)
				}
				if actual[0] > want[0] || actual[1] > want[1] {
					t.Fatalf("%s uid=%d got %v, want EXACT raw HTTP %v: cross-node billing, duplicate polling, or protocol overhead", node.name, uid, actual, want)
				}
				node.last[uid] = actual
			}
			for uid, want := range node.want {
				_, active := node.users[uid]
				_, returned := traffic[uid]
				// Existing API may omit removed users until they are readded;
				// their historical total must survive and is checked on readd.
				if !active && !returned {
					continue
				}
				if traffic[uid] != want {
					complete = false
					pending = fmt.Sprintf("%s uid=%d got %v, want EXACT %v", node.name, uid, traffic[uid], want)
				}
			}
		}
		if complete {
			stable++
			if stable == 2 {
				return
			}
		} else {
			stable = 0
		}
		if time.Now().After(deadline) {
			t.Fatalf("native billing failed to converge without byte tolerance: %s", pending)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f *srFixture) assertDenied(t *testing.T, options srClientOptions) {
	t.Helper()
	before := make([]int64, len(f.regions))
	for i, region := range f.regions {
		before[i] = region.hits.Load()
	}
	request := f.request()
	response, err := f.exchange(t, options, request)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("authentication attempt hung instead of being rejected: %v", err)
	}
	// core.Dial dispatches asynchronously. An empty EOF is a rejection;
	// client config errors and timeout cancellation must never count as one.
	if len(response) != 0 {
		t.Fatalf("unauthorized UUID/SID/key received %d application bytes", len(response))
	}
	f.assertBilling(t)
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(request.targetPort))
	for i, region := range f.regions {
		if got := region.hits.Load(); got != before[i] {
			t.Fatalf("unauthorized traffic reached %s: hits %d -> %d", region.marker, before[i], got)
		}
	}
	for _, node := range f.nodes {
		if events := node.flux.forTarget(target); len(events) != 0 {
			t.Fatalf("unauthorized traffic produced accepted Flux events: %+v", events)
		}
	}
}

type srFlight struct {
	fixture *srFixture
	index   int
	user    model.UserSpec
	request srRequest
	stream  *srStream
	session *srSession
}

func (f *srFixture) beginFlight(t *testing.T, index int, user model.UserSpec) *srFlight {
	t.Helper()
	request := f.request()
	stream := f.regions[f.nodes[index].region].newStream(request.token, request.body)
	t.Cleanup(stream.release)
	options := f.options(index, user)
	options.targetPort = request.targetPort
	session := f.openSession(t, options, 60*time.Second)
	if n, err := session.conn.Write(request.raw); err != nil || n != len(request.raw) {
		t.Fatalf("write long-running request = (%d, %v), want (%d, nil)", n, err, len(request.raw))
	}
	first := make([]byte, len(stream.first))
	if _, err := io.ReadFull(session.conn, first); err != nil {
		t.Fatalf("read long-running prefix: %v (context: %v)", err, session.ctx.Err())
	}
	if !bytes.Equal(first, stream.first) {
		t.Fatal("long-running prefix used another node's region or was corrupted")
	}
	f.nodes[index].credit(user.ID, len(request.raw), len(first))
	f.assertSourceIP(t, index, user.ID)
	return &srFlight{fixture: f, index: index, user: user, request: request, stream: stream, session: session}
}

func (flight *srFlight) finish(t *testing.T) {
	t.Helper()
	flight.stream.release()
	tail, err := io.ReadAll(io.LimitReader(flight.session.conn, srMaxResponseBytes))
	if err != nil || flight.session.ctx.Err() != nil {
		t.Fatalf("old connection was interrupted: read=%v, context=%v", err, flight.session.ctx.Err())
	}
	if !bytes.Equal(tail, flight.stream.tail) {
		t.Fatalf("old connection lost/changed tail bytes: got %d, want %d exact bytes", len(tail), len(flight.stream.tail))
	}
	flight.session.close()
	flight.fixture.nodes[flight.index].credit(flight.user.ID, 0, len(tail))
	flight.fixture.assertFlux(t, flight.index, flight.user, flight.request.targetPort)
}

func (f *srFixture) successUnpolled(t *testing.T, index int, user model.UserSpec, region int) {
	t.Helper()
	f.successUnpolledWithOptions(t, index, user, region, f.options(index, user))
}

func (f *srFixture) successUnpolledWithOptions(t *testing.T, index int, user model.UserSpec, region int, options srClientOptions) {
	t.Helper()
	request := f.request()
	responseBytes, err := f.exchange(t, options, request)
	if err != nil {
		t.Fatalf("unpolled real HTTP exchange: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseBytes)), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("parse unpolled HTTP response: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	marker := fmt.Sprintf("region-%d", region+1)
	expectedBody := []byte(fmt.Sprintf("region=%s\ntoken=%s\nrequest=%s\n", marker, request.token, request.body))
	if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Region") != marker || !bytes.Equal(body, expectedBody) {
		t.Fatalf("unpolled HTTP region/body mismatch: status=%d region=%q read=%v", response.StatusCode, response.Header.Get("X-Region"), readErr)
	}
	f.nodes[index].credit(user.ID, len(request.raw), len(responseBytes))
	f.assertFlux(t, index, user, request.targetPort)
}
