package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestNormalizeProtocol(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		version  int
		want     string
	}{
		{"hy2", 0, "hysteria2"},
		{"hysteria2", 0, "hysteria2"},
		{"hysteria", 2, "hysteria2"},
		{"hysteria", 1, "hysteria"},
		{"hysteria", 0, "hysteria"},
		{"vless", 2, "vless"},
		{"tuic", 0, "tuic"},
	} {
		if got := NormalizeProtocol(tc.protocol, tc.version); got != tc.want {
			t.Errorf("NormalizeProtocol(%q, %d) = %q, want %q", tc.protocol, tc.version, got, tc.want)
		}
	}
}

func TestClientRecordNormalizesHy2Protocol(t *testing.T) {
	client, err := New(Config{URL: "https://flux.example/api/node-audit/ingest", Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443", Protocol: "hy2"})
	if got := (<-client.queue).Protocol; got != "hysteria2" {
		t.Fatalf("queued protocol = %q, want hysteria2", got)
	}
}

func TestClientWarnsOnceWhenReceiverRejectsEventsAndDoesNotRetry(t *testing.T) {
	logs := &lockedBuffer{}
	nlog.Init(logs, slog.LevelInfo, false)
	defer nlog.Init(os.Stdout, slog.LevelInfo, true)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		fmt.Fprintf(w, `{"ok":true,"accepted":0,"rejected":1,"batchId":%q}`, r.Header.Get("X-Flux-Batch-Id"))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Secret: "secret", Site: "wrong-site", AgentID: "node-1", QueueSize: 4, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx)
	for range 2 {
		client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443"})
	}
	deadline := time.Now().Add(3 * time.Second)
	// The receiver rejects each event, so Dropped reaches 2 only after the
	// client has processed both responses.
	for client.Snapshot().Dropped < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-client.Done()

	// Both batches were sent without the failure backoff and neither was retried.
	if got := attempts.Load(); got != 2 {
		t.Fatalf("HTTP attempts = %d, want 2", got)
	}
	stats := client.Snapshot()
	if stats.Dropped != 2 || stats.Failures != 0 {
		t.Fatalf("stats = %+v, want 2 dropped and no failures", stats)
	}
	out := logs.String()
	if n := strings.Count(out, "audit receiver rejected events"); n != 1 {
		t.Fatalf("rejection warnings = %d, want exactly one (rate limited)\n%s", n, out)
	}
	for _, want := range []string{"WARN", "sites=wrong-site", "accepted=0", "rejected=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("warning is missing %q\n%s", want, out)
		}
	}
}
