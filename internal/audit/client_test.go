package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientUploadsSignedGzipBatch(t *testing.T) {
	received := make(chan Batch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("missing authentication or compression headers: %v", r.Header)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		wireBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		reader, err := gzip.NewReader(bytes.NewReader(wireBody))
		if err != nil {
			t.Error(err)
			return
		}
		defer reader.Close()
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
			return
		}
		mac := hmac.New(sha256.New, []byte("secret"))
		fmt.Fprintf(mac, "%s.%s.", r.Header.Get("X-Flux-Timestamp"), r.Header.Get("X-Flux-Batch-Id"))
		mac.Write(wireBody)
		if r.Header.Get("X-Flux-Signature") != fmt.Sprintf("%x", mac.Sum(nil)) {
			t.Error("invalid HMAC signature")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var batch Batch
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Error(err)
			return
		}
		received <- batch
		fmt.Fprintf(w, `{"ok":true,"accepted":2,"rejected":0,"batchId":%q}`, r.Header.Get("X-Flux-Batch-Id"))
	}))
	defer server.Close()

	client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 4, BatchSize: 2, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	event := Event{Time: time.Now().UTC(), NodeID: 7, Core: "xray", Protocol: "vless", Network: "tcp", UserID: 42, UUID: "uuid", SourceIP: "203.0.113.2", Target: "example.com:443"}
	client.Record(event)
	client.Record(event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)
	select {
	case batch := <-received:
		if batch.AgentID != "node-1" || len(batch.Events) != 2 || batch.Events[0].Site != "test" || batch.Events[0].UserID != event.UserID || batch.Events[0].Target != event.Target || batch.Events[0].EventID == batch.Events[1].EventID {
			t.Fatalf("wrong batch: %+v", batch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("batch was not sent")
	}
	cancel()
	<-client.Done()
}

func TestClientRetainsUnavailableBatchAndRetriesIdenticalPayload(t *testing.T) {
	var attempts atomic.Int32
	var firstID string
	var firstBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if attempts.Add(1) == 1 {
			firstID, firstBody = r.Header.Get("X-Flux-Batch-Id"), body
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("X-Flux-Batch-Id") != firstID || !bytes.Equal(body, firstBody) {
			t.Error("retry changed the batch identity or compressed payload")
		}
		fmt.Fprintf(w, `{"ok":true,"accepted":1,"rejected":0,"batchId":%q}`, r.Header.Get("X-Flux-Batch-Id"))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	waits := make(chan time.Duration, 1)
	retry := make(chan time.Time, 1)
	client.backoffWait = func(d time.Duration) <-chan time.Time {
		waits <- d
		return retry
	}
	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx)
	defer func() { cancel(); <-client.Done() }()
	client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443"})
	select {
	case <-waits:
	case <-time.After(3 * time.Second):
		t.Fatal("failed upload did not enter backoff")
	}
	if stats := client.Snapshot(); stats.Dropped != 0 || stats.Queued != 1 {
		t.Fatalf("transient failure lost buffered events: %+v", stats)
	}
	retry <- time.Now()
	deadline := time.Now().Add(3 * time.Second)
	for (client.Snapshot().Uploaded != 1 || client.Snapshot().Queued != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := client.Snapshot(); stats.Uploaded != 1 || stats.Dropped != 0 || stats.Failures != 1 || stats.Retries != 1 || stats.Queued != 0 {
		t.Fatalf("recovered upload stats = %+v", stats)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("HTTP attempts = %d, want failed attempt and one retry", got)
	}
}

func TestClientShutdownFlushesAllBufferedBatches(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer reader.Close()
		var batch Batch
		if err := json.NewDecoder(reader).Decode(&batch); err != nil {
			t.Error(err)
			return
		}
		accepted.Add(int32(len(batch.Events)))
		fmt.Fprintf(w, `{"ok":true,"accepted":%d,"rejected":0,"batchId":%q}`, len(batch.Events), r.Header.Get("X-Flux-Batch-Id"))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 8, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443"})
	}
	client.shutdown(&pendingBatch{events: make([]Event, 0, 2)})
	if stats := client.Snapshot(); accepted.Load() != 5 || stats.Uploaded != 5 || stats.Dropped != 0 || stats.Queued != 0 {
		t.Fatalf("graceful shutdown lost queued events: accepted=%d stats=%+v", accepted.Load(), stats)
	}
}

func TestClientDoesNotReleaseBatchForWrongAcknowledgement(t *testing.T) {
	for _, ackID := range []string{"", "another-batch"} {
		t.Run(ackID, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"ok":true,"accepted":1,"rejected":0,"batchId":%q}`, ackID)
			}))
			defer server.Close()
			client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2})
			if err != nil {
				t.Fatal(err)
			}
			batch := &pendingBatch{events: []Event{{Site: "test", UserID: 1, Time: time.Now(), SourceIP: "203.0.113.2", Target: "example.com:443"}}}
			result := client.send(context.Background(), batch)
			if result.outcome != sendFailed || client.Snapshot().Uploaded != 0 || client.Snapshot().Dropped != 0 {
				t.Fatalf("mismatched acknowledgement released events: result=%+v stats=%+v", result, client.Snapshot())
			}
		})
	}
}

func TestClientShutdownCountsExpiredBufferedEventsWithoutUploadingThem(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				fmt.Fprintf(w, `{"ok":true,"accepted":1,"rejected":0,"batchId":%q}`, r.Header.Get("X-Flux-Batch-Id"))
			}))
			defer server.Close()
			client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2, BatchSize: 1})
			if err != nil {
				t.Fatal(err)
			}
			client.Record(Event{UserID: 1, Time: time.Now().Add(-13 * time.Hour), SourceIP: "203.0.113.2", Target: "example.com:443"})
			batch := &pendingBatch{events: make([]Event, 0, 1)}
			if pending {
				batch.events = append(batch.events, <-client.queue)
				if err := client.seal(batch); err != nil {
					t.Fatal(err)
				}
			}
			client.shutdown(batch)
			if stats := client.Snapshot(); requests.Load() != 0 || stats.Uploaded != 0 || stats.Dropped != 1 || stats.Queued != 0 {
				t.Fatalf("expired retry was not explicitly terminated: requests=%d stats=%+v", requests.Load(), stats)
			}
		})
	}
}

func TestClientBoundsQueueWithoutBlockingRecord(t *testing.T) {
	client, err := New(Config{URL: "https://flux.example/api/node-audit/ingest", Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "first"})
	done := make(chan struct{})
	go func() {
		client.Record(Event{UserID: 1, SourceIP: "203.0.113.2", Target: "second"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Record blocked on full queue")
	}
	if got := client.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestClientRecordDoesNotWaitForStalledUpload(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer reader.Close()
		var batch Batch
		if err := json.NewDecoder(reader).Decode(&batch); err != nil {
			t.Error(err)
			return
		}
		once.Do(func() { close(started) })
		<-release
		fmt.Fprintf(w, `{"ok":true,"accepted":%d,"rejected":0,"batchId":%q}`, len(batch.Events), r.Header.Get("X-Flux-Batch-Id"))
	}))
	client, err := New(Config{URL: server.URL, Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2, BatchSize: 1})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx)
	defer func() {
		close(release)
		cancel()
		<-client.Done()
		server.Close()
	}()
	event := Event{UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443"}
	client.Record(event)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("upload did not start")
	}
	recorded := make(chan struct{})
	go func() {
		for range 128 {
			client.Record(event)
		}
		close(recorded)
	}()
	select {
	case <-recorded:
	case <-time.After(time.Second):
		t.Fatal("connection recording waited for the stalled HTTP response")
	}
	if stats := client.Snapshot(); stats.Queued != 3 || stats.Dropped != 126 || stats.Uploaded != 0 {
		t.Fatalf("stalled upload exceeded its memory/event budget: %+v", stats)
	}
}

func BenchmarkClientRecord(b *testing.B) {
	for _, full := range []bool{false, true} {
		name := "available"
		if full {
			name = "full"
		}
		b.Run(name, func(b *testing.B) {
			client, err := New(Config{URL: "https://flux.example/ingest", Secret: "test-only", Site: "test", AgentID: "bench", QueueSize: 1})
			if err != nil {
				b.Fatal(err)
			}
			event := Event{Time: time.Now(), UserID: 1, SourceIP: "203.0.113.2", Target: "example.com:443"}
			if full {
				client.Record(event)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				client.Record(event)
				if !full {
					<-client.queue
				}
			}
		})
	}
}

func TestClientDropsOversizedEventFieldsWithoutQueueing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "site", mutate: func(e *Event) { e.Site = strings.Repeat("s", 129) }},
		{name: "uuid", mutate: func(e *Event) { e.UUID = strings.Repeat("u", 129) }},
		{name: "core", mutate: func(e *Event) { e.Core = strings.Repeat("c", 33) }},
		{name: "protocol", mutate: func(e *Event) { e.Protocol = strings.Repeat("p", 65) }},
		{name: "network", mutate: func(e *Event) { e.Network = strings.Repeat("n", 17) }},
		{name: "source_ip", mutate: func(e *Event) { e.SourceIP = strings.Repeat("i", 129) }},
		{name: "target", mutate: func(e *Event) { e.Target = strings.Repeat("t", 513) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Config{URL: "https://flux.example/api/node-audit/ingest", Secret: "secret", Site: "test", AgentID: "node-1", QueueSize: 2, BatchSize: 1})
			if err != nil {
				t.Fatal(err)
			}
			event := Event{Site: "test", UserID: 1, UUID: "uuid", Core: "xray", Protocol: "vless", Network: "tcp", SourceIP: "203.0.113.2", Target: "example.com:443"}
			tc.mutate(&event)
			client.Record(event)
			stats := client.Snapshot()
			if stats.Queued != 0 || stats.Dropped != 1 {
				t.Fatalf("oversized event stats = %+v, want queued=0 and dropped=1", stats)
			}
		})
	}
}

func TestClientRejectsInsecureRemoteEndpoint(t *testing.T) {
	if _, err := New(Config{URL: "http://flux.example/ingest", Secret: "secret", Site: "test", AgentID: "node-1"}); err == nil {
		t.Fatal("remote audit data must require HTTPS")
	}
}

func TestConfigValidatesFluxAgentID(t *testing.T) {
	base := Config{URL: "https://flux.example/ingest", Secret: "secret"}
	for _, id := range []string{"node-1.us:east", strings.Repeat("a", 128)} {
		cfg := base
		cfg.AgentID = id
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid agent_id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"bad/id", "has space", "nonascii-\u8282\u70b9", strings.Repeat("a", 129)} {
		cfg := base
		cfg.AgentID = id
		if err := cfg.Validate(); err == nil {
			t.Errorf("invalid agent_id %q accepted", id)
		}
	}
}

func TestAcquireSharesUploaderAcrossSites(t *testing.T) {
	received := make(chan Batch, 2)
	requests := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer reader.Close()
		var batch Batch
		if err := json.NewDecoder(reader).Decode(&batch); err != nil {
			t.Error(err)
			return
		}
		received <- batch
		requests <- struct{}{}
		fmt.Fprintf(w, `{"ok":true,"accepted":%d,"rejected":0,"batchId":%q}`, len(batch.Events), r.Header.Get("X-Flux-Batch-Id"))
	}))
	defer server.Close()

	base := Config{URL: server.URL, Secret: "secret", AgentID: "machine-1", QueueSize: 4, BatchSize: 2, FlushInterval: time.Hour}
	first, err := Acquire(Config{URL: base.URL, Secret: base.Secret, AgentID: base.AgentID, Site: "alpha", QueueSize: base.QueueSize, BatchSize: base.BatchSize, FlushInterval: base.FlushInterval})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(Config{URL: base.URL, Secret: base.Secret, AgentID: base.AgentID, Site: "beta", QueueSize: base.QueueSize, BatchSize: base.BatchSize, FlushInterval: base.FlushInterval})
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	if first.client != second.client {
		first.Close()
		second.Close()
		t.Fatal("instances with the same uploader configuration must share one client")
	}

	first.Record(Event{UserID: 42, UUID: "same-uuid", NodeID: 7, Core: "xray", Protocol: "vless", Network: "tcp", SourceIP: "192.0.2.1", Target: "one.example:443"})
	first.Close()
	second.Record(Event{UserID: 42, UUID: "same-uuid", NodeID: 8, Core: "singbox", Protocol: "vless", Network: "tcp", SourceIP: "192.0.2.2", Target: "two.example:443"})

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for first.Snapshot().Uploaded != 2 {
		select {
		case <-deadline.C:
			second.Close()
			t.Fatal("shared uploader did not account for both delivered events")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case batch := <-received:
		if len(batch.Events) != 2 || batch.Events[0].Site != "alpha" || batch.Events[1].Site != "beta" {
			t.Fatalf("shared batch lost per-handle site identity: %+v", batch.Events)
		}
	case <-time.After(3 * time.Second):
		second.Close()
		t.Fatal("shared uploader did not deliver both sites in one batch")
	}
	second.Close()
	if got := len(requests); got != 1 {
		t.Fatalf("HTTP batches = %d, want 1", got)
	}
}

func TestHandleRecordsAfterCloseAreAccounted(t *testing.T) {
	h, err := Acquire(Config{URL: "https://flux.example/ingest", Secret: "secret", Site: "alpha", AgentID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	h.Record(Event{UserID: 1, SourceIP: "192.0.2.1", Target: "example.com:443"})
	if got := h.Snapshot().Dropped; got != 1 {
		t.Fatalf("dropped after Close = %d, want 1", got)
	}
}

func TestHandleConcurrentRecordAndLastCloseAccountEveryEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	h, err := Acquire(Config{URL: server.URL, Secret: "secret", Site: "alpha", AgentID: "node-1", QueueSize: 256, BatchSize: 256, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const records = 128
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < records; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			h.Record(Event{UserID: 1, SourceIP: "192.0.2.1", Target: "example.com:443"})
		}()
	}
	closed := make(chan struct{})
	go func() {
		<-start
		h.Close()
		close(closed)
	}()
	close(start)
	wg.Wait()
	<-closed
	stats := h.Snapshot()
	if got := stats.Uploaded + stats.Dropped; got != records {
		t.Fatalf("accounted = %d, want %d (stats: %+v)", got, records, stats)
	}
}
