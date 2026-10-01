package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	// DefaultQueueSize and DefaultBatchSize size the process-wide shared
	// uploader when audit.queue_size or audit.batch_size is 0.
	DefaultQueueSize = 16384
	DefaultBatchSize = 512
	// MaxQueueSize and MaxBatchSize bound the configurable sizes.
	MaxQueueSize = 200000
	MaxBatchSize = 5000

	defaultFlushInterval = 2 * time.Second
	shutdownSendTimeout  = 5 * time.Second
	MaxPendingAge        = 12 * time.Hour
	dropLogInterval      = time.Minute
	logBodyLimit         = 200
	maxLoggedSites       = 8
	responseLimit        = 4096
	// MaxSiteBytes bounds audit.site, including a site derived from the panel domain.
	MaxSiteBytes     = 128
	maxUUIDBytes     = 128
	maxCoreBytes     = 32
	maxProtocolBytes = 64
	maxNetworkBytes  = 16
	maxSourceIPBytes = 128
	maxTargetBytes   = 512

	// After a failed upload Run waits backoffMin before the next attempt,
	// doubling the wait with every consecutive failure up to backoffMax.
	backoffMin = time.Second
	backoffMax = 30 * time.Second

	// Uploads are sequential, so one keep-alive connection per uploader is
	// reused for every batch. The idle timeout stays below common server
	// keep-alive timeouts (nginx: 75s) so that the client retires an idle
	// connection before the server closes it.
	requestTimeout        = 8 * time.Second
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 6 * time.Second
	idleConnTimeout       = 60 * time.Second
	maxResponseHeaderSize = 64 << 10
	// drainLimit bounds the unread response bytes discarded to keep a
	// connection reusable; a longer body closes the connection instead.
	drainLimit = 64 << 10
)

var validAgentID = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

// Version is reported with every batch. The main package sets it to the
// build version before any uploader is created; it is omitted when empty.
var Version string

// NormalizeProtocol returns the protocol name Flux expects: "hy2" and the
// Xray/panel "hysteria" protocol at version 2 are both reported as
// "hysteria2". version is 0 when unknown; any other protocol is unchanged.
func NormalizeProtocol(protocol string, version int) string {
	switch protocol {
	case "hy2":
		return "hysteria2"
	case "hysteria":
		if version == 2 {
			return "hysteria2"
		}
	}
	return protocol
}

// Event contains connection metadata, never traffic payloads.
type Event struct {
	EventID  string    `json:"event_id"`
	Site     string    `json:"site"`
	Time     time.Time `json:"time"`
	Event    string    `json:"event"`
	UserID   int       `json:"user_id"`
	UUID     string    `json:"uuid"`
	NodeID   int       `json:"node_id"`
	Core     string    `json:"core"`
	Protocol string    `json:"protocol"`
	Network  string    `json:"network"`
	SourceIP string    `json:"source_ip"`
	Target   string    `json:"target"`
}

// Batch is the uncompressed JSON body of one upload. InstanceID is random per
// uploader and constant for its lifetime; it lets the receiver keep the Stats
// counters of processes that share one AgentID apart, and it prefixes every
// batch and event ID of the uploader.
type Batch struct {
	AgentID    string  `json:"agent_id"`
	InstanceID string  `json:"instance_id"`
	Version    string  `json:"version,omitempty"`
	SentAt     int64   `json:"sent_at"`
	Stats      Stats   `json:"stats"`
	Events     []Event `json:"events"`
}

// Config describes an uploader. Site is not part of the uploader: Acquire
// stamps it on the events recorded through each Handle, so services of
// different sites can share one uploader. New ignores it.
type Config struct {
	URL           string
	Secret        string
	Site          string
	AgentID       string
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
}

// Stats are uploader counters. Queued includes the queue and unconfirmed
// batch; the other counters are cumulative. Failures counts failed attempts,
// Retries counts repeated attempts, and Dropped counts actual event loss.
type Stats struct {
	Queued   int    `json:"queued"`
	Dropped  uint64 `json:"dropped"`
	Uploaded uint64 `json:"uploaded"`
	Retries  uint64 `json:"retries"`
	Failures uint64 `json:"failures"`
}

// Client owns a fixed-size queue. Record does no disk or network I/O and
// intentionally drops events rather than slowing down the proxy when full.
type Client struct {
	cfg      Config
	version  string
	queue    chan Event
	done     chan struct{}
	http     *http.Client
	prefix   string
	sequence atomic.Uint64
	uploaded atomic.Uint64
	dropped  atomic.Uint64
	failures atomic.Uint64
	retries  atomic.Uint64
	pending  atomic.Int64

	// backoffWait returns a channel that fires after d. Tests replace it to
	// observe the backoff and end it early.
	backoffWait func(d time.Duration) <-chan time.Time

	// Owned by the Run goroutine.
	reportedDropped uint64
	lastDropLog     time.Time
	rejectedTotal   uint64 // rejected by the receiver since the last rejection log
	lastRejectLog   time.Time
	failureStreak   int
	backoff         time.Duration // wait before the next attempt; 0 after a success
}

// Sink receives accepted-connection events from the proxy kernels.
type Sink interface {
	Record(Event)
}

// Validate reports whether cfg can create an uploader. It does not check
// Site, which only Acquire requires.
func (cfg Config) Validate() error {
	_, err := cfg.withDefaults()
	return err
}

func (cfg Config) withDefaults() (Config, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return cfg, errors.New("audit.url must be an HTTPS URL (HTTP is allowed only for loopback testing)")
	}
	if cfg.Secret == "" {
		return cfg, errors.New("audit secret is required")
	}
	if cfg.QueueSize < 0 || cfg.QueueSize > MaxQueueSize {
		return cfg, fmt.Errorf("audit.queue_size must be between 0 and %d", MaxQueueSize)
	}
	if cfg.BatchSize < 0 || cfg.BatchSize > MaxBatchSize {
		return cfg, fmt.Errorf("audit.batch_size must be between 0 and %d", MaxBatchSize)
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.BatchSize == 0 {
		// A small explicit queue caps the default batch size instead of
		// failing validation.
		cfg.BatchSize = min(DefaultBatchSize, cfg.QueueSize)
	}
	if cfg.BatchSize > cfg.QueueSize {
		return cfg, errors.New("audit.batch_size must not exceed audit.queue_size")
	}
	if cfg.AgentID == "" {
		cfg.AgentID, err = os.Hostname()
		if err != nil || cfg.AgentID == "" {
			cfg.AgentID = "xboard-node"
		}
	}
	if !validAgentID.MatchString(cfg.AgentID) {
		return cfg, errors.New("audit.agent_id must match [a-zA-Z0-9_.:-]{1,128}")
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	return cfg, nil
}

// New creates an uploader whose Run the caller manages. Services use Acquire,
// which shares one uploader per configuration in the process. Events passed
// to Client.Record must already carry their Site.
func New(cfg Config) (*Client, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	return newClient(cfg)
}

// newClient expects cfg to have passed withDefaults.
func newClient(cfg Config) (*Client, error) {
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("audit ID seed: %w", err)
	}
	return &Client{
		cfg: cfg, version: Version, queue: make(chan Event, cfg.QueueSize), done: make(chan struct{}),
		http: newHTTPClient(), prefix: hex.EncodeToString(seed[:]), backoffWait: time.After,
	}, nil
}

// newHTTPClient returns a client with its own keep-alive pool and bounded
// timeouts. It takes proxy settings from the environment and does not follow
// redirects.
func newHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            dialer.DialContext,
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           1,
			MaxIdleConnsPerHost:    1,
			IdleConnTimeout:        idleConnTimeout,
			TLSHandshakeTimeout:    tlsHandshakeTimeout,
			ResponseHeaderTimeout:  responseHeaderTimeout,
			MaxResponseHeaderBytes: maxResponseHeaderSize,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Record enqueues an event without blocking. Events without a site, user,
// source IP or target, and events that do not fit into the queue, are counted
// as dropped.
func (c *Client) Record(event Event) {
	if c == nil {
		return
	}
	if event.Site == "" {
		event.Site = c.cfg.Site
	}
	event.Protocol = NormalizeProtocol(event.Protocol, 0)
	if event.Site == "" || event.UserID <= 0 || event.SourceIP == "" || event.Target == "" {
		c.dropped.Add(1)
		return
	}
	if len(event.Site) > MaxSiteBytes || len(event.UUID) > maxUUIDBytes || len(event.Core) > maxCoreBytes ||
		len(event.Protocol) > maxProtocolBytes || len(event.Network) > maxNetworkBytes ||
		len(event.SourceIP) > maxSourceIPBytes || len(event.Target) > maxTargetBytes {
		c.dropped.Add(1)
		return
	}
	if len(c.queue) == cap(c.queue) {
		c.dropped.Add(1)
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	event.EventID = c.prefix + "-" + strconv.FormatUint(c.sequence.Add(1), 16)
	event.Event = "accepted"
	select {
	case c.queue <- event:
	default:
		c.dropped.Add(1)
	}
}

func (c *Client) Dropped() uint64       { return c.dropped.Load() }
func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) Snapshot() Stats {
	return Stats{Queued: len(c.queue) + int(c.pending.Load()), Dropped: c.dropped.Load(), Uploaded: c.uploaded.Load(), Failures: c.failures.Load(), Retries: c.retries.Load()}
}

// pendingBatch is the batch being delivered. Its ID and payload are fixed by
// the first send attempt so that every retry is byte-identical.
type pendingBatch struct {
	events     []Event
	id         string
	payload    []byte
	compressed []byte
	attempts   int
}

func (b *pendingBatch) sealed() bool { return b.id != "" }

func (b *pendingBatch) expired(now time.Time) bool {
	cutoff := now.Add(-MaxPendingAge)
	for _, event := range b.events {
		if event.Time.Before(cutoff) {
			return true
		}
	}
	return false
}

func (b *pendingBatch) reset() {
	clear(b.events)
	b.events = b.events[:0]
	b.id, b.payload, b.compressed = "", nil, nil
	b.attempts = 0
}

// Run delivers batches until ctx is cancelled; call it at most once. A batch
// is sent as soon as it holds BatchSize events, or on the flush tick when it
// holds at least one. Transient failures retain the sealed batch and back off
// from 1s to 30s. No newer event can mutate its payload or bypass it. Memory
// stays bounded by the queue plus one batch; a full queue drops new events.
// Cancellation drains remaining batches within one shared shutdown deadline.
func (c *Client) Run(ctx context.Context) {
	defer close(c.done)
	defer c.http.CloseIdleConnections()
	flush := time.NewTicker(c.cfg.FlushInterval)
	defer flush.Stop()
	batch := &pendingBatch{events: make([]Event, 0, c.cfg.BatchSize)}
	var retry <-chan time.Time // non-nil while backing off
	for {
		queue := c.queue
		if batch.sealed() || len(batch.events) >= c.cfg.BatchSize {
			queue = nil
		}
		select {
		case event := <-queue:
			if time.Since(event.Time) > MaxPendingAge {
				c.dropped.Add(1)
				continue
			}
			batch.events = append(batch.events, event)
			c.pending.Store(int64(len(batch.events)))
			if retry != nil || len(batch.events) < c.cfg.BatchSize {
				continue
			}
		case <-flush.C:
			c.reportDrops(false)
			if retry != nil || len(batch.events) == 0 {
				continue
			}
		case <-retry:
			retry = nil
			if len(batch.events) == 0 {
				continue
			}
		case <-ctx.Done():
			c.shutdown(batch)
			return
		}
		finished, running := c.sendOnce(ctx, batch)
		if !running {
			c.shutdown(batch)
			return
		}
		if finished {
			batch.reset()
			c.pending.Store(0)
		}
		if c.backoff > 0 {
			retry = c.backoffWait(c.backoff)
		}
	}
}

// shutdown flushes all buffered batches within one total deadline. Only the
// events still unconfirmed at the deadline are counted as dropped.
func (c *Client) shutdown(batch *pendingBatch) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownSendTimeout)
	defer cancel()
	defer c.pending.Store(0)
	for ctx.Err() == nil {
		if batch.expired(time.Now()) {
			c.dropped.Add(uint64(len(batch.events)))
			batch.reset()
			c.pending.Store(0)
		}
		for !batch.sealed() && len(batch.events) < c.cfg.BatchSize && len(c.queue) > 0 {
			event := <-c.queue
			if time.Since(event.Time) > MaxPendingAge {
				c.dropped.Add(1)
				continue
			}
			batch.events = append(batch.events, event)
		}
		c.pending.Store(int64(len(batch.events)))
		if len(batch.events) == 0 {
			break
		}
		res := c.send(ctx, batch)
		if res.outcome == sendOK {
			batch.reset()
			c.pending.Store(0)
			continue
		}
		if res.outcome == sendInvalid {
			c.dropFailed(batch, res, 0)
			batch.reset()
			c.pending.Store(0)
			continue
		}
		if ctx.Err() != nil {
			break
		}
		c.retainFailed(batch, res, backoffMin)
		timer := time.NewTimer(backoffMin)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	if len(batch.events) > 0 {
		c.dropped.Add(uint64(len(batch.events)))
		batch.reset()
	}
	remaining := 0
drain:
	for range cap(c.queue) {
		select {
		case <-c.queue:
			remaining++
		default:
			break drain
		}
	}
	c.dropped.Add(uint64(remaining))
	c.reportDrops(true)
}

// sendOnce reports whether the batch can be released and whether Run can
// continue. Context cancellation leaves ownership to the shutdown drain.
func (c *Client) sendOnce(ctx context.Context, batch *pendingBatch) (bool, bool) {
	if ctx.Err() != nil {
		return false, false
	}
	if batch.expired(time.Now()) {
		c.dropped.Add(uint64(len(batch.events)))
		c.backoff = 0
		return true, true
	}
	res := c.send(ctx, batch)
	if res.outcome == sendOK {
		c.failureStreak = 0
		c.backoff = 0
		return true, true
	}
	if ctx.Err() != nil {
		return false, false
	}
	c.backoff = nextBackoff(c.backoff)
	if res.outcome == sendInvalid {
		c.dropFailed(batch, res, c.backoff)
		return true, true
	}
	c.retainFailed(batch, res, c.backoff)
	return false, true
}

func (c *Client) retainFailed(batch *pendingBatch, res sendResult, backoff time.Duration) {
	c.failureStreak++
	if c.failureStreak == 1 || c.failureStreak%60 == 0 {
		nlog.Core().Warn("audit upload failed; retaining batch for retry", c.failureArgs(res, "events", len(batch.events), "failed_attempts", c.failureStreak, "backoff", backoff)...)
	}
}

// nextBackoff returns the wait after one more consecutive failed upload.
func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return backoffMin
	}
	return min(2*current, backoffMax)
}

// dropFailed counts a failed batch as dropped and logs only the first failure
// of a streak and every 60th after it. backoff is the wait before the next
// attempt (0 on shutdown).
func (c *Client) dropFailed(batch *pendingBatch, res sendResult, backoff time.Duration) {
	c.dropped.Add(uint64(len(batch.events)))
	c.failureStreak++
	if c.failureStreak == 1 || c.failureStreak%60 == 0 {
		nlog.Core().Warn("audit upload failed; dropping batch", c.failureArgs(res, "events", len(batch.events), "failed_batches", c.failureStreak, "backoff", backoff)...)
	}
}

// reportRejected warns when the receiver refuses events from an accepted
// batch, which is how Flux answers a site it does not know. The batch is not
// retried; the warning is rate limited like the drop log so a wrong audit.site
// cannot flood the log.
func (c *Client) reportRejected(batch *pendingBatch, res sendResult) {
	c.rejectedTotal += uint64(res.rejected)
	now := time.Now()
	if !c.lastRejectLog.IsZero() && now.Sub(c.lastRejectLog) < dropLogInterval {
		return
	}
	var sites []string
	for _, event := range batch.events {
		if !slices.Contains(sites, event.Site) {
			sites = append(sites, event.Site)
			if len(sites) == maxLoggedSites {
				break
			}
		}
	}
	nlog.Core().Warn("audit receiver rejected events; set audit.site or map the panel domain in Flux", "agent", c.cfg.AgentID, "sites", strings.Join(sites, ","),
		"accepted", res.accepted, "rejected", res.rejected, "rejected_since_last_log", c.rejectedTotal)
	c.rejectedTotal = 0
	c.lastRejectLog = now
}

func (c *Client) failureArgs(res sendResult, extra ...any) []any {
	args := append([]any{"agent", c.cfg.AgentID}, extra...)
	if res.status != 0 {
		args = append(args, "status", res.status)
	}
	if res.err != nil {
		args = append(args, "error", res.err)
	}
	if res.body != "" {
		args = append(args, "body", res.body)
	}
	return append(args, "queued", len(c.queue), "dropped", c.dropped.Load())
}

// reportDrops logs newly dropped events at most once per dropLogInterval
// (always when force is set), so a sustained overload cannot flood the log.
func (c *Client) reportDrops(force bool) {
	dropped := c.dropped.Load()
	if dropped <= c.reportedDropped {
		return
	}
	now := time.Now()
	if !force && !c.lastDropLog.IsZero() && now.Sub(c.lastDropLog) < dropLogInterval {
		return
	}
	nlog.Core().Warn("audit events dropped", "agent", c.cfg.AgentID, "new_dropped", dropped-c.reportedDropped, "total_dropped", dropped, "queued", len(c.queue))
	c.reportedDropped = dropped
	c.lastDropLog = now
}

type sendOutcome int

const (
	sendFailed  sendOutcome = iota // transient or ambiguous failure; retain the batch
	sendOK                         // accepted; per-event rejections count as dropped
	sendInvalid                    // malformed or oversized batch; cannot recover by retry
)

type sendResult struct {
	outcome sendOutcome
	status  int    // HTTP status; 0 if no response was received
	body    string // quoted response snippet worth logging, if any
	err     error

	// Set when the receiver accepted the batch: how many events it kept and
	// how many it refused (for example an unknown site).
	accepted, rejected int
}

// send makes one upload attempt and counts it in Failures unless the receiver
// accepted the batch.
func (c *Client) send(ctx context.Context, batch *pendingBatch) sendResult {
	res := c.post(ctx, batch)
	if res.outcome != sendOK {
		c.failures.Add(1)
	} else if res.rejected > 0 {
		c.reportRejected(batch, res)
	}
	return res
}

func (c *Client) post(ctx context.Context, batch *pendingBatch) sendResult {
	if !batch.sealed() {
		if err := c.seal(batch); err != nil {
			// Only possible with malformed events; a later send cannot fix it.
			return sendResult{outcome: sendInvalid, err: err}
		}
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(c.cfg.Secret))
	io.WriteString(mac, timestamp+"."+batch.id+".")
	mac.Write(batch.compressed)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(batch.compressed))
	if err != nil {
		return sendResult{outcome: sendInvalid, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Flux-Timestamp", timestamp)
	req.Header.Set("X-Flux-Batch-Id", batch.id)
	req.Header.Set("X-Flux-Signature", hex.EncodeToString(mac.Sum(nil)))
	// The receiver deduplicates a batch ID, so the request is idempotent. The
	// header lets the transport replay it on a new connection when a reused
	// keep-alive connection turns out to have been closed by the server.
	req.Header.Set("Idempotency-Key", batch.id)
	if batch.attempts > 0 {
		c.retries.Add(1)
	}
	batch.attempts++
	resp, err := c.http.Do(req)
	if err != nil {
		return sendResult{outcome: sendFailed, err: err}
	}
	defer drainAndClose(resp.Body)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
	res := sendResult{outcome: sendFailed, status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
			res.outcome = sendInvalid
		}
		if resp.StatusCode < 500 || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			res.body = logSnippet(body)
		}
		return res
	}
	var result struct {
		OK       bool   `json:"ok"`
		Accepted int    `json:"accepted"`
		Rejected int    `json:"rejected"`
		BatchID  string `json:"batchId"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.OK || result.Accepted < 0 || result.Rejected < 0 ||
		result.Accepted+result.Rejected != len(batch.events) || result.BatchID != batch.id {
		res.err = errors.New("unexpected ingest response")
		res.body = logSnippet(body)
		return res
	}
	c.uploaded.Add(uint64(result.Accepted))
	c.dropped.Add(uint64(result.Rejected))
	res.outcome = sendOK
	res.accepted, res.rejected = result.Accepted, result.Rejected
	return res
}

// drainAndClose discards up to drainLimit unread bytes so that the keep-alive
// connection can be reused, then closes the body.
func drainAndClose(body io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(body, drainLimit))
	body.Close()
}

// seal fixes the batch ID and payload so the bounded shutdown attempt can be
// deduplicated if the first request reached the server but its response was lost.
func (c *Client) seal(batch *pendingBatch) error {
	id := c.prefix + "-" + strconv.FormatUint(c.sequence.Add(1), 16)
	payload, err := json.Marshal(Batch{AgentID: c.cfg.AgentID, InstanceID: c.prefix, Version: c.version, SentAt: time.Now().Unix(), Stats: c.Snapshot(), Events: batch.events})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	batch.id, batch.payload, batch.compressed = id, payload, buf.Bytes()
	return nil
}

// logSnippet returns the first logBodyLimit bytes of a response body, quoted
// so that it stays on one log line.
func logSnippet(body []byte) string {
	if len(body) > logBodyLimit {
		body = body[:logBodyLimit]
	}
	return strconv.Quote(string(body))
}
