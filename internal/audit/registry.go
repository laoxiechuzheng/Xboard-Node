package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

type sharedUploader struct {
	client  *Client
	key     string
	refs    int
	closing bool
	cancel  context.CancelFunc
}

type Handle struct {
	shared *sharedUploader
	client *Client
	site   string

	mu     sync.RWMutex
	closed bool
}

var uploaderRegistry = struct {
	sync.Mutex
	items map[string]*sharedUploader
}{items: make(map[string]*sharedUploader)}

// Acquire returns a site-scoped recorder backed by one process-wide uploader
// for each endpoint, secret, agent, and queue configuration.
func Acquire(cfg Config) (*Handle, error) {
	site := strings.TrimSpace(cfg.Site)
	if site == "" {
		return nil, errors.New("audit.site is required")
	}
	cfg.Site = site
	normalized, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	key, err := uploaderKey(normalized)
	if err != nil {
		return nil, err
	}

	for {
		uploaderRegistry.Lock()
		if shared := uploaderRegistry.items[key]; shared != nil {
			if shared.closing {
				done := shared.client.Done()
				uploaderRegistry.Unlock()
				<-done
				uploaderRegistry.Lock()
				if uploaderRegistry.items[key] == shared {
					delete(uploaderRegistry.items, key)
				}
				uploaderRegistry.Unlock()
				continue
			}
			shared.refs++
			uploaderRegistry.Unlock()
			return &Handle{shared: shared, client: shared.client, site: site}, nil
		}

		client, err := newClient(normalized)
		if err != nil {
			uploaderRegistry.Unlock()
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		shared := &sharedUploader{client: client, key: key, refs: 1, cancel: cancel}
		uploaderRegistry.items[key] = shared
		uploaderRegistry.Unlock()
		go client.Run(ctx)
		return &Handle{shared: shared, client: client, site: site}, nil
	}
}

func uploaderKey(cfg Config) (string, error) {
	identity, err := json.Marshal(struct {
		URL           string
		Secret        string
		AgentID       string
		QueueSize     int
		BatchSize     int
		FlushInterval int64
	}{cfg.URL, cfg.Secret, cfg.AgentID, cfg.QueueSize, cfg.BatchSize, int64(cfg.FlushInterval)})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(identity)
	return hex.EncodeToString(sum[:]), nil
}

func (h *Handle) Record(event Event) {
	if h == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		h.client.dropped.Add(1)
		return
	}
	event.Site = h.site
	h.client.Record(event)
}

func (h *Handle) Snapshot() Stats {
	if h == nil {
		return Stats{}
	}
	return h.client.Snapshot()
}

func (h *Handle) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	var last bool
	uploaderRegistry.Lock()
	if uploaderRegistry.items[h.shared.key] == h.shared {
		h.shared.refs--
		if h.shared.refs == 0 {
			h.shared.closing = true
			h.shared.cancel()
			last = true
		}
	}
	uploaderRegistry.Unlock()
	h.mu.Unlock()

	if last {
		<-h.client.Done()
		uploaderRegistry.Lock()
		if uploaderRegistry.items[h.shared.key] == h.shared {
			delete(uploaderRegistry.items, h.shared.key)
		}
		uploaderRegistry.Unlock()
	}
}
