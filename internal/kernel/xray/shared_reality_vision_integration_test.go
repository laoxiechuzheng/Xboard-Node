package xray_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/kernel"
)

type srCountedTLSStream struct {
	net.Conn
	upload   atomic.Int64
	download atomic.Int64
}

func (c *srCountedTLSStream) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.download.Add(int64(n))
	return n, err
}

func (c *srCountedTLSStream) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.upload.Add(int64(n))
	return n, err
}

func TestXraySharedRealityVisionTLSLargeTransfer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("run the real REALITY fixture on Linux")
	}
	f := srNewFixture(t)
	index := 7
	node := f.nodes[index]
	upload := bytes.Repeat([]byte("request-payload-"), 128*1024)
	download := bytes.Repeat([]byte("response-payload-"), 192*1024)
	gates := map[string]chan struct{}{"alias": make(chan struct{}), "original": make(chan struct{})}
	application := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(upload)+1)))
		if err != nil || !bytes.Equal(body, upload) {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}
		gate := gates[r.Header.Get("X-Transfer")]
		if gate == nil || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			http.Error(w, "invalid TLS transfer", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(download)))
		w.Write(download[:4096])
		w.(http.Flusher).Flush()
		select {
		case <-gate:
			w.Write(download[4096:])
		case <-r.Context().Done():
		}
	}))
	application.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	application.StartTLS()
	t.Cleanup(application.Close)
	trusted := x509.NewCertPool()
	trusted.AddCert(application.Certificate())
	spec := srCloneNode(t, node.spec)
	spec.CustomOutbounds[0].Settings["redirect"] = application.Listener.Addr().String()
	if err := node.kernel.Reload(spec, node.userList(), kernel.TLSCert{}); err != nil {
		t.Fatalf("configure a real TLS 1.3 application outlet: %v", err)
	}
	node.spec = spec
	for round, entry := range []string{"alias", "original"} {
		t.Run(entry, func(t *testing.T) {
			if !node.running {
				if err := node.kernel.Start(spec, node.userList(), kernel.TLSCert{}); err != nil {
					t.Fatal(err)
				}
				node.running = true
			}
			before, _, _, err := node.kernel.GetUserTraffic(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			baseline := before[node.primary.ID]
			defer func() {
				node.kernel.Stop()
				node.running = false
			}()
			gate := gates[entry]
			defer func() {
				select {
				case <-gate:
				default:
					close(gate)
				}
			}()
			options := f.options(index, node.primary)
			if entry == "original" {
				options = f.directOptions(index, node.primary)
			}
			options.targetPort = 16001 + round
			session := f.openSession(t, options, 45*time.Second)
			defer session.close()
			wire := &srCountedTLSStream{Conn: session.conn}
			secure := tls.Client(wire, &tls.Config{
				RootCAs: trusted, ServerName: "example.com", MinVersion: tls.VersionTLS13,
			})
			request, err := http.NewRequest(http.MethodPost, "https://example.com/transfer", bytes.NewReader(upload))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Transfer", entry)
			if err := request.Write(secure); err != nil {
				t.Fatalf("send TLS application payload: %v", err)
			}
			response, err := http.ReadResponse(bufio.NewReader(secure), request)
			if err != nil {
				t.Fatalf("read TLS application response: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || secure.ConnectionState().Version != tls.VersionTLS13 {
				t.Fatalf("unexpected TLS application status: %d", response.StatusCode)
			}
			prefix := make([]byte, 4096)
			if _, err := io.ReadFull(response.Body, prefix); err != nil || !bytes.Equal(prefix, download[:4096]) {
				t.Fatalf("TLS response prefix mismatch: %v", err)
			}
			f.assertSourceIP(t, index, node.primary.ID)
			close(gate)
			tail, err := io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(tail, download[4096:]) {
				t.Fatalf("large TLS payload lost or corrupted: bytes=%d, error=%v", len(tail), err)
			}
			up, down := wire.upload.Load(), wire.download.Load()
			if up <= int64(len(upload)) || down <= int64(len(download)) {
				t.Fatalf("application TLS wire counters missed TLS framing: up=%d down=%d", up, down)
			}
			// Native splice publishes its byte count when the copy finishes.
			// Stop the server before closing the client's REALITY transport.
			want := [2]int64{baseline[0] + up, baseline[1] + down}
			node.kernel.Stop()
			node.running = false
			deadline := time.Now().Add(srObservationTimeout)
			for {
				traffic, _, _, err := node.kernel.GetUserTraffic(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				actual := traffic[node.primary.ID]
				if actual == want {
					break
				}
				if actual[0] > want[0] || actual[1] > want[1] || time.Now().After(deadline) {
					t.Fatalf("final Vision TLS native payload bytes = %v, want exact %v", actual, want)
				}
				time.Sleep(10 * time.Millisecond)
			}
			f.assertFlux(t, index, node.primary, options.targetPort)
			session.close()
			final, _, _, err := node.kernel.GetUserTraffic(context.Background())
			if err != nil || final[node.primary.ID][0] < want[0] || final[node.primary.ID][1] < want[1] {
				t.Fatalf("Stop lost Vision TLS traffic: final=%v, minimum=%v, error=%v", final[node.primary.ID], want, err)
			}
			t.Logf("Vision %s retained source IP; exact inner TLS wire bytes upload=%d download=%d, cipher=%d", entry, up, down, secure.ConnectionState().CipherSuite)
		})
	}
}
