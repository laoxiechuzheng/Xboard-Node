package xray

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// linkState is the dispatcher's per-link bookkeeping of one user.
type linkState struct {
	indexed   int
	connCount int64
	aliveIPs  int
}

func linkStateOf(ld *LimitDispatcher, userID int) linkState {
	ld.mu.RLock()
	indexed := len(ld.links[userEmail(userID)])
	ld.mu.RUnlock()
	alive, _ := ld.GetConnectionState()
	return linkState{indexed: indexed, connCount: ld.connCount.Load(), aliveIPs: len(alive[userID])}
}

func waitReleased(t *testing.T, ld *LimitDispatcher, userID int, what string) {
	t.Helper()
	waitFor(t, what, func() bool { return linkStateOf(ld, userID) == linkState{} })
}

func closeUplink(t *testing.T, link *transport.Link) {
	t.Helper()
	// Exactly what task.Close(link.Writer) does in the trojan/vmess inbounds.
	if err := link.Writer.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
}

// downlinkInterrupted reports whether the link's downlink pipe was torn down
// (a live, empty downlink times out instead).
func downlinkInterrupted(link *transport.Link) bool {
	_, err := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(20 * time.Millisecond)
	return err != nil && err != buf.ErrReadTimeout
}

// A client that half-closed its upload keeps downloading: its Dispatch link
// stays indexed and counted, and a removal or CloseUUID still cuts it.
func TestLimitDispatcherHalfClosedPipeLinkIsCut(t *testing.T) {
	for _, mode := range []string{"removal", "CloseUUID"} {
		t.Run(mode, func(t *testing.T) {
			ld, _ := newRemovalTestDispatcher()
			installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1}, model.UserSpec{ID: 2, UUID: removalUUID2})
			link, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
			if err != nil {
				t.Fatal(err)
			}
			closeUplink(t, link)
			if got := linkStateOf(ld, 1); got != (linkState{indexed: 1, connCount: 1, aliveIPs: 1}) {
				t.Fatalf("half-closed link state = %+v, want still indexed and counted", got)
			}

			switch mode {
			case "removal":
				installUsers(ld, model.UserSpec{ID: 2, UUID: removalUUID2})
			case "CloseUUID":
				if n := ld.CloseUUID(removalUUID1); n != 1 {
					t.Fatalf("CloseUUID = %d, want 1", n)
				}
			}
			if !downlinkInterrupted(link) {
				t.Fatal("downlink of the half-closed link was not interrupted")
			}
			if got := linkStateOf(ld, 1); got != (linkState{}) {
				t.Fatalf("revoked link state = %+v, want released", got)
			}
		})
	}
}

// A Dispatch link ends when both directions have: the uplink Writer closed
// and the downlink drained (outbound closed it) or interrupted, in either
// order (mux sub-streams interrupt the downlink first).
func TestLimitDispatcherPipeLinkReleasedWhenBothEndsFinish(t *testing.T) {
	t.Run("uplink_then_downlink_EOF", func(t *testing.T) {
		ld, inner := newRemovalTestDispatcher()
		installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
		link, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
		if err != nil {
			t.Fatal(err)
		}
		closeUplink(t, link)
		inner.lastDownlink.Load().Close()
		if got := linkStateOf(ld, 1); got.indexed != 1 {
			t.Fatalf("link released before the inbound read the end of the downlink: %+v", got)
		}
		if _, err := link.Reader.ReadMultiBuffer(); err != io.EOF {
			t.Fatalf("downlink read = %v, want EOF", err)
		}
		if got := linkStateOf(ld, 1); got != (linkState{}) {
			t.Fatalf("finished link state = %+v, want released", got)
		}
	})
	t.Run("mux_order", func(t *testing.T) {
		ld, _ := newRemovalTestDispatcher()
		installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
		link, err := ld.Dispatch(vlessUserContext(t, 1, removalUUID1), removalDest)
		if err != nil {
			t.Fatal(err)
		}
		// mux Session.Close: interrupt the input, then close the output.
		common.Interrupt(link.Reader)
		if got := linkStateOf(ld, 1); got.indexed != 1 {
			t.Fatalf("link released while its uplink is open: %+v", got)
		}
		closeUplink(t, link)
		if got := linkStateOf(ld, 1); got != (linkState{}) {
			t.Fatalf("finished link state = %+v, want released", got)
		}
	})
}

// The dispatch context ending releases a link whose Writer is never closed
// (SS2022's sing bridge), also when it was already done at dispatch time.
func TestLimitDispatcherLinkReleasedWhenContextEnds(t *testing.T) {
	t.Run("cancelled_later", func(t *testing.T) {
		ld, _ := newRemovalTestDispatcher()
		installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
		ctx, cancel := context.WithCancel(vlessUserContext(t, 1, removalUUID1))
		defer cancel()
		if _, err := ld.Dispatch(ctx, removalDest); err != nil {
			t.Fatal(err)
		}
		if got := linkStateOf(ld, 1); got != (linkState{indexed: 1, connCount: 1, aliveIPs: 1}) {
			t.Fatalf("live link state = %+v", got)
		}
		cancel()
		waitReleased(t, ld, 1, "link release after its context ended")
	})
	t.Run("already_done", func(t *testing.T) {
		ld, _ := newRemovalTestDispatcher()
		installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1})
		ctx, cancel := context.WithCancel(vlessUserContext(t, 1, removalUUID1))
		cancel()
		if _, err := ld.Dispatch(ctx, removalDest); err != nil {
			t.Fatal(err)
		}
		waitReleased(t, ld, 1, "release of a link dispatched under a finished context")
	})
}

// Mux detaches an XUDP session from its link with ReturnAnError/Recover on
// the link's reader and may attach it to another mux connection later; the
// link is dispatched under a timeout-only context its outbound outlives.
// None of that ends the link: it stays indexed until it really ends.
func TestLimitDispatcherXUDPDetachKeepsLink(t *testing.T) {
	ld, _ := newRemovalTestDispatcher()
	installUsers(ld, model.UserSpec{ID: 1, UUID: removalUUID1}, model.UserSpec{ID: 2, UUID: removalUUID2})
	ctx, cancel := context.WithCancel(session.ContextWithTimeoutOnly(vlessUserContext(t, 1, removalUUID1), true))
	defer cancel()
	link, err := ld.Dispatch(ctx, removalDest)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := link.Reader.(io.Reader); ok {
		t.Fatal("the downlink reader must not look like an io.Reader to the sing bridge")
	}
	xudp, ok := link.Reader.(interface {
		ReturnAnError(error)
		Recover() error
	})
	if !ok {
		t.Fatal("the downlink reader lost the interface mux uses to detach XUDP sessions")
	}

	// The detach error is consumed by the old handler's read...
	xudp.ReturnAnError(io.EOF)
	if _, err := link.Reader.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("read after ReturnAnError = %v, want the injected EOF", err)
	}
	// ...or taken back by Recover.
	xudp.ReturnAnError(io.EOF)
	if err := xudp.Recover(); err != io.EOF {
		t.Fatalf("Recover = %v, want the injected EOF", err)
	}
	cancel() // the first mux connection ends
	time.Sleep(20 * time.Millisecond)
	if got := linkStateOf(ld, 1); got != (linkState{indexed: 1, connCount: 1, aliveIPs: 1}) {
		t.Fatalf("detached XUDP link state = %+v, want still indexed and counted", got)
	}
	if downlinkInterrupted(link) {
		t.Fatal("detaching the XUDP session tore down its downlink")
	}
	// The injected EOF did not end the downlink: with the uplink closed too
	// the link is still live, not released.
	closeUplink(t, link)
	if got := linkStateOf(ld, 1); got.indexed != 1 {
		t.Fatalf("an injected detach error counted as the end of the downlink: %+v", got)
	}

	installUsers(ld, model.UserSpec{ID: 2, UUID: removalUUID2})
	if !downlinkInterrupted(link) {
		t.Fatal("removal did not cut the detached XUDP link")
	}
	if got := linkStateOf(ld, 1); got != (linkState{}) {
		t.Fatalf("revoked XUDP link state = %+v, want released", got)
	}
}

// DispatchLink (VLESS Vision/REALITY) is released when its Writer, the
// downlink to the client, closes, as before.
func TestLimitDispatcherDispatchLinkReleasedOnWriterClose(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, nil)
	link := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !ld.trackLink(ctx, link, linkIdentity{email: email, sourceIP: "1.1.1.1", isTCP: true}, cancel) {
		t.Fatal("admitted link refused")
	}
	if link.Reader != (nopReader{}) {
		t.Fatal("DispatchLink's reader must be left alone")
	}
	if got := linkStateOf(ld, 1); got.indexed != 1 || got.connCount != 1 {
		t.Fatalf("live link state = %+v", got)
	}
	common.Close(link.Writer)
	if got := linkStateOf(ld, 1); got.indexed != 0 || got.connCount != 0 {
		t.Fatalf("closed link state = %+v, want released", got)
	}
}
