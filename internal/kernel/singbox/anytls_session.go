package singbox

import (
	"reflect"
	"unsafe"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common"
)

// anytlsStreamSession is the offset of session.Stream's unexported parent
// session pointer, or -1 when the pinned sing-anytls layout has changed.
var anytlsStreamSession = func() uintptr {
	field, ok := reflect.TypeOf((*session.Stream)(nil)).Elem().FieldByName("sess")
	if !ok || field.Type != reflect.TypeOf((*session.Session)(nil)) {
		return ^uintptr(0)
	}
	return field.Offset
}()

// closeAnyTLSSession closes the AnyTLS session that carries conn, if conn is
// (or wraps) an AnyTLS stream, and reports whether it did.
//
// AnyTLS authenticates once per TLS connection and then serves any number of
// streams under that identity (sing-anytls Service.NewConnection), and the
// client keeps the authenticated session pooled for new streams. Closing only
// a removed user's streams would leave that session usable; closing the
// session makes the client reconnect and authenticate again. sing-anytls does
// not export a stream's session, so its pointer is read at the field offset
// checked above; if the layout no longer matches, only the stream is closed.
func closeAnyTLSSession(conn any) bool {
	if anytlsStreamSession == ^uintptr(0) {
		return false
	}
	stream, ok := common.Cast[*session.Stream](conn)
	if !ok || stream == nil {
		return false
	}
	sess := *(**session.Session)(unsafe.Add(unsafe.Pointer(stream), anytlsStreamSession))
	if sess == nil {
		return false
	}
	_ = sess.Close()
	return true
}
