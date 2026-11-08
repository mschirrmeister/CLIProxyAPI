package connstats

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// DialContextFunc matches net.Dialer.DialContext and http.Transport.DialContext.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// trackedConn wraps the raw (TCP-level) connection, below TLS, so byte counts
// match what is on the wire and Close/EOF show who ended the connection.
type trackedConn struct {
	net.Conn
	st *connState
}

// Track wraps a freshly dialed connection. kind is one of the Kind constants,
// addr the dial target and dialStart the time the dial began (zero if unknown).
// It returns conn unchanged when collection is off or conn is already tracked.
func Track(ctx context.Context, conn net.Conn, kind, addr string, dialStart time.Time) net.Conn {
	return track(ctx, conn, kind, addr, dialStart, "", "")
}

func track(ctx context.Context, conn net.Conn, kind, addr string, dialStart time.Time, provider, authID string) net.Conn {
	if conn == nil || !col.enabled.Load() {
		return conn
	}
	if _, ok := conn.(*trackedConn); ok {
		return conn
	}
	st := col.openConn(ctx, conn, kind, addr, dialStart, provider, authID)
	return &trackedConn{Conn: conn, st: st}
}

// NoteTLS records the TLS result for a connection returned by Track. It is a
// no-op for untracked connections.
func NoteTLS(conn net.Conn, handshakeStart time.Time, version uint16, alpn string, resumed bool) {
	tc, ok := conn.(*trackedConn)
	if !ok {
		return
	}
	tc.st.c.noteTLS(tc.st, handshakeStart, version, alpn, resumed)
}

// WrapDialContext returns a dial function that tracks every connection it
// creates. provider and authID label the connection when set; otherwise the
// labels come from the dial context (see Instrument).
func WrapDialContext(dial DialContextFunc, kind, provider, authID string) DialContextFunc {
	if dial == nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !col.enabled.Load() {
			return dial(ctx, network, addr)
		}
		start := time.Now()
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return conn, err
		}
		return track(ctx, conn, kind, addr, start, provider, authID), nil
	}
}

// NetConn returns the wrapped connection, like tls.Conn.NetConn, so callers
// can still reach the *net.TCPConn (for example to set TCP keepalive).
func (c *trackedConn) NetConn() net.Conn { return c.Conn }

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		now := time.Now().UnixNano()
		c.st.bytesIn.Add(int64(n))
		if prev := c.st.lastIO.Swap(now); now-prev >= int64(quietGap) {
			c.st.quietReadAt.Store(now)
		}
		if c.st.inFlight.Load() == 0 && c.st.requests.Load() > 0 {
			c.st.idleReadAt.Store(now)
		}
	}
	if err != nil {
		c.noteErr(err, true)
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.st.bytesOut.Add(int64(n))
		c.st.lastIO.Store(time.Now().UnixNano())
	}
	if err != nil {
		c.noteErr(err, false)
	}
	return n, err
}

func (c *trackedConn) Close() error {
	// Mark the close before the underlying Close so that read errors caused by
	// it are not mistaken for a remote close.
	c.st.c.finalize(c.st, originLocal, nil)
	return c.Conn.Close()
}

func (c *trackedConn) noteErr(err error, read bool) {
	if c.st.closed.Load() || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}
	if read && errors.Is(err, io.EOF) {
		c.st.c.finalize(c.st, originRemote, nil)
		return
	}
	c.st.c.finalize(c.st, originError, err)
}

func init() {
	hookDefaultTransport()
}

// hookDefaultTransport tracks connections of http.DefaultTransport and of every
// transport cloned from it afterwards (the standard transport family). The hook
// is installed during package initialization, before importers clone the
// default transport, and passes through untouched while collection is off.
func hookDefaultTransport() {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok || t == nil || t.DialContext == nil {
		return
	}
	t.DialContext = WrapDialContext(t.DialContext, KindStandard, "", "")
}
