package helps

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/connstats"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// fixedDialer sends every dial to one listener, so requests can use the real
// upstream host name (and its TLS server name) against a loopback server.
type fixedDialer struct{ addr string }

func (d fixedDialer) Dial(network, _ string) (net.Conn, error) {
	return net.Dial(network, d.addr)
}

func (d fixedDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.addr)
}

func connsForAuth(snap connstats.Snapshot, authID string) []connstats.Conn {
	var out []connstats.Conn
	for _, c := range append(append([]connstats.Conn(nil), snap.Open...), snap.Closed...) {
		if c.AuthID == authID {
			out = append(out, c)
		}
	}
	return out
}

// TestConnStatsClaudeCodeTransportRecordsReuse sends streamed requests through
// the Claude Code uTLS transport and checks that the connection view sees one
// pooled connection with its TLS details and every request on it.
func TestConnStatsClaudeCodeTransportRecordsReuse(t *testing.T) {
	connstats.Configure(true, 0, 0, "")
	t.Cleanup(func() { connstats.Configure(false, 0, 0, "") })

	certificate := newResumptionTestCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	srv.TLS = &gotls.Config{Certificates: []gotls.Certificate{certificate}}
	srv.StartTLS()
	defer srv.Close()

	transport := newClaudeCodeRoundTripperForDialerAndRoots(fixedDialer{addr: srv.Listener.Addr().String()}, roots)
	defer transport.CloseIdleConnections()
	// The collector is process-wide, so -count>1 runs need their own label.
	auth := &cliproxyauth.Auth{ID: fmt.Sprintf("connstats-claude-test-%d", time.Now().UnixNano()), Provider: "claude"}
	client := InstrumentConnStats(context.Background(), &http.Client{Transport: transport}, auth)

	for i := 0; i < 3; i++ {
		req, errReq := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{"stream":true}`))
		if errReq != nil {
			t.Fatal(errReq)
		}
		resp, errDo := client.Do(req)
		if errDo != nil {
			t.Fatalf("request %d: %v", i, errDo)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	snap := connstats.SnapshotSince(time.Time{})
	conns := connsForAuth(snap, auth.ID)
	if len(conns) != 1 {
		t.Fatalf("connections = %d, want 1: %+v", len(conns), conns)
	}
	c := conns[0]
	if c.Kind != connstats.KindClaudeCode || c.Provider != "claude" || c.Requests != 3 {
		t.Fatalf("conn = %+v", c)
	}
	if c.TLSVersion != "TLS 1.3" || c.ALPN != "http/1.1" || c.Proto != "http/1.1" || c.TLSMs <= 0 {
		t.Fatalf("TLS details = version %q alpn %q proto %q tls_ms %v", c.TLSVersion, c.ALPN, c.Proto, c.TLSMs)
	}
	var reused, streamed int
	for _, r := range snap.Requests {
		if r.AuthID != auth.ID {
			continue
		}
		if r.Reused {
			reused++
		}
		if r.Stream && r.End == connstats.EndEOF {
			streamed++
		}
	}
	if reused != 2 || streamed != 3 {
		t.Fatalf("reused=%d complete streams=%d, want 2 and 3", reused, streamed)
	}
}

func TestStampProxyKeepAliveKeepsTrackedConn(t *testing.T) {
	connstats.Configure(true, 0, 0, "")
	t.Cleanup(func() { connstats.Configure(false, 0, 0, "") })
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatal(errListen)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		if conn, errAccept := listener.Accept(); errAccept == nil {
			_ = conn.Close()
		}
	}()
	raw, errDial := net.Dial("tcp", listener.Addr().String())
	if errDial != nil {
		t.Fatal(errDial)
	}
	tracked := connstats.Track(context.Background(), raw, connstats.KindStandard, listener.Addr().String(), time.Now())
	defer func() { _ = tracked.Close() }()
	if tracked == raw {
		t.Fatal("connection was not tracked")
	}
	if got := stampProxyKeepAlive(tracked); got != tracked {
		t.Fatal("stampProxyKeepAlive replaced the tracked connection")
	}
}
