package connstats

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// enable gives each test a fresh, enabled collector.
func enable(t *testing.T) {
	t.Helper()
	reset()
	Configure(true, 0, 0, "")
	t.Cleanup(func() {
		Configure(false, 0, 0, "")
		reset()
	})
}

func trackedTransport() *http.Transport {
	return &http.Transport{
		DialContext:       WrapDialContext((&net.Dialer{}).DialContext, KindStandard, "", ""),
		ForceAttemptHTTP2: false,
	}
}

func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
}

// waitClosed waits for the asynchronous close of n connections.
func waitClosed(t *testing.T, n int) Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap := SnapshotSince(time.Time{})
		if len(snap.Closed) >= n {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d closed connections, have %d (open %d)", n, len(snap.Closed), len(snap.Open))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDisabledIsPassthrough(t *testing.T) {
	reset()
	Configure(false, 0, 0, "")
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if got := Track(context.Background(), a, KindStandard, "x:1", time.Now()); got != a {
		t.Fatal("Track wrapped a connection while disabled")
	}
	client := &http.Client{}
	if got := Instrument(context.Background(), client, "p", "a"); got != client {
		t.Fatal("Instrument wrapped a client while disabled")
	}
}

func TestReuseIsRecordedAndServerCloseIsRemote(t *testing.T) {
	enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 1000))
	}))
	defer srv.Close()

	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "claude", "auth-1")
	get(t, client, srv.URL+"/a?key=secret")
	get(t, client, srv.URL+"/b")

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 {
		t.Fatalf("open connections = %d, want 1", len(snap.Open))
	}
	conn := snap.Open[0]
	if conn.Requests != 2 || conn.InFlight != 0 {
		t.Fatalf("requests=%d in_flight=%d, want 2 and 0", conn.Requests, conn.InFlight)
	}
	if conn.Provider != "claude" || conn.AuthID != "auth-1" || conn.Kind != KindStandard {
		t.Fatalf("labels = %q/%q/%q", conn.Provider, conn.AuthID, conn.Kind)
	}
	if conn.BytesIn < 2000 || conn.BytesOut == 0 {
		t.Fatalf("bytes in=%d out=%d, want at least both bodies in", conn.BytesIn, conn.BytesOut)
	}
	if len(snap.Requests) != 2 || snap.Requests[0].Reused || !snap.Requests[1].Reused {
		t.Fatalf("reuse flags wrong: %+v", snap.Requests)
	}
	for _, r := range snap.Requests {
		if r.ConnID != conn.ID || r.End != EndEOF || r.Status != http.StatusOK {
			t.Fatalf("request not linked or incomplete: %+v", r)
		}
		if strings.Contains(r.Path, "secret") {
			t.Fatalf("query string recorded: %q", r.Path)
		}
	}
	if snap.Totals.ReusedRequests != 1 {
		t.Fatalf("reused total = %d, want 1", snap.Totals.ReusedRequests)
	}

	srv.CloseClientConnections()
	snap = waitClosed(t, 1)
	if got := snap.Closed[0].CloseReason; got != CloseServerIdle {
		t.Fatalf("close reason = %q, want %q", got, CloseServerIdle)
	}
}

func TestTLSCloseNotifyCountsAsServerClose(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr := trackedTransport()
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	client := Instrument(context.Background(), &http.Client{Transport: tr}, "claude", "a")
	get(t, client, srv.URL)

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 || snap.Open[0].TLSVersion == "" || snap.Open[0].Proto != "http/1.1" {
		t.Fatalf("TLS details missing: %+v", snap.Open)
	}
	// The TLS layer consumes close_notify and the transport closes the
	// connection locally; it must still count as a server close.
	srv.CloseClientConnections()
	snap = waitClosed(t, 1)
	if got := snap.Closed[0].CloseReason; got != CloseServerIdle {
		t.Fatalf("close reason = %q, want %q", got, CloseServerIdle)
	}
}

func TestNoKeepAliveIsProxyAfterResponse(t *testing.T) {
	enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr := trackedTransport()
	tr.DisableKeepAlives = true
	client := Instrument(context.Background(), &http.Client{Transport: tr}, "p", "a")
	get(t, client, srv.URL)
	get(t, client, srv.URL)

	snap := waitClosed(t, 2)
	for _, c := range snap.Closed {
		if c.CloseReason != CloseProxyAfterResponse || c.Requests != 1 {
			t.Fatalf("conn %d: reason=%q requests=%d", c.ID, c.CloseReason, c.Requests)
		}
	}
}

func TestEarlyBodyCloseIsIncomplete(t *testing.T) {
	enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, strings.Repeat("data: x\n\n", 5000))
	}))
	defer srv.Close()
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_, _ = resp.Body.Read(buf)
	_ = resp.Body.Close()

	snap := waitClosed(t, 1)
	r := snap.Requests[0]
	if r.End != EndClosedEarly || !r.Stream || r.EndedAt == nil {
		t.Fatalf("request = %+v, want ended early, stream", r)
	}
	if got := snap.Closed[0].CloseReason; got != CloseProxyAfterResponse {
		t.Fatalf("close reason = %q, want %q", got, CloseProxyAfterResponse)
	}
}

// A round tripper that dials per request without net/http (like the Chrome
// HTTP/2 path) gets its request bound through the dial context.
type dialingRoundTripper struct{ peers chan net.Conn }

func (d *dialingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	a, b := net.Pipe()
	d.peers <- b
	conn := Track(req.Context(), a, KindChrome, "chatgpt.com:443", time.Now())
	body := &closeConnBody{ReadCloser: io.NopCloser(strings.NewReader("ok")), conn: conn}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body, Request: req}, nil
}

type closeConnBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *closeConnBody) Close() error {
	_ = b.ReadCloser.Close()
	return b.conn.Close()
}

func TestDialContextBindsRequestWithoutGotConn(t *testing.T) {
	enable(t)
	rt := &dialingRoundTripper{peers: make(chan net.Conn, 1)}
	client := Instrument(context.Background(), &http.Client{Transport: rt}, "codex", "c1")
	get(t, client, "https://chatgpt.com/backend-api/codex/responses")
	_ = (<-rt.peers).Close()

	snap := waitClosed(t, 1)
	c := snap.Closed[0]
	if c.Requests != 1 || c.Provider != "codex" || c.CloseReason != CloseProxyPerRequest {
		t.Fatalf("conn = %+v", c)
	}
	if snap.Requests[0].ConnID != c.ID {
		t.Fatalf("request conn = %d, want %d", snap.Requests[0].ConnID, c.ID)
	}
}

func TestClassify(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }
	cases := []struct {
		name     string
		kind     string
		origin   closeOrigin
		requests int32
		inFlight int32
		lastEnd  int64
		idleRead int64
		want     string
	}{
		{"error", KindStandard, originError, 1, 0, 0, 0, CloseError},
		{"remote idle", KindStandard, originRemote, 1, 0, ago(time.Minute), 0, CloseServerIdle},
		{"remote in request", KindStandard, originRemote, 1, 1, 0, 0, CloseServerInRequest},
		{"ws local", KindWebSocket, originLocal, 0, 0, 0, 0, CloseWSLocal},
		{"ws remote", KindWebSocket, originRemote, 0, 0, 0, 0, CloseWSRemote},
		{"close after idle read", KindClaudeCode, originLocal, 3, 0, ago(400 * time.Second), ago(2 * time.Millisecond), CloseServerIdle},
		{"stale idle read", KindClaudeCode, originLocal, 3, 0, ago(400 * time.Second), ago(time.Minute), CloseProxyIdle},
		{"aborted", KindClaudeCode, originLocal, 1, 1, 0, 0, CloseProxyAborted},
		{"unused", KindStandard, originLocal, 0, 0, 0, 0, CloseProxyUnused},
		{"no request info", KindStandard, originLocal, -1, 0, 0, 0, CloseProxyClosed},
		{"after response", KindClaudeCode, originLocal, 1, 0, ago(time.Millisecond), 0, CloseProxyAfterResponse},
		{"per request", KindChrome, originLocal, 1, 0, ago(time.Millisecond), 0, CloseProxyPerRequest},
		{"idle timeout", KindStandard, originLocal, 1, 0, ago(90 * time.Second), 0, CloseProxyIdle},
	}
	for _, tc := range cases {
		st := &connState{info: Conn{Kind: tc.kind}}
		if tc.requests < 0 { // uninstrumented client: traffic but no request records
			tc.requests = 0
			st.bytesIn.Store(5000)
		}
		st.requests.Store(tc.requests)
		st.inFlight.Store(tc.inFlight)
		st.lastEnd.Store(tc.lastEnd)
		st.idleReadAt.Store(tc.idleRead)
		if got := classify(st, tc.origin, now); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHistoryIsBoundedAndSinceFilters(t *testing.T) {
	enable(t)
	Configure(true, 3, 4, "")
	for i := 0; i < 6; i++ {
		a, b := net.Pipe()
		c := Track(context.Background(), a, KindStandard, "x:1", time.Time{})
		_ = c.Close()
		_ = b.Close()
	}
	snap := SnapshotSince(time.Time{})
	if len(snap.Closed) != 3 {
		t.Fatalf("closed = %d, want 3", len(snap.Closed))
	}
	if snap.Totals.ConnsClosed != 6 || snap.Totals.CloseReasons[CloseProxyUnused] != 6 {
		t.Fatalf("totals = %+v", snap.Totals)
	}
	if got := SnapshotSince(time.Now().Add(time.Second)); len(got.Closed) != 0 {
		t.Fatalf("since filter kept %d connections", len(got.Closed))
	}
}

func TestEventsRecordToggleAndReload(t *testing.T) {
	reset()
	Configure(true, 0, 0, "startup")
	Configure(true, 0, 0, "config_reload")
	Configure(false, 0, 0, "config_reload")
	defer reset()
	snap := SnapshotSince(time.Time{})
	var kinds []string
	for _, e := range snap.Events {
		kinds = append(kinds, e.Kind)
	}
	if got := strings.Join(kinds, ","); got != "enabled,config_reload,disabled" {
		t.Fatalf("events = %s", got)
	}
}

func TestNetConnUnwrap(t *testing.T) {
	enable(t)
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := Track(context.Background(), a, KindStandard, "x:1", time.Time{})
	defer func() { _ = c.Close() }()
	u, ok := c.(interface{ NetConn() net.Conn })
	if !ok || u.NetConn() != a {
		t.Fatal("NetConn does not return the wrapped connection")
	}
}

func TestLocalCloseDuringRequestWaitsForOutcome(t *testing.T) {
	for _, tc := range []struct {
		end  string
		want string
	}{{EndEOF, CloseProxyAfterResponse}, {EndAfterFinalEvent, CloseProxyAfterResponse}, {EndClosedEarly, CloseProxyAborted}, {EndCancelled, CloseProxyAborted}} {
		enable(t)
		a, b := net.Pipe()
		conn := Track(context.Background(), a, KindClaudeCode, "api.anthropic.com:443", time.Time{})
		st := conn.(*trackedConn).st
		req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
		rec := col.startRequest("claude", "a", req)
		col.bind(rec, st)
		_ = conn.Close()
		_ = b.Close()
		if snap := SnapshotSince(time.Time{}); len(snap.Open) != 1 || len(snap.Closed) != 0 {
			t.Fatalf("close recorded before the request ended: open=%d closed=%d", len(snap.Open), len(snap.Closed))
		}
		col.finishRequest(rec, tc.end, nil)
		snap := SnapshotSince(time.Time{})
		if len(snap.Closed) != 1 || snap.Closed[0].CloseReason != tc.want {
			t.Fatalf("end=%s: closed=%+v, want reason %q", tc.end, snap.Closed, tc.want)
		}
	}
}

func TestWebsocketTurnsCountAsRequests(t *testing.T) {
	enable(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		if c, errAccept := listener.Accept(); errAccept == nil {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	dial := WrapDialContext((&net.Dialer{}).DialContext, KindWebSocket, "codex", "c1")
	conn, err := dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		NoteWebsocketTurn(conn.LocalAddr())
	}
	_ = conn.Close()
	snap := SnapshotSince(time.Time{})
	if len(snap.Closed) != 1 || snap.Closed[0].Requests != 3 || snap.Closed[0].CloseReason != CloseWSLocal {
		t.Fatalf("closed = %+v", snap.Closed)
	}
	if snap.Totals.Requests != 3 || snap.Totals.ReusedRequests != 2 {
		t.Fatalf("totals = %+v", snap.Totals)
	}
	// A turn on an unknown or non-WebSocket address is ignored.
	NoteWebsocketTurn(listener.Addr())
	if got := SnapshotSince(time.Time{}).Totals.Requests; got != 3 {
		t.Fatalf("requests after unknown address = %d", got)
	}
}

// A client that is not instrumented leaves no request records; a server close
// on its idle connection must still be recognized from the wire pattern.
func TestServerCloseWithoutRequestRecords(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr := trackedTransport()
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	get(t, &http.Client{Transport: tr}, srv.URL) // not instrumented
	// Age the connection so the close arrives after a quiet period, without a
	// wall-clock sleep.
	col.mu.Lock()
	for _, st := range col.open {
		st.lastIO.Store(time.Now().Add(-2 * quietGap).UnixNano())
	}
	col.mu.Unlock()
	srv.CloseClientConnections()
	snap := waitClosed(t, 1)
	if c := snap.Closed[0]; c.Requests != 0 || c.CloseReason != CloseServerIdle {
		t.Fatalf("conn = requests %d reason %q, want 0 and %q", c.Requests, c.CloseReason, CloseServerIdle)
	}
}
