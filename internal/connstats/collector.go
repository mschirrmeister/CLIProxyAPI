// Package connstats records metadata about upstream connections: when they were
// dialed, how long TCP and TLS took, which requests used them, how many bytes
// they carried and why they were closed. The management API exposes the result
// so operators can see connection reuse per provider.
//
// Only metadata is kept. Bodies, tokens and query strings are never recorded;
// of the headers only the response Content-Type is kept. To tell a finished
// stream from an interrupted one, the last bytes read from an event stream are
// checked for a final-event marker and then discarded. Collection is off by
// default and costs one atomic load per dial and per request while disabled.
package connstats

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Connection kinds, one per transport family in the proxy.
const (
	// KindClaudeCode is the shared Claude Code uTLS transport for inference.
	KindClaudeCode = "claude_code_utls"
	// KindClaudeOAuth is the Claude OAuth control-plane uTLS transport.
	KindClaudeOAuth = "claude_oauth_utls"
	// KindChrome is the Chrome-fingerprint uTLS transport (one connection per request).
	KindChrome = "chrome_utls"
	// KindStandard covers net/http transports cloned from http.DefaultTransport.
	KindStandard = "standard"
	// KindWebSocket is an upstream WebSocket connection.
	KindWebSocket = "websocket"
)

// Close reasons.
const (
	CloseServerIdle         = "server_idle"
	CloseServerInRequest    = "server_during_request"
	CloseProxyAfterResponse = "proxy_after_response"
	CloseProxyPerRequest    = "proxy_per_request"
	CloseProxyIdle          = "proxy_idle"
	CloseProxyAborted       = "proxy_aborted"
	CloseProxyUnused        = "proxy_unused"
	CloseProxyClosed        = "proxy_closed"
	CloseWSLocal            = "ws_closed_local"
	CloseWSRemote           = "ws_closed_remote"
	CloseError              = "error"
)

const (
	defaultConnHistory    = 500
	defaultRequestHistory = 1000
	maxHistory            = 20000
	maxConnRequestIDs     = 50
	maxEvents             = 200

	// afterResponseWindow attributes a local close to the response that just
	// ended instead of to an idle timeout.
	afterResponseWindow = 250 * time.Millisecond
	// idleReadWindow: a local close shortly after unsolicited bytes arrived on an
	// idle connection is the transport reacting to a server close (TLS
	// close_notify, HTTP/2 GOAWAY) that the TLS layer above the wrapper consumed.
	idleReadWindow = time.Second
	// quietGap is how long a connection must be silent before arriving bytes
	// count as unsolicited. It lets server closes be recognized on connections
	// whose client is not instrumented and therefore has no request records.
	quietGap = time.Second
)

// Conn is the exported snapshot of one upstream connection.
type Conn struct {
	ID       uint64 `json:"id"`
	Kind     string `json:"kind"`
	Provider string `json:"provider,omitempty"`
	AuthID   string `json:"auth_id,omitempty"`
	// Addr is the upstream target (host:port), also when the connection runs
	// through a proxy.
	Addr string `json:"addr"`
	// Proxy is the proxy (host:port) the connection is tunneled through, empty
	// for a direct connection. Proxy credentials are never recorded.
	Proxy      string `json:"proxy,omitempty"`
	Local      string `json:"local,omitempty"`
	Remote     string `json:"remote,omitempty"`
	Proto      string `json:"proto,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	TLSResumed bool   `json:"tls_resumed"`
	// DialMs is the time until the connection reached the target, including
	// the proxy tunnel.
	DialMs float64 `json:"dial_ms"`
	// ProxyMs is the part of DialMs spent setting up the proxy tunnel (CONNECT,
	// and TLS to an https proxy), when it can be measured separately.
	ProxyMs        float64    `json:"proxy_ms,omitempty"`
	TLSMs          float64    `json:"tls_ms,omitempty"`
	OpenedAt       time.Time  `json:"opened_at"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	LastIO         time.Time  `json:"last_io"`
	LastRequestEnd *time.Time `json:"last_request_end,omitempty"`
	BytesIn        int64      `json:"bytes_in"`
	BytesOut       int64      `json:"bytes_out"`
	Requests       int        `json:"requests"`
	InFlight       int        `json:"in_flight"`
	CloseReason    string     `json:"close_reason,omitempty"`
	CloseError     string     `json:"close_error,omitempty"`
	RequestIDs     []uint64   `json:"request_ids,omitempty"`
}

// Request is the exported snapshot of one upstream HTTP request.
type Request struct {
	ID       uint64 `json:"id"`
	ConnID   uint64 `json:"conn_id,omitempty"`
	Provider string `json:"provider,omitempty"`
	AuthID   string `json:"auth_id,omitempty"`
	// Model is the model the client asked for, when the caller provides it.
	Model  string `json:"model,omitempty"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	// ContentType is the Content-Type of the upstream response.
	ContentType string `json:"content_type,omitempty"`
	// Encoding is the Content-Encoding of the response as the caller reads
	// it; empty when it is plain or the transport decompressed it.
	Encoding string `json:"encoding,omitempty"`
	// Stream reports an event stream: the request asked for one (Accept) or
	// the response is one (Content-Type).
	Stream      bool       `json:"stream"`
	Reused      bool       `json:"reused"`
	WasIdle     bool       `json:"was_idle"`
	IdleMs      float64    `json:"idle_ms,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FirstByteMs float64    `json:"first_byte_ms,omitempty"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	// End tells how the response ended, one of the End* constants. It is
	// empty while the request is in flight.
	End   string `json:"end,omitempty"`
	Error string `json:"error,omitempty"`
}

// How a request ended.
const (
	// EndEOF: the response body was read to the end.
	EndEOF = "eof"
	// EndAfterFinalEvent: the body was closed before its end, after the final
	// event of the stream had arrived ([DONE], message_stop,
	// response.completed, ...). Normal for streams.
	EndAfterFinalEvent = "after_final_event"
	// EndClosedEarly: the body was closed before its end and no final event
	// was seen.
	EndClosedEarly = "closed_early"
	// EndClosedUnchecked: a compressed event stream was closed before its
	// end. Its final event cannot be checked without decompressing it, so
	// whether it was complete is unknown.
	EndClosedUnchecked = "closed_unchecked"
	// EndCancelled: the request context was cancelled before the response
	// ended, before or after its headers arrived. Usually the client went
	// away; a deadline counts as EndError, not as a cancellation.
	EndCancelled = "cancelled"
	// EndReadError: reading the body failed, for example on a reset.
	EndReadError = "read_error"
	// EndError: the round trip failed before a response arrived.
	EndError = "error"
	// EndNoBody: the response has no body (101, 204, HEAD, ...).
	EndNoBody = "no_body"
	// EndSent: a WebSocket turn; the message was sent.
	EndSent = "sent"
)

// endedNormally reports whether a request end counts as a finished exchange.
// An unchecked stream counts as one: a connection closed after it is not
// called aborted without evidence.
func endedNormally(end string) bool {
	switch end {
	case EndEOF, EndAfterFinalEvent, EndClosedUnchecked, EndNoBody, EndSent:
		return true
	}
	return false
}

// ModelFunc returns the model a request was made for, read from its context.
type ModelFunc func(ctx context.Context) string

var modelFunc atomic.Pointer[ModelFunc]

// SetModelFunc installs the function that labels requests with their model.
// The executors register one that reads the model the client asked for.
func SetModelFunc(fn ModelFunc) {
	if fn == nil {
		modelFunc.Store(nil)
		return
	}
	modelFunc.Store(&fn)
}

func modelFromContext(ctx context.Context) string {
	fn := modelFunc.Load()
	if fn == nil || ctx == nil {
		return ""
	}
	return (*fn)(ctx)
}

// Event marks something that helps reading the timeline, such as a restart or
// a configuration reload.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// Totals are counters since process start (or since collection was enabled).
type Totals struct {
	ConnsOpened    int64            `json:"conns_opened"`
	ConnsClosed    int64            `json:"conns_closed"`
	Requests       int64            `json:"requests"`
	ReusedRequests int64            `json:"reused_requests"`
	BytesIn        int64            `json:"bytes_in"`
	BytesOut       int64            `json:"bytes_out"`
	CloseReasons   map[string]int64 `json:"close_reasons"`
}

// Snapshot is the management API payload.
type Snapshot struct {
	Enabled   bool      `json:"enabled"`
	Now       time.Time `json:"now"`
	StartedAt time.Time `json:"started_at"`
	Totals    Totals    `json:"totals"`
	Open      []Conn    `json:"open"`
	Closed    []Conn    `json:"closed"`
	Requests  []Request `json:"requests"`
	Events    []Event   `json:"events"`
}

type connState struct {
	c    *collector
	info Conn // guarded by c.mu

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	lastIO   atomic.Int64 // unix nanos
	// idleReadAt is set when bytes arrive while no request is in flight on a
	// connection that already served one.
	idleReadAt atomic.Int64
	// quietReadAt is set when bytes arrive after at least quietGap of silence.
	quietReadAt atomic.Int64
	requests    atomic.Int32
	inFlight    atomic.Int32
	lastEnd     atomic.Int64 // unix nanos of the last request end
	closed      atomic.Bool
	localKey    string    // guarded by c.mu
	pendingAt   time.Time // guarded by c.mu; local close waiting for its request to end
	// tunnelAfterDial: the transport sets up the proxy tunnel after the dial
	// (an HTTP proxy dialed by a standard transport), so it can be timed.
	tunnelAfterDial bool    // guarded by c.mu
	tcpDialMs       float64 // guarded by c.mu; the dial to the proxy alone
}

type requestState struct {
	c        *collector
	info     Request // guarded by c.mu
	conn     *connState
	finished bool
	tlsStart time.Time
	tlsMs    float64
	// target is the canonical host:port of the request URL.
	target string
	// dialing is the connection dialed for this request. Unlike conn it does
	// not move when the request ends up on another connection.
	dialing *connState
}

type collector struct {
	enabled atomic.Bool

	mu          sync.Mutex
	connHistory int
	reqHistory  int
	nextConnID  uint64
	nextReqID   uint64
	open        map[uint64]*connState
	byLocal     map[string]*connState
	closed      []Conn
	requests    []*requestState
	events      []Event
	totals      Totals
	started     time.Time
}

var col = newCollector()

func newCollector() *collector {
	return &collector{
		connHistory: defaultConnHistory,
		reqHistory:  defaultRequestHistory,
		open:        make(map[uint64]*connState),
		byLocal:     make(map[string]*connState),
		totals:      Totals{CloseReasons: make(map[string]int64)},
		started:     time.Now(),
	}
}

// Enabled reports whether collection is on.
func Enabled() bool { return col.enabled.Load() }

// Configure applies the configuration. reason is recorded as a timeline event
// ("startup", "config_reload") when it is not empty.
func Configure(enabled bool, connHistory, requestHistory int, reason string) {
	col.configure(enabled, connHistory, requestHistory, reason)
}

func (c *collector) configure(enabled bool, connHistory, requestHistory int, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connHistory = clampHistory(connHistory, defaultConnHistory)
	c.reqHistory = clampHistory(requestHistory, defaultRequestHistory)
	was := c.enabled.Swap(enabled)
	now := time.Now()
	if was != enabled {
		kind := "disabled"
		if enabled {
			kind = "enabled"
		}
		c.addEventLocked(Event{Time: now, Kind: kind})
	} else if enabled && reason != "" {
		c.addEventLocked(Event{Time: now, Kind: reason})
	}
	c.trimLocked()
}

func clampHistory(v, def int) int {
	if v <= 0 {
		return def
	}
	if v > maxHistory {
		return maxHistory
	}
	return v
}

func (c *collector) addEventLocked(ev Event) {
	c.events = append(c.events, ev)
	if over := len(c.events) - maxEvents; over > 0 {
		c.events = append(c.events[:0:0], c.events[over:]...)
	}
}

// trimLocked drops the oldest history entries. A list may run a quarter over
// its limit before it is cut back in one copy, so a full history is not copied
// on every new entry. Snapshots return at most the limit (see newest).
func (c *collector) trimLocked() {
	if len(c.closed) > c.connHistory+historySlack(c.connHistory) {
		c.closed = append(c.closed[:0:0], newest(c.closed, c.connHistory)...)
	}
	if len(c.requests) > c.reqHistory+historySlack(c.reqHistory) {
		c.requests = append(c.requests[:0:0], newest(c.requests, c.reqHistory)...)
	}
}

func historySlack(limit int) int { return limit/4 + 1 }

// newest returns the last limit entries of list.
func newest[T any](list []T, limit int) []T {
	if over := len(list) - limit; over > 0 {
		return list[over:]
	}
	return list
}

// openConn registers a dialed connection. via is the proxy the dialer tunnels
// through, when the dialer knows it. A standard transport dials an HTTP proxy
// itself, so a dial address that differs from the target of the request being
// dialed for is that proxy.
func (c *collector) openConn(ctx context.Context, raw net.Conn, kind, addr, via string, dialStart time.Time, provider, authID string) *connState {
	now := time.Now()
	st := &connState{c: c}
	st.lastIO.Store(now.UnixNano())
	lbl := labelsFromContext(ctx)
	if provider == "" {
		provider = lbl.provider
	}
	if authID == "" {
		authID = lbl.authID
	}
	st.info = Conn{
		Kind:     kind,
		Provider: provider,
		AuthID:   authID,
		Addr:     addr,
		OpenedAt: now,
		LastIO:   now,
	}
	if kind == KindWebSocket {
		st.info.Proto = "websocket"
	}
	rec := requestFromContext(ctx)
	switch {
	case via != "":
		st.info.Proxy = via
	case kind == KindStandard && rec != nil && rec.target != "" && !strings.EqualFold(rec.target, addr):
		st.info.Proxy = addr
		st.info.Addr = rec.target
		st.tunnelAfterDial = true
	}
	if !dialStart.IsZero() {
		st.info.DialMs = durationMs(now.Sub(dialStart))
		st.tcpDialMs = st.info.DialMs
	}
	if a := raw.LocalAddr(); a != nil {
		st.info.Local = a.String()
	}
	if a := raw.RemoteAddr(); a != nil {
		st.info.Remote = a.String()
	}

	c.mu.Lock()
	c.nextConnID++
	st.info.ID = c.nextConnID
	c.open[st.info.ID] = st
	if key := st.info.Local; key != "" && isIndexableAddr(raw.LocalAddr()) {
		if _, exists := c.byLocal[key]; !exists {
			c.byLocal[key] = st
			st.localKey = key
		}
	}
	c.totals.ConnsOpened++
	c.mu.Unlock()

	if rec != nil {
		c.mu.Lock()
		rec.dialing = st
		c.mu.Unlock()
		c.bind(rec, st)
	}
	return st
}

// tlsStarting marks the start of a TLS handshake for rec. On a connection that a
// standard transport tunnels through an HTTP proxy, the handshake with the
// target starts once the tunnel is up, so the time since the dial ended is the
// tunnel setup. It counts towards the dial: DialMs is the time to reach the
// target, whatever the path. With an https proxy the transport may first
// shake hands with the proxy; the last handshake, the target's, decides.
func (c *collector) tlsStarting(rec *requestState) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	rec.tlsStart = now
	st := rec.dialing
	if st == nil || !st.tunnelAfterDial {
		return
	}
	tunnel := durationMs(now.Sub(st.info.OpenedAt))
	st.info.ProxyMs = tunnel
	st.info.DialMs = st.tcpDialMs + tunnel
}

// canonicalAddr returns host:port for a request URL, with the scheme's default
// port when the URL has none, the way net/http dials it.
func canonicalAddr(u *url.URL) string {
	if u == nil || u.Host == "" {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		default:
			return ""
		}
	}
	return net.JoinHostPort(host, port)
}

func isIndexableAddr(a net.Addr) bool {
	if a == nil {
		return false
	}
	switch a.Network() {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		return true
	}
	return false
}

func (c *collector) noteTLS(st *connState, handshakeStart time.Time, version uint16, alpn string, resumed bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if version != 0 {
		st.info.TLSVersion = tls.VersionName(version)
	}
	st.info.ALPN = alpn
	st.info.TLSResumed = resumed
	if !handshakeStart.IsZero() {
		st.info.TLSMs = durationMs(now.Sub(handshakeStart))
	}
	if st.info.Proto == "" {
		st.info.Proto = protoFromALPN(alpn)
	}
}

func protoFromALPN(alpn string) string {
	if alpn == "h2" {
		return "h2"
	}
	return "http/1.1"
}

// pendingCloseLimit bounds how long a local close waits for its in-flight
// request to end before it is recorded as aborted.
const pendingCloseLimit = 2 * time.Second

// finalize records the end of a connection exactly once. A local close while a
// request is in flight waits for that request to end: net/http closes a
// non-reusable connection inside the final body read, before the reader sees
// EOF, so only the request outcome separates a finished response from an
// aborted one.
func (c *collector) finalize(st *connState, origin closeOrigin, err error) {
	if !st.closed.CompareAndSwap(false, true) {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if origin == originLocal && st.info.Kind != KindWebSocket && st.inFlight.Load() > 0 {
		st.pendingAt = now
		return
	}
	c.commitLocked(st, classify(st, origin, now), now, err)
}

func (c *collector) commitLocked(st *connState, reason string, closedAt time.Time, err error) {
	st.pendingAt = time.Time{}
	info := st.snapshotLocked()
	info.ClosedAt = &closedAt
	info.CloseReason = reason
	if err != nil && reason == CloseError {
		info.CloseError = err.Error()
	}
	delete(c.open, st.info.ID)
	if st.localKey != "" && c.byLocal[st.localKey] == st {
		delete(c.byLocal, st.localKey)
	}
	c.closed = append(c.closed, info)
	c.totals.ConnsClosed++
	c.totals.BytesIn += info.BytesIn
	c.totals.BytesOut += info.BytesOut
	c.totals.CloseReasons[reason]++
	c.trimLocked()
}

type closeOrigin int

const (
	originLocal closeOrigin = iota
	originRemote
	originError
)

func classify(st *connState, origin closeOrigin, now time.Time) string {
	ws := st.info.Kind == KindWebSocket // Kind is immutable after open
	inFlight := st.inFlight.Load()
	switch origin {
	case originError:
		return CloseError
	case originRemote:
		if ws {
			return CloseWSRemote
		}
		if inFlight > 0 {
			return CloseServerInRequest
		}
		return CloseServerIdle
	}
	if ws {
		return CloseWSLocal
	}
	recent := func(t int64) bool { return t != 0 && now.Sub(time.Unix(0, t)) <= idleReadWindow }
	if inFlight == 0 && recent(st.idleReadAt.Load()) {
		return CloseServerIdle
	}
	if inFlight > 0 {
		return CloseProxyAborted
	}
	if st.requests.Load() == 0 {
		// No request records: either unused, or used by a client that is not
		// instrumented. Fall back to the wire pattern alone.
		if recent(st.quietReadAt.Load()) {
			return CloseServerIdle
		}
		if st.bytesIn.Load() == 0 {
			return CloseProxyUnused
		}
		return CloseProxyClosed
	}
	if end := st.lastEnd.Load(); end != 0 && now.Sub(time.Unix(0, end)) <= afterResponseWindow {
		if st.info.Kind == KindChrome {
			return CloseProxyPerRequest
		}
		return CloseProxyAfterResponse
	}
	return CloseProxyIdle
}

// snapshotLocked copies the connection including live counters.
func (st *connState) snapshotLocked() Conn {
	info := st.info
	info.BytesIn = st.bytesIn.Load()
	info.BytesOut = st.bytesOut.Load()
	info.LastIO = time.Unix(0, st.lastIO.Load())
	info.Requests = int(st.requests.Load())
	info.InFlight = int(st.inFlight.Load())
	if end := st.lastEnd.Load(); end != 0 {
		t := time.Unix(0, end)
		info.LastRequestEnd = &t
	}
	info.RequestIDs = append([]uint64(nil), st.info.RequestIDs...)
	return info
}

func (c *collector) startRequest(provider, authID string, req *http.Request) *requestState {
	rec := &requestState{c: c, info: Request{
		Provider:  provider,
		AuthID:    authID,
		Model:     modelFromContext(req.Context()),
		Method:    req.Method,
		Stream:    isEventStream(req.Header.Get("Accept")),
		StartedAt: time.Now(),
	}}
	if req.URL != nil {
		rec.info.Host = req.URL.Host
		rec.info.Path = req.URL.Path
		rec.target = canonicalAddr(req.URL)
	}
	c.mu.Lock()
	c.nextReqID++
	rec.info.ID = c.nextReqID
	c.requests = append(c.requests, rec)
	c.totals.Requests++
	c.trimLocked()
	c.mu.Unlock()
	return rec
}

// bind attaches a request to a connection. A request bound tentatively at dial
// time moves when GotConn reports a different connection.
func (c *collector) bind(rec *requestState, st *connState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec.conn == st || rec.finished {
		return
	}
	if old := rec.conn; old != nil {
		old.requests.Add(-1)
		old.inFlight.Add(-1)
		old.info.RequestIDs = removeID(old.info.RequestIDs, rec.info.ID)
	}
	rec.conn = st
	rec.info.ConnID = st.info.ID
	st.requests.Add(1)
	st.inFlight.Add(1)
	st.info.RequestIDs = append(st.info.RequestIDs, rec.info.ID)
	if over := len(st.info.RequestIDs) - maxConnRequestIDs; over > 0 {
		st.info.RequestIDs = append(st.info.RequestIDs[:0:0], st.info.RequestIDs[over:]...)
	}
	if rec.tlsMs > 0 && st.info.TLSMs == 0 {
		st.info.TLSMs = rec.tlsMs
	}
}

func removeID(ids []uint64, id uint64) []uint64 {
	for i, v := range ids {
		if v == id {
			return append(ids[:i:i], ids[i+1:]...)
		}
	}
	return ids
}

func (c *collector) gotConn(rec *requestState, info httptrace.GotConnInfo) {
	if info.Conn == nil {
		return
	}
	var st *connState
	if a := info.Conn.LocalAddr(); a != nil && isIndexableAddr(a) {
		c.mu.Lock()
		st = c.byLocal[a.String()]
		c.mu.Unlock()
	}
	c.mu.Lock()
	rec.info.Reused = info.Reused
	rec.info.WasIdle = info.WasIdle
	if info.WasIdle {
		rec.info.IdleMs = durationMs(info.IdleTime)
	}
	if info.Reused {
		c.totals.ReusedRequests++
	}
	c.mu.Unlock()
	if st == nil {
		return
	}
	c.bind(rec, st)
	// A request bound at dial time was bound before its TLS handshake ended;
	// take the handshake time now that it is known.
	c.mu.Lock()
	if rec.tlsMs > 0 && st.info.TLSMs == 0 {
		st.info.TLSMs = rec.tlsMs
	}
	c.mu.Unlock()
	if cs, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		c.mu.Lock()
		if st.info.TLSVersion == "" {
			state := cs.ConnectionState()
			st.info.TLSVersion = tls.VersionName(state.Version)
			st.info.ALPN = state.NegotiatedProtocol
			st.info.TLSResumed = state.DidResume
			st.info.Proto = protoFromALPN(state.NegotiatedProtocol)
		}
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		if st.info.Proto == "" {
			st.info.Proto = "http/1.1"
		}
		c.mu.Unlock()
	}
}

func (c *collector) gotResponse(rec *requestState, resp *http.Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec.info.Status = resp.StatusCode
	rec.info.ContentType = resp.Header.Get("Content-Type")
	if enc := resp.Header.Get("Content-Encoding"); !isIdentityEncoding(enc) {
		rec.info.Encoding = strings.ToLower(strings.TrimSpace(enc))
	}
	if isEventStream(rec.info.ContentType) {
		rec.info.Stream = true
	}
}

// isEventStream reports whether an Accept or Content-Type value names
// text/event-stream.
func isEventStream(value string) bool {
	return strings.Contains(strings.ToLower(value), "text/event-stream")
}

func (c *collector) firstByte(rec *requestState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec.info.FirstByteMs = durationMs(time.Since(rec.info.StartedAt))
}

func (c *collector) finishRequest(rec *requestState, end string, err error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec.finished {
		return
	}
	rec.finished = true
	rec.info.EndedAt = &now
	rec.info.End = end
	if err != nil {
		rec.info.Error = err.Error()
	}
	if st := rec.conn; st != nil {
		st.lastEnd.Store(now.UnixNano())
		st.inFlight.Add(-1)
		if !st.pendingAt.IsZero() && st.inFlight.Load() == 0 {
			reason := CloseProxyAborted
			if endedNormally(end) && err == nil {
				reason = CloseProxyAfterResponse
				if st.info.Kind == KindChrome {
					reason = CloseProxyPerRequest
				}
			}
			c.commitLocked(st, reason, st.pendingAt, nil)
		}
	}
}

// SnapshotSince returns the current state. Closed connections and requests
// that ended before since are left out; the zero time returns everything kept.
func SnapshotSince(since time.Time) Snapshot { return col.snapshot(since) }

func (c *collector) snapshot(since time.Time) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	var stale []*connState
	for _, st := range c.open {
		if !st.pendingAt.IsZero() && now.Sub(st.pendingAt) > pendingCloseLimit {
			stale = append(stale, st)
		}
	}
	for _, st := range stale {
		c.commitLocked(st, CloseProxyAborted, st.pendingAt, nil)
	}
	out := Snapshot{
		Enabled:   c.enabled.Load(),
		Now:       now,
		StartedAt: c.started,
		Totals:    c.totals,
		Open:      make([]Conn, 0, len(c.open)),
		Closed:    make([]Conn, 0, len(c.closed)),
		Requests:  make([]Request, 0, len(c.requests)),
		Events:    append([]Event(nil), c.events...),
	}
	out.Totals.CloseReasons = make(map[string]int64, len(c.totals.CloseReasons))
	for k, v := range c.totals.CloseReasons {
		out.Totals.CloseReasons[k] = v
	}
	for _, st := range c.open {
		info := st.snapshotLocked()
		out.Open = append(out.Open, info)
		out.Totals.BytesIn += info.BytesIn
		out.Totals.BytesOut += info.BytesOut
	}
	sort.Slice(out.Open, func(i, j int) bool { return out.Open[i].ID < out.Open[j].ID })
	for _, info := range newest(c.closed, c.connHistory) {
		if !since.IsZero() && info.ClosedAt != nil && info.ClosedAt.Before(since) {
			continue
		}
		info.RequestIDs = append([]uint64(nil), info.RequestIDs...)
		out.Closed = append(out.Closed, info)
	}
	for _, rec := range newest(c.requests, c.reqHistory) {
		if !since.IsZero() && rec.info.EndedAt != nil && rec.info.EndedAt.Before(since) {
			continue
		}
		out.Requests = append(out.Requests, rec.info)
	}
	return out
}

func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// reset clears all state. Tests use it.
func reset() {
	enabled := col.enabled.Load()
	col = newCollector()
	col.enabled.Store(enabled)
}

// NoteWebsocketTurn records one upstream message (a turn) sent on a tracked
// WebSocket connection, identified by its local address. WebSocket traffic
// does not pass through http.RoundTripper, so this is how turns appear as
// requests on the connection.
func NoteWebsocketTurn(local net.Addr) {
	if local == nil || !col.enabled.Load() || !isIndexableAddr(local) {
		return
	}
	col.websocketTurn(local.String())
}

func (c *collector) websocketTurn(key string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.byLocal[key]
	if st == nil || st.info.Kind != KindWebSocket {
		return
	}
	reused := st.requests.Load() > 0
	c.nextReqID++
	rec := &requestState{c: c, conn: st, finished: true, info: Request{
		ID:        c.nextReqID,
		ConnID:    st.info.ID,
		Provider:  st.info.Provider,
		AuthID:    st.info.AuthID,
		Method:    "WS",
		Host:      st.info.Addr,
		StartedAt: now,
		EndedAt:   &now,
		End:       EndSent,
		Reused:    reused,
		Stream:    true,
	}}
	c.requests = append(c.requests, rec)
	c.totals.Requests++
	if reused {
		c.totals.ReusedRequests++
	}
	st.requests.Add(1)
	st.lastEnd.Store(now.UnixNano())
	st.info.RequestIDs = append(st.info.RequestIDs, rec.info.ID)
	if over := len(st.info.RequestIDs) - maxConnRequestIDs; over > 0 {
		st.info.RequestIDs = append(st.info.RequestIDs[:0:0], st.info.RequestIDs[over:]...)
	}
	c.trimLocked()
}
