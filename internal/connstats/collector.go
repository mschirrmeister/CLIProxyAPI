// Package connstats records metadata about upstream connections: when they were
// dialed, how long TCP and TLS took, which requests used them, how many bytes
// they carried and why they were closed. The management API exposes the result
// so operators can see connection reuse per provider.
//
// Only metadata is kept. Headers, bodies, tokens and query strings are never
// recorded. Collection is off by default and costs one atomic load per dial and
// per request while disabled.
package connstats

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
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
)

// Conn is the exported snapshot of one upstream connection.
type Conn struct {
	ID             uint64     `json:"id"`
	Kind           string     `json:"kind"`
	Provider       string     `json:"provider,omitempty"`
	AuthID         string     `json:"auth_id,omitempty"`
	Addr           string     `json:"addr"`
	Local          string     `json:"local,omitempty"`
	Remote         string     `json:"remote,omitempty"`
	Proto          string     `json:"proto,omitempty"`
	TLSVersion     string     `json:"tls_version,omitempty"`
	ALPN           string     `json:"alpn,omitempty"`
	TLSResumed     bool       `json:"tls_resumed"`
	DialMs         float64    `json:"dial_ms"`
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
	ID          uint64     `json:"id"`
	ConnID      uint64     `json:"conn_id,omitempty"`
	Provider    string     `json:"provider,omitempty"`
	AuthID      string     `json:"auth_id,omitempty"`
	Method      string     `json:"method"`
	Host        string     `json:"host"`
	Path        string     `json:"path"`
	Status      int        `json:"status,omitempty"`
	Stream      bool       `json:"stream"`
	Reused      bool       `json:"reused"`
	WasIdle     bool       `json:"was_idle"`
	IdleMs      float64    `json:"idle_ms,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FirstByteMs float64    `json:"first_byte_ms,omitempty"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	Complete    bool       `json:"complete"`
	Error       string     `json:"error,omitempty"`
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
	requests   atomic.Int32
	inFlight   atomic.Int32
	lastEnd    atomic.Int64 // unix nanos of the last request end
	closed     atomic.Bool
	localKey   string    // guarded by c.mu
	pendingAt  time.Time // guarded by c.mu; local close waiting for its request to end
}

type requestState struct {
	c        *collector
	info     Request // guarded by c.mu
	conn     *connState
	finished bool
	tlsStart time.Time
	tlsMs    float64
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

func (c *collector) trimLocked() {
	if over := len(c.closed) - c.connHistory; over > 0 {
		c.closed = append(c.closed[:0:0], c.closed[over:]...)
	}
	if over := len(c.requests) - c.reqHistory; over > 0 {
		c.requests = append(c.requests[:0:0], c.requests[over:]...)
	}
}

func (c *collector) openConn(ctx context.Context, raw net.Conn, kind, addr string, dialStart time.Time, provider, authID string) *connState {
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
	if !dialStart.IsZero() {
		st.info.DialMs = durationMs(now.Sub(dialStart))
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

	if rec := requestFromContext(ctx); rec != nil {
		c.bind(rec, st)
	}
	return st
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
	if t := st.idleReadAt.Load(); t != 0 && inFlight == 0 && now.Sub(time.Unix(0, t)) <= idleReadWindow {
		return CloseServerIdle
	}
	if inFlight > 0 {
		return CloseProxyAborted
	}
	if st.requests.Load() == 0 {
		return CloseProxyUnused
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
		Method:    req.Method,
		StartedAt: time.Now(),
	}}
	if req.URL != nil {
		rec.info.Host = req.URL.Host
		rec.info.Path = req.URL.Path
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
	rec.info.Stream = strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
}

func (c *collector) firstByte(rec *requestState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec.info.FirstByteMs = durationMs(time.Since(rec.info.StartedAt))
}

func (c *collector) finishRequest(rec *requestState, complete bool, err error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec.finished {
		return
	}
	rec.finished = true
	rec.info.EndedAt = &now
	rec.info.Complete = complete
	if err != nil {
		rec.info.Error = err.Error()
	}
	if st := rec.conn; st != nil {
		st.lastEnd.Store(now.UnixNano())
		st.inFlight.Add(-1)
		if !st.pendingAt.IsZero() && st.inFlight.Load() == 0 {
			reason := CloseProxyAborted
			if complete && err == nil {
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
	for _, info := range c.closed {
		if !since.IsZero() && info.ClosedAt != nil && info.ClosedAt.Before(since) {
			continue
		}
		info.RequestIDs = append([]uint64(nil), info.RequestIDs...)
		out.Closed = append(out.Closed, info)
	}
	for _, rec := range c.requests {
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
		Complete:  true,
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
