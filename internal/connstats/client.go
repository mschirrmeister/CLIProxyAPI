package connstats

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type labelsKey struct{}
type requestKey struct{}
type suppressKey struct{}

type labels struct {
	provider string
	authID   string
}

func labelsFromContext(ctx context.Context) labels {
	if ctx == nil {
		return labels{}
	}
	lbl, _ := ctx.Value(labelsKey{}).(labels)
	return lbl
}

func requestFromContext(ctx context.Context) *requestState {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(requestKey{}).(*requestState)
	return rec
}

// Suppress marks ctx so that Instrument leaves clients built with it alone.
// Use it for an inner client constructor whose result the caller still
// inspects or rewraps, and instrument the outer client instead.
func Suppress(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, suppressKey{}, true)
}

// Instrument returns a copy of client whose requests are recorded and linked to
// the connections they use. provider and authID label the requests and any
// connection dialed for them. The client is returned unchanged when
// collection is off, ctx is suppressed, or it is already instrumented.
func Instrument(ctx context.Context, client *http.Client, provider, authID string) *http.Client {
	if client == nil || !col.enabled.Load() {
		return client
	}
	if ctx != nil && ctx.Value(suppressKey{}) != nil {
		return client
	}
	if _, ok := client.Transport.(*roundTripper); ok {
		return client
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone := *client
	clone.Transport = &roundTripper{base: base, lbl: labels{provider: provider, authID: authID}}
	return &clone
}

type roundTripper struct {
	base http.RoundTripper
	lbl  labels
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !col.enabled.Load() {
		return rt.base.RoundTrip(req)
	}
	c := col
	rec := c.startRequest(rt.lbl.provider, rt.lbl.authID, req)
	trace := &httptrace.ClientTrace{
		GotConn:           func(info httptrace.GotConnInfo) { c.gotConn(rec, info) },
		TLSHandshakeStart: func() { c.tlsStarting(rec) },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			c.mu.Lock()
			if !rec.tlsStart.IsZero() {
				rec.tlsMs = durationMs(time.Since(rec.tlsStart))
			}
			c.mu.Unlock()
		},
		GotFirstResponseByte: func() { c.firstByte(rec) },
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	ctx = context.WithValue(ctx, requestKey{}, rec)
	ctx = context.WithValue(ctx, labelsKey{}, rt.lbl)

	resp, err := rt.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		end := EndError
		if errors.Is(err, context.Canceled) {
			end = EndCancelled
		}
		c.finishRequest(rec, end, err)
		return resp, err
	}
	if resp == nil {
		c.finishRequest(rec, EndError, nil)
		return resp, err
	}
	c.gotResponse(rec, resp)
	// A 101 body is the upgraded connection; leave it untouched.
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.Body == nil || resp.Body == http.NoBody {
		c.finishRequest(rec, EndNoBody, nil)
		return resp, nil
	}
	body := &trackedBody{ReadCloser: resp.Body, rec: rec}
	// Only a plain event stream can be checked for its final event; a
	// compressed one is left alone and reported as unchecked when closed
	// early. A response without Content-Type to a request that asked for a
	// stream counts as one (chatgpt.com sends none).
	contentType := resp.Header.Get("Content-Type")
	stream := isEventStream(contentType) || (contentType == "" && isEventStream(req.Header.Get("Accept")))
	if stream {
		if isIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			body.scan = true
		} else {
			body.unchecked = true
		}
	}
	resp.Body = body
	return resp, nil
}

func isIdentityEncoding(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "identity"
}

// CloseIdleConnections forwards to the wrapped transport so that
// http.Client.CloseIdleConnections keeps working.
func (rt *roundTripper) CloseIdleConnections() {
	if ci, ok := rt.base.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

// finalEventMarkers end an event stream in the protocols the proxy speaks
// upstream. Each starts with a newline: inside a JSON string a newline is
// escaped, so a match is stream framing and never generated text.
var finalEventMarkers = [][]byte{
	[]byte("\ndata: [DONE]"),                     // OpenAI chat completions, OpenRouter
	[]byte("\nevent: message_stop"),              // Anthropic messages
	[]byte("\nevent: response.completed"),        // OpenAI / Codex responses
	[]byte("\nevent: response.done"),             // OpenAI responses (realtime style)
	[]byte("\nevent: response.incomplete"),       // OpenAI responses, cut by max tokens
	[]byte("\nevent: response.failed"),           // OpenAI responses, failed upstream
	[]byte("\ndata: {\"type\":\"message_stop\""), // Anthropic without event lines
}

// maxMarkerLen bounds the bytes carried between reads so that a marker split
// across two reads is still found.
var maxMarkerLen = func() int {
	n := 0
	for _, m := range finalEventMarkers {
		if len(m) > n {
			n = len(m)
		}
	}
	return n
}()

// trackedBody ends the request record at EOF, at a read error or at Close.
// The record ends before the inner Close so that a transport closing its
// connection with the body sees the request as finished.
type trackedBody struct {
	io.ReadCloser
	rec  *requestState
	once sync.Once

	// scan enables the final-event check for plain event streams. Only Read
	// touches carry and sawFinal; Close reads sawFinal after the last Read.
	scan     bool
	carry    []byte
	join     []byte // scratch for carry plus the next read, reused
	sawFinal atomic.Bool
	// unchecked marks a compressed event stream, which cannot be scanned.
	unchecked bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && b.scan && !b.sawFinal.Load() {
		b.check(p[:n])
	}
	switch {
	case err == nil:
	case err == io.EOF:
		b.finish(EndEOF, nil)
	case errors.Is(err, context.Canceled):
		// The caller gave up on the request; the stream was cut, not broken.
		b.finish(EndCancelled, err)
	default:
		b.finish(EndReadError, err)
	}
	return n, err
}

// check looks for a final-event marker in chunk, including one that started
// in the previous read.
func (b *trackedBody) check(chunk []byte) {
	keep := maxMarkerLen - 1
	if len(b.carry) > 0 {
		head := chunk
		if len(head) > keep {
			head = head[:keep]
		}
		b.join = append(append(b.join[:0], b.carry...), head...)
		if containsMarker(b.join) {
			b.sawFinal.Store(true)
			return
		}
	}
	if containsMarker(chunk) {
		b.sawFinal.Store(true)
		return
	}
	if len(chunk) < keep {
		// Short read: keep what is left of the old carry in front of it.
		b.join = append(append(b.join[:0], b.carry...), chunk...)
		b.carry = append(b.carry[:0], newest(b.join, keep)...)
		return
	}
	b.carry = append(b.carry[:0], chunk[len(chunk)-keep:]...)
}

// containsMarker reports whether data contains a final-event marker. Every
// marker starts with a newline, so only the positions of newlines are tried.
func containsMarker(data []byte) bool {
	for i := 0; i < len(data); {
		j := bytes.IndexByte(data[i:], '\n')
		if j < 0 {
			return false
		}
		rest := data[i+j:]
		// Markers continue with "data:" or "event:"; blank lines and other
		// fields are skipped by their first character.
		if len(rest) < 2 || (rest[1] != 'd' && rest[1] != 'e') {
			i += j + 1
			continue
		}
		for _, m := range finalEventMarkers {
			if bytes.HasPrefix(rest, m) {
				return true
			}
		}
		i += j + 1
	}
	return false
}

func (b *trackedBody) Close() error {
	end := EndClosedEarly
	switch {
	case b.sawFinal.Load():
		end = EndAfterFinalEvent
	case b.unchecked:
		end = EndClosedUnchecked
	}
	b.finish(end, nil)
	return b.ReadCloser.Close()
}

func (b *trackedBody) finish(end string, err error) {
	b.once.Do(func() { b.rec.c.finishRequest(b.rec, end, err) })
}
