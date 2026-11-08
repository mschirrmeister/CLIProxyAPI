package connstats

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
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
		GotConn: func(info httptrace.GotConnInfo) { c.gotConn(rec, info) },
		TLSHandshakeStart: func() {
			c.mu.Lock()
			rec.tlsStart = time.Now()
			c.mu.Unlock()
		},
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
		c.finishRequest(rec, false, err)
		return resp, err
	}
	if resp == nil {
		c.finishRequest(rec, false, nil)
		return resp, err
	}
	c.gotResponse(rec, resp)
	// A 101 body is the upgraded connection; leave it untouched.
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.Body == nil || resp.Body == http.NoBody {
		c.finishRequest(rec, true, nil)
		return resp, nil
	}
	resp.Body = &trackedBody{ReadCloser: resp.Body, rec: rec}
	return resp, nil
}

// CloseIdleConnections forwards to the wrapped transport so that
// http.Client.CloseIdleConnections keeps working.
func (rt *roundTripper) CloseIdleConnections() {
	if ci, ok := rt.base.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

// trackedBody ends the request record at EOF (complete) or at Close (early).
// The record ends before the inner Close so that a transport closing its
// connection with the body sees the request as finished.
type trackedBody struct {
	io.ReadCloser
	rec  *requestState
	once sync.Once
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.finish(true)
	}
	return n, err
}

func (b *trackedBody) Close() error {
	b.finish(false)
	return b.ReadCloser.Close()
}

func (b *trackedBody) finish(complete bool) {
	b.once.Do(func() { b.rec.c.finishRequest(b.rec, complete, nil) })
}
