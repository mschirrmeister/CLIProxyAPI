package connstats

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// streamServer writes body as an event stream and then keeps the response
// open until the client goes away, like an upstream that sends its final
// event before it ends the body.
func streamServer(t *testing.T, body string, hold bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, body)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hold {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// readThenClose reads until want appears in what was read, then closes the
// body without waiting for its end.
func readThenClose(t *testing.T, client *http.Client, url, want string, chunk int) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	buf := make([]byte, chunk)
	for !strings.Contains(seen.String(), want) {
		n, errRead := resp.Body.Read(buf)
		seen.Write(buf[:n])
		if errRead != nil {
			t.Fatalf("read before %q: %v", want, errRead)
		}
	}
	_ = resp.Body.Close()
}

func lastRequest(t *testing.T) Request {
	t.Helper()
	snap := SnapshotSince(time.Time{})
	if len(snap.Requests) == 0 {
		t.Fatal("no request recorded")
	}
	return snap.Requests[len(snap.Requests)-1]
}

func TestRequestEndAfterFinalEvent(t *testing.T) {
	for name, tc := range map[string]struct {
		body  string
		until string
	}{
		"chat_completions": {"data: {\"choices\":[]}\n\ndata: [DONE]\n\n", "[DONE]"},
		"anthropic":        {"event: content_block_delta\ndata: {}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "message_stop\"}"},
		"responses":        {"event: response.output_text.delta\ndata: {}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n", "completed\"}"},
	} {
		t.Run(name, func(t *testing.T) {
			enable(t)
			srv := streamServer(t, tc.body, true)
			client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
			readThenClose(t, client, srv.URL, tc.until, 4096)
			if r := lastRequest(t); r.End != EndAfterFinalEvent || !r.Stream {
				t.Fatalf("end=%q stream=%v, want %q stream", r.End, r.Stream, EndAfterFinalEvent)
			}
		})
	}
}

// A marker split across two reads is still found.
func TestRequestEndMarkerAcrossReads(t *testing.T) {
	enable(t)
	srv := streamServer(t, strings.Repeat("data: {\"x\":1}\n\n", 50)+"data: [DONE]\n\n", true)
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	// Three-byte reads split "\ndata: [DONE]" over several reads.
	readThenClose(t, client, srv.URL, "[DONE]", 3)
	if r := lastRequest(t); r.End != EndAfterFinalEvent {
		t.Fatalf("end=%q, want %q", r.End, EndAfterFinalEvent)
	}
}

// Generated text that quotes a marker is not a final event: inside a JSON
// string the newline before it is escaped.
func TestRequestEndIgnoresMarkerInText(t *testing.T) {
	enable(t)
	body := "data: {\"delta\":\"try\\ndata: [DONE]\\nevent: message_stop\"}\n\ndata: {\"delta\":\"more\"}\n\n"
	srv := streamServer(t, body, true)
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	readThenClose(t, client, srv.URL, "more", 4096)
	if r := lastRequest(t); r.End != EndClosedEarly {
		t.Fatalf("end=%q, want %q", r.End, EndClosedEarly)
	}
}

func TestRequestEndEOF(t *testing.T) {
	enable(t)
	srv := streamServer(t, "data: x\n\ndata: [DONE]\n\n", false)
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if r := lastRequest(t); r.End != EndEOF || r.ContentType != "text/event-stream" {
		t.Fatalf("end=%q content_type=%q, want eof and text/event-stream", r.End, r.ContentType)
	}
}

type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 0, b.err }
func (failingBody) Close() error               { return nil }

type bodyTransport struct{ body io.ReadCloser }

func (b bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       b.body,
		Request:    req,
	}, nil
}

func TestRequestEndReadErrorAndCancel(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("connection reset by peer"), EndReadError},
		{context.Canceled, EndCancelled},
		{context.DeadlineExceeded, EndReadError},
	} {
		enable(t)
		client := Instrument(context.Background(), &http.Client{Transport: bodyTransport{failingBody{tc.err}}}, "p", "a")
		resp, err := client.Get("http://upstream.test/stream")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = resp.Body.Read(make([]byte, 8))
		_ = resp.Body.Close()
		r := lastRequest(t)
		if r.End != tc.want || r.Error == "" {
			t.Fatalf("%v: end=%q error=%q, want %q with error", tc.err, r.End, r.Error, tc.want)
		}
	}
}

// A request that asks for an event stream counts as a stream even when the
// response does not say so (seen with chatgpt.com).
func TestRequestStreamFromAccept(t *testing.T) {
	enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {}\n\n")
	}))
	defer srv.Close()
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("{}"))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if r := lastRequest(t); !r.Stream || r.ContentType != "application/octet-stream" {
		t.Fatalf("stream=%v content_type=%q, want stream from Accept", r.Stream, r.ContentType)
	}
}

type headerlessStream struct{ body io.ReadCloser }

func (h headerlessStream) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: h.body, Request: req}, nil
}

// chatgpt.com answers a stream request without Content-Type; its final event
// is still recognized when the request asked for a stream.
func TestRequestEndFinalEventWithoutContentType(t *testing.T) {
	enable(t)
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "event: response.output_text.delta\ndata: {}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
		// Keep the stream open, like an upstream that has not ended the body.
	}()
	defer func() { _ = pw.Close() }()
	client := Instrument(context.Background(), &http.Client{Transport: headerlessStream{pr}}, "codex", "a")
	req, _ := http.NewRequest(http.MethodPost, "https://chatgpt.test/backend-api/codex/responses", strings.NewReader("{}"))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	buf := make([]byte, 64)
	for !strings.Contains(seen.String(), "completed\"}") {
		n, errRead := resp.Body.Read(buf)
		seen.Write(buf[:n])
		if errRead != nil {
			t.Fatal(errRead)
		}
	}
	_ = resp.Body.Close()
	if r := lastRequest(t); r.End != EndAfterFinalEvent || !r.Stream || r.ContentType != "" {
		t.Fatalf("end=%q stream=%v content_type=%q, want %q stream without content type", r.End, r.Stream, r.ContentType, EndAfterFinalEvent)
	}
}

// A JSON error answer to a stream request is not scanned as a stream.
func TestRequestEndJSONErrorToStreamRequest(t *testing.T) {
	enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "{\"error\":\"x\\ndata: [DONE]\"}")
	}))
	defer srv.Close()
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("{}"))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = resp.Body.Read(make([]byte, 4))
	_ = resp.Body.Close()
	if r := lastRequest(t); r.End != EndClosedEarly || r.Status != http.StatusTooManyRequests {
		t.Fatalf("end=%q status=%d, want closed_early 429", r.End, r.Status)
	}
}

type modelKey struct{}

func TestRequestModelLabel(t *testing.T) {
	enable(t)
	SetModelFunc(func(ctx context.Context) string { s, _ := ctx.Value(modelKey{}).(string); return s })
	defer SetModelFunc(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	ctx := context.WithValue(context.Background(), modelKey{}, "kimi-k2")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if r := lastRequest(t); r.Model != "kimi-k2" {
		t.Fatalf("model=%q, want kimi-k2", r.Model)
	}
}

// The standard transport binds a request at dial time, before its TLS
// handshake ends; the handshake time still reaches the connection.
func TestStandardTransportRecordsTLSTime(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport).Clone()
	base.DialContext = WrapDialContext((&net.Dialer{}).DialContext, KindStandard, "", "")
	client := Instrument(context.Background(), &http.Client{Transport: base}, "p", "a")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 || snap.Open[0].TLSMs <= 0 || snap.Open[0].TLSVersion == "" {
		t.Fatalf("open = %+v, want one connection with TLS time and version", snap.Open)
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// A request cancelled before its response arrived is a cancellation; any
// other round-trip failure, a deadline included, is an error.
func TestRequestEndBeforeResponse(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, EndCancelled},
		{fmt.Errorf("dial: %w", context.Canceled), EndCancelled},
		{context.DeadlineExceeded, EndError},
		{errors.New("connection refused"), EndError},
	} {
		enable(t)
		client := Instrument(context.Background(), &http.Client{Transport: failingTransport{tc.err}}, "p", "a")
		if _, err := client.Get("http://upstream.test/x"); err == nil {
			t.Fatal("want an error")
		}
		r := lastRequest(t)
		if r.End != tc.want || r.Error == "" {
			t.Fatalf("%v: end=%q error=%q, want %q with error", tc.err, r.End, r.Error, tc.want)
		}
	}
}
