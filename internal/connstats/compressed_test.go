package connstats

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gzipStreamServer sends a gzip-compressed event stream with its final event
// and keeps the response open until the client goes away.
func gzipStreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = io.WriteString(zw, "data: {\"choices\":[]}\n\ndata: [DONE]\n\n")
		_ = zw.Flush()
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A caller that asks for compression itself reads the compressed bytes; the
// final event cannot be seen, so an early close is unchecked, not early.
func TestRequestEndCompressedStreamUnchecked(t *testing.T) {
	enable(t)
	srv := gzipStreamServer(t)
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Body.Read(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	r := lastRequest(t)
	if r.End != EndClosedUnchecked || r.Encoding != "gzip" || !r.Stream {
		t.Fatalf("request = %+v, want an unchecked gzip stream", r)
	}
}

// When the transport negotiates gzip itself it decompresses the body, so the
// stream is plain to the caller and its final event is found.
func TestRequestEndTransparentGzipIsChecked(t *testing.T) {
	enable(t)
	srv := gzipStreamServer(t)
	client := Instrument(context.Background(), &http.Client{Transport: trackedTransport()}, "p", "a")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	buf := make([]byte, 16)
	for !strings.Contains(seen.String(), "[DONE]") {
		n, errRead := resp.Body.Read(buf)
		seen.Write(buf[:n])
		if errRead != nil {
			t.Fatalf("read: %v", errRead)
		}
	}
	_ = resp.Body.Close()

	r := lastRequest(t)
	if r.End != EndAfterFinalEvent || r.Encoding != "" {
		t.Fatalf("request = %+v, want a checked plain stream", r)
	}
}
