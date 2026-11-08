package connstats

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// benchStream is an event stream of about 24 KB that ends with [DONE].
var benchStream = strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"lorem ipsum dolor sit amet\"}}]}\n\n", 300) + "data: [DONE]\n\n"

func benchServer(b *testing.B) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, benchStream)
	}))
	b.Cleanup(srv.Close)
	return srv
}

func benchGet(b *testing.B, client *http.Client, url string) {
	resp, err := client.Get(url)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		b.Fatal(err)
	}
	_ = resp.Body.Close()
}

// BenchmarkStreamRequest compares one streamed request on a reused connection
// without the wrapper, with the wrapper while collection is off, and with
// collection on.
func BenchmarkStreamRequest(b *testing.B) {
	srv := benchServer(b)
	plainTransport := func() *http.Transport {
		return &http.Transport{DialContext: (&net.Dialer{}).DialContext, MaxIdleConnsPerHost: 4}
	}
	trackedTr := func() *http.Transport {
		return &http.Transport{DialContext: WrapDialContext((&net.Dialer{}).DialContext, KindStandard, "", ""), MaxIdleConnsPerHost: 4}
	}

	b.Run("no_wrapper", func(b *testing.B) {
		client := &http.Client{Transport: plainTransport()}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchGet(b, client, srv.URL)
		}
	})
	b.Run("wrapper_off", func(b *testing.B) {
		// Built while collection was on, then switched off: the wrappers stay
		// in place and pass through.
		enableBench(b)
		client := Instrument(context.Background(), &http.Client{Transport: trackedTr()}, "p", "a")
		Configure(false, 0, 0, "")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchGet(b, client, srv.URL)
		}
	})
	b.Run("on", func(b *testing.B) {
		enableBench(b)
		client := Instrument(context.Background(), &http.Client{Transport: trackedTr()}, "p", "a")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchGet(b, client, srv.URL)
		}
	})
}

// BenchmarkFinalEventScan measures the stream tail check alone, per 4 KB read.
func BenchmarkFinalEventScan(b *testing.B) {
	chunk := []byte(benchStream[:4096])
	body := &trackedBody{scan: true}
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		body.check(chunk)
	}
}

func enableBench(b *testing.B) {
	b.Helper()
	reset()
	Configure(true, 0, 0, "")
	b.Cleanup(func() {
		Configure(false, 0, 0, "")
		reset()
	})
}
