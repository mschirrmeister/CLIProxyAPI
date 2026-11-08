package connstats

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// connectProxy runs a minimal HTTP CONNECT proxy that waits delay before it
// confirms the tunnel, so the tunnel setup takes a measurable time.
func connectProxy(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			go func(client net.Conn) {
				defer func() { _ = client.Close() }()
				br := bufio.NewReader(client)
				req, errRead := http.ReadRequest(br)
				if errRead != nil || req.Method != http.MethodConnect {
					return
				}
				upstream, errDial := net.Dial("tcp", req.Host)
				if errDial != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer func() { _ = upstream.Close() }()
				time.Sleep(delay)
				if _, errWrite := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); errWrite != nil {
					return
				}
				go func() {
					_, _ = io.Copy(upstream, br)
					_ = upstream.Close()
				}()
				_, _ = io.Copy(client, upstream)
			}(client)
		}
	}()
	return ln.Addr().String()
}

func TestStandardTransportThroughHTTPProxy(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	proxyAddr := connectProxy(t, 40*time.Millisecond)

	base := srv.Client().Transport.(*http.Transport).Clone()
	base.DialContext = WrapDialContext((&net.Dialer{}).DialContext, KindStandard, "", "")
	base.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})
	client := Instrument(context.Background(), &http.Client{Transport: base}, "p", "a")
	get(t, client, srv.URL)

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 {
		t.Fatalf("open = %+v, want one connection", snap.Open)
	}
	c := snap.Open[0]
	if c.Addr != srv.Listener.Addr().String() {
		t.Errorf("addr = %q, want the target %q", c.Addr, srv.Listener.Addr().String())
	}
	if c.Proxy != proxyAddr || c.Remote != proxyAddr {
		t.Errorf("proxy = %q, remote = %q, want both %q", c.Proxy, c.Remote, proxyAddr)
	}
	if c.ProxyMs < 30 {
		t.Errorf("proxy_ms = %v, want the tunnel delay of about 40 ms", c.ProxyMs)
	}
	if c.DialMs < c.ProxyMs {
		t.Errorf("dial_ms = %v, want it to include proxy_ms = %v", c.DialMs, c.ProxyMs)
	}
	if c.TLSMs <= 0 || c.TLSVersion == "" {
		t.Errorf("tls = %v ms %q, want the target handshake", c.TLSMs, c.TLSVersion)
	}
	if r := lastRequest(t); r.ConnID != c.ID || r.Host != srv.Listener.Addr().String() {
		t.Errorf("request = %+v, want it on connection %d", r, c.ID)
	}
}

func TestDirectConnectionHasNoProxy(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport).Clone()
	base.DialContext = WrapDialContext((&net.Dialer{}).DialContext, KindStandard, "", "")
	base.Proxy = nil
	client := Instrument(context.Background(), &http.Client{Transport: base}, "p", "a")
	get(t, client, srv.URL)

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 {
		t.Fatalf("open = %+v, want one connection", snap.Open)
	}
	if c := snap.Open[0]; c.Proxy != "" || c.ProxyMs != 0 || c.Addr != srv.Listener.Addr().String() {
		t.Errorf("conn = %+v, want a direct connection to the target", c)
	}
}

type proxyDialer struct{ addr string }

func (d proxyDialer) ProxyAddr() string { return d.addr }

func TestTrackViaRecordsDialerProxy(t *testing.T) {
	enable(t)
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	conn := TrackVia(context.Background(), a, KindClaudeCode, "api.example.com:443", proxyDialer{"proxy.example.com:3128"}, time.Now())
	defer func() { _ = conn.Close() }()

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 {
		t.Fatalf("open = %+v, want one connection", snap.Open)
	}
	if c := snap.Open[0]; c.Addr != "api.example.com:443" || c.Proxy != "proxy.example.com:3128" || c.ProxyMs != 0 {
		t.Errorf("conn = %+v, want target, proxy and no separate tunnel time", c)
	}
	if got := ProxyAddr(struct{}{}); got != "" {
		t.Errorf("ProxyAddr(direct) = %q, want empty", got)
	}
	if got := ProxyAddr(nil); got != "" {
		t.Errorf("ProxyAddr(nil) = %q, want empty", got)
	}
}

// A dial function that tunnels itself, like a SOCKS5 dialer, dials the target
// address; the proxy comes from the wrapper.
func TestWrapProxyDialContextRecordsProxy(t *testing.T) {
	enable(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = WrapProxyDialContext((&net.Dialer{}).DialContext, KindStandard, "socks.example.com:1080")
	client := Instrument(context.Background(), &http.Client{Transport: base}, "p", "a")
	get(t, client, srv.URL)

	snap := SnapshotSince(time.Time{})
	if len(snap.Open) != 1 {
		t.Fatalf("open = %+v, want one connection", snap.Open)
	}
	if c := snap.Open[0]; c.Addr != srv.Listener.Addr().String() || c.Proxy != "socks.example.com:1080" || c.ProxyMs != 0 {
		t.Errorf("conn = %+v, want target, SOCKS proxy and the tunnel inside the dial", c)
	}
}

func TestCanonicalAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"https://api.example.com/v1":      "api.example.com:443",
		"http://api.example.com/v1":       "api.example.com:80",
		"https://api.example.com:8443/v1": "api.example.com:8443",
		"wss://chatgpt.example.com/ws":    "chatgpt.example.com:443",
		"https://[2001:db8::1]/v1":        "[2001:db8::1]:443",
		"ftp://files.example.com/x":       "",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalAddr(u); got != want {
			t.Errorf("canonicalAddr(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := canonicalAddr(nil); got != "" {
		t.Errorf("canonicalAddr(nil) = %q, want empty", got)
	}
}
