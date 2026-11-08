package proxyutil

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/connstats"
	"golang.org/x/net/proxy"
)

// socks5Server runs a minimal SOCKS5 proxy without authentication.
func socks5Server(t *testing.T) string {
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
			go serveSOCKS5(client)
		}
	}()
	return ln.Addr().String()
}

func serveSOCKS5(client net.Conn) {
	defer func() { _ = client.Close() }()
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(client, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(client, n); err != nil {
			return
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(client, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(client, port); err != nil {
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
	if err != nil {
		_, _ = client.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
}

// The SOCKS5 transport replaces the tracked dial function of the default
// transport; its connections must still be recorded, with the proxy.
func TestBuildHTTPTransportSOCKS5IsTracked(t *testing.T) {
	connstats.Configure(true, 0, 0, "")
	t.Cleanup(func() { connstats.Configure(false, 0, 0, "") })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	socksAddr := socks5Server(t)

	transport, mode, errBuild := BuildHTTPTransport("socks5://" + socksAddr)
	if errBuild != nil || mode != ModeProxy {
		t.Fatalf("BuildHTTPTransport mode=%d err=%v", mode, errBuild)
	}
	transport.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	client := connstats.Instrument(context.Background(), &http.Client{Transport: transport}, "p", "a")
	resp, errGet := client.Get(srv.URL)
	if errGet != nil {
		t.Fatal(errGet)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	var found *connstats.Conn
	snap := connstats.SnapshotSince(time.Time{})
	for i := range snap.Open {
		if snap.Open[i].Proxy == socksAddr {
			found = &snap.Open[i]
		}
	}
	if found == nil {
		t.Fatalf("open = %+v, want a connection through %s", snap.Open, socksAddr)
	}
	if found.Addr != srv.Listener.Addr().String() || found.Kind != connstats.KindStandard {
		t.Errorf("conn = %+v, want a standard connection to %s", *found, srv.Listener.Addr())
	}
	bound := false
	for _, r := range snap.Requests {
		if r.ConnID == found.ID {
			bound = true
		}
	}
	if !bound {
		t.Errorf("requests = %+v, want one on connection %d", snap.Requests, found.ID)
	}
}

func TestBuildDialerReportsProxyAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"http://user:secret@proxy.example.com:8080":   "proxy.example.com:8080",
		"http://proxy.example.com":                    "proxy.example.com:80",
		"https://proxy.example.com":                   "proxy.example.com:443",
		"socks5://user:secret@proxy.example.com:1081": "proxy.example.com:1081",
		"socks5h://proxy.example.com":                 "proxy.example.com:1080",
	} {
		dialer, mode, errBuild := BuildDialer(raw)
		if errBuild != nil || mode != ModeProxy {
			t.Fatalf("BuildDialer(%q) mode=%d err=%v", raw, mode, errBuild)
		}
		if got := connstats.ProxyAddr(dialer); got != want {
			t.Errorf("ProxyAddr(%q) = %q, want %q", raw, got, want)
		}
		if _, ok := dialer.(proxy.ContextDialer); !ok {
			t.Errorf("BuildDialer(%q) = %T, want a context dialer", raw, dialer)
		}
	}
	direct, _, _ := BuildDialer("direct")
	if got := connstats.ProxyAddr(direct); got != "" {
		t.Errorf("ProxyAddr(direct) = %q, want empty", got)
	}
}
