package helps

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/connstats"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// Label upstream requests with the model the client asked for. The conductor
// stores it on the execution context before an executor runs, so requests
// built from that context carry it.
func init() {
	connstats.SetModelFunc(coreusage.RequestedModelAliasFromContext)
}

// InstrumentConnStats links the client's upstream requests to their
// connections for the connection view, labelled with the credential.
func InstrumentConnStats(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth) *http.Client {
	provider, authID := connStatsLabels(auth)
	return connstats.Instrument(ctx, client, provider, authID)
}

// SuppressConnStats keeps an inner client constructor from instrumenting a
// client that the caller still inspects; the caller instruments the result.
func SuppressConnStats(ctx context.Context) context.Context {
	return connstats.Suppress(ctx)
}

// TrackWebsocketDialer tracks connections opened by an upstream WebSocket dialer.
func TrackWebsocketDialer(dialer *websocket.Dialer, auth *cliproxyauth.Auth) {
	if dialer == nil || dialer.NetDialContext == nil || !connstats.Enabled() {
		return
	}
	provider, authID := connStatsLabels(auth)
	dialer.NetDialContext = connstats.WrapDialContext(dialer.NetDialContext, connstats.KindWebSocket, provider, authID)
}

func noteUtlsHandshake(conn net.Conn, handshakeStart time.Time, tlsConn *tls.UConn) {
	if !connstats.Enabled() {
		return
	}
	state := tlsConn.ConnectionState()
	connstats.NoteTLS(conn, handshakeStart, state.Version, state.NegotiatedProtocol, state.DidResume)
}

func connStatsLabels(auth *cliproxyauth.Auth) (provider, authID string) {
	if auth == nil {
		return "", ""
	}
	return auth.Provider, auth.ID
}

// NoteWebsocketTurn counts one upstream message sent on a WebSocket connection.
func NoteWebsocketTurn(conn *websocket.Conn) {
	if conn == nil || !connstats.Enabled() {
		return
	}
	connstats.NoteWebsocketTurn(conn.LocalAddr())
}
