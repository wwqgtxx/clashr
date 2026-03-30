package xhttp

import (
	"github.com/metacubex/mihomo/transport/gun"

	"github.com/metacubex/http"
)

type closeIdleTransport interface {
	CloseIdleConnections()
}

func forceCloseAllConnections(roundTripper http.RoundTripper) {
	if tr, ok := roundTripper.(closeIdleTransport); ok {
		tr.CloseIdleConnections()
	}
	switch tr := roundTripper.(type) {
	case *http.Http2Transport:
		gun.CloseHttp2Transport(tr)
	}
}
