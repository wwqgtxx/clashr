package mixec

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
)

type ChanListener interface {
	PutConn(conn net.Conn)
}

type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	closed atomic.Bool
}

func (l *chanListener) Close() error {
	if !l.closed.Swap(true) {
		close(l.ch)
	}
	return nil
}

func (l *chanListener) Accept() (net.Conn, error) {
	if conn, ok := <-l.ch; ok {
		return conn, nil
	}
	return nil, errors.New("listener closed")
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func (l *chanListener) PutConn(conn net.Conn) {
	if !l.closed.Load() {
		l.ch <- conn
	}
}

var once sync.Once
var _chanListener *chanListener

type ecHandler struct {
	tunnel    C.Tunnel
	additions []inbound.Addition
}

func (h ecHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/socket.io" && r.Header.Get("Upgrade") == "websocket" {
		conn, err := vmess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}
		if !sing_vmess.HandleVmess(conn, h.tunnel, h.additions...) {
			_ = conn.Close()
		}
		return
	}
	if r.URL.Path == "/ws" && r.Header.Get("Upgrade") == "websocket" {
		conn, err := vmess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}
		if !sing_shadowsocks.HandleShadowSocks(conn, h.tunnel, h.additions...) {
			_ = conn.Close()
		}
		return
	}

	if handler := C.GetECHandler(); handler != nil {
		handler.ServeHTTP(w, r)
	}
}

func GetChanListener(tunnel C.Tunnel, additions ...inbound.Addition) ChanListener {
	once.Do(func() {
		_chanListener = &chanListener{
			make(chan net.Conn),
			net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0)),
			atomic.NewBool(false),
		}
		go http.Serve(_chanListener, ecHandler{tunnel, additions})
	})
	return _chanListener
}
