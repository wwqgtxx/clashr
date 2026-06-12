package mixec

import (
	"context"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/mtproxy"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks4"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	closed       bool
	config       LC.AuthServer
	listeners    []net.Listener
	udpListeners []*socks.UDPListener
}

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: authStore.Default}, inbound.NewListenerConfig(), tunnel, additions...)
}

func NewWithConfig(config LC.AuthServer, lc *inbound.ListenerConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIXEC"),
			inbound.WithSpecialRules(""),
		}
	}
	ml := &Listener{false, config, nil, nil}
	cl := GetChanListener(tunnel, additions...)

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//UDP
		sul, err := socks.NewUDPWithConfig(config, lc, tunnel, additions...)
		if err != nil {
			return nil, err
		}
		ml.udpListeners = append(ml.udpListeners, sul)

		//TCP
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		ml.listeners = append(ml.listeners, l)

		go func() {
			log.Infoln("MixEC(RESTful Api+Socks+MTProxy+VmessWS) proxy listening at: %s", l.Addr().String())
			for {
				c, err := l.Accept()
				if err != nil {
					if ml.closed {
						break
					}
					continue
				}
				store := config.AuthStore
				if isDefault || store == authStore.Default { // only apply on default listener
					if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
						_ = c.Close()
						continue
					}
					if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
						store = authStore.Nil
					}
				}
				go handleECConn(c, cl, tunnel, store, additions...)
			}
		}()
	}

	return ml, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
	for _, lis := range l.udpListeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() string {
	return l.config.Listen
}

func handleECConn(conn net.Conn, cl ChanListener, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version: // 0x04
		socks.HandleSocks4(bufConn, tunnel, store, additions...)
		return
	case socks5.Version: // 0x05
		socks.HandleSocks5(bufConn, tunnel, store, additions...)
		return
	case mtproxy.FakeTLSFirstByte: // 0x16
		if mtproxy.HandleFakeTLS(bufConn, tunnel, additions...) {
			return
		}
	}

	cl.PutConn(bufConn)
}
