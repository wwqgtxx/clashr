package gun

import (
	"net"

	"github.com/metacubex/mihomo/common/atomic"

	"golang.org/x/net/http2"
)

type TransportWrap struct {
	*http2.Transport
	closed *atomic.Bool
}

type netAddr struct {
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (addr netAddr) RemoteAddr() net.Addr {
	return addr.remoteAddr
}

func (addr netAddr) LocalAddr() net.Addr {
	return addr.localAddr
}
