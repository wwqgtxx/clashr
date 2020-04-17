package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	"net"

	adapters "github.com/wwqgtxx/clashr/adapters/inbound"
	"github.com/wwqgtxx/clashr/common/pool"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/tunnel"
)

type ShadowSocksUDPListener struct {
	net.PacketConn
	config string
	closed bool
}

func NewShadowSocksUDPProxy(config string) (*ShadowSocksUDPListener, error) {
	addr, cipher, password, err := parseSSURL(config)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksUDPListener{l, config, false}
	pickCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}
	conn := pickCipher.PacketConn(l)
	go func() {
		for {
			buf := pool.BufPool.Get().([]byte)
			n, remoteAddr, err := conn.ReadFrom(buf)
			if err != nil {
				pool.BufPool.Put(buf[:cap(buf)])
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(conn, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksUDPListener) Close() error {
	l.closed = true
	return l.PacketConn.Close()
}

func (l *ShadowSocksUDPListener) Config() string {
	return l.config
}

func handleSocksUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	tgtAddr := socks5.SplitAddr(buf)
	if tgtAddr == nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.BufPool.Put(buf[:cap(buf)])
		return
	}
	target := socks5.ParseAddr(tgtAddr.String())
	payload := buf[len(tgtAddr):]

	packet := &fakeConn{
		PacketConn: pc,
		rAddr:      addr,
		payload:    payload,
		bufRef:     buf,
	}
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.SHADOWSOCKS))
}