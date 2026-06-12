package mtproxy

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mtproxy/common"
	"github.com/metacubex/mihomo/component/mtproxy/server_protocol"
	"github.com/metacubex/mihomo/component/mtproxy/tools"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	FakeTLSFirstByte = server_protocol.FakeTLSFirstByte
)

func init() {
	common.PrintlnFunc = func(str string) {
		log.Warnln(str)
	}
}

type Listener struct {
	config     string
	closed     bool
	listeners  []net.Listener
	serverInfo *tools.ServerInfo
}

var _listener *Listener

func New(config string, lc *inbound.ListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	var hl *Listener
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MTPROXY"),
			inbound.WithSpecialRules(""),
		}
		defer func() {
			_listener = hl
		}()
	}
	if len(config) == 0 {
		return nil, nil
	}
	spliced := strings.Split(config, "@")
	addrString := ""
	if len(spliced) > 2 {
		return nil, errors.New("addr format error")
	}
	if len(spliced) > 1 {
		addrString = spliced[1]
	}

	spliced2 := strings.Split(spliced[0], ":")
	serverInfo, err := tools.ParseHexedSecret(spliced2[0])
	if err != nil {
		return nil, err
	}
	if len(spliced2) == 2 {
		serverInfo.CloakPort = spliced2[1]
	}

	hl = &Listener{
		config:     config,
		closed:     false,
		serverInfo: serverInfo,
	}

	if len(addrString) == 0 {
		return hl, nil
	}

	for _, addr := range strings.Split(addrString, ",") {
		addr := addr

		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		hl.listeners = append(hl.listeners, l)

		go func() {
			log.Infoln("MTProxy listening at: %s", l.Addr().String())

			for {
				c, err := l.Accept()
				if err != nil {
					if hl.closed {
						break
					}
					continue
				}
				go hl.HandleConn(c, tunnel)
			}
		}()
	}

	return hl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) SecretMode() common.SecretMode {
	return l.serverInfo.SecretMode
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	serverProtocol := l.serverInfo.ServerProtocolMaker(
		l.serverInfo.Secret,
		l.serverInfo.SecretMode,
		l.serverInfo.CloakHost,
		l.serverInfo.CloakPort,
	)
	serverConn, err := serverProtocol.Handshake(conn)
	if err != nil {
		//log.Warnln("Cannot perform client handshake: %s", err)

		return
	}
	defer serverConn.Close()

	telegramConn, err := l.serverInfo.TelegramDialer.Dial(
		serverProtocol,
		func(addr string) (net.Conn, error) {
			conn1, conn2 := N.Pipe()
			metadata := &C.Metadata{
				NetWork: C.TCP,
				Type:    C.MTPROXY,
			}
			err := metadata.SetRemoteAddress(addr)
			if err != nil {
				return nil, err
			}
			inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(conn.RemoteAddr()), inbound.WithInAddr(conn.LocalAddr()))
			inbound.ApplyAdditions(metadata, additions...)
			go tunnel.HandleTCPConn(conn2, metadata)
			return conn1, nil
		})
	if err != nil {
		return
	}
	defer telegramConn.Close()

	N.Relay(serverConn, telegramConn)
}

func HandleFakeTLS(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.SecretMode() == common.SecretModeTLS {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}
