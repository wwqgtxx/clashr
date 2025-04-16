package inbound_test

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks/shadowstream"
	"github.com/stretchr/testify/assert"
)

var shadowsocksCipherList = []string{shadowsocks.MethodNone}

func init() {
	shadowsocksCipherList = append(shadowsocksCipherList, shadowaead.List...)
	shadowsocksCipherList = append(shadowsocksCipherList, shadowaead_2022.List...)
	shadowsocksCipherList = append(shadowsocksCipherList, shadowstream.List...)
}

func testInboundShadowSocks(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption) {
	for _, cipher := range shadowsocksCipherList {
		t.Run(cipher, func(t *testing.T) {
			inboundOptions.Cipher = cipher
			outboundOptions.Cipher = cipher
			testInboundShadowSocks0(t, inboundOptions, outboundOptions)
		})
	}
}

func testInboundShadowSocks0(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption) {
	passwordLen := 32
	if strings.Contains(inboundOptions.Cipher, "-128-") {
		passwordLen = 16
	}
	passwordBytes := make([]byte, passwordLen)
	rand.Read(passwordBytes)
	password := base64.StdEncoding.EncodeToString(passwordBytes)
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "shadowsocks_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Password = password
	in, err := inbound.NewShadowSocks(&inboundOptions)
	assert.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	assert.NoError(t, err)
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	assert.NoError(t, err)

	outboundOptions.Name = "shadowsocks_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = password

	out, err := outbound.NewShadowSocks(outboundOptions)
	assert.NoError(t, err)
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundShadowSocks_Basic(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{}
	outboundOptions := outbound.ShadowSocksOption{}
	testInboundShadowSocks(t, inboundOptions, outboundOptions)
}
