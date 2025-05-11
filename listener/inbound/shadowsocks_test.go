package inbound_test

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks/shadowstream"
	"github.com/stretchr/testify/assert"
)

var shadowsocksCipherList = []string{shadowsocks.MethodNone}
var shadowsocksCipherListShort = []string{shadowsocks.MethodNone}
var shadowsocksPassword32 string
var shadowsocksPassword16 string

func init() {
	shadowsocksCipherList = append(shadowsocksCipherList, shadowaead.List...)
	shadowsocksCipherList = append(shadowsocksCipherList, shadowaead_2022.List...)
	shadowsocksCipherList = append(shadowsocksCipherList, shadowstream.List...)
	shadowsocksCipherListShort = append(shadowsocksCipherListShort, shadowaead.List[0])
	shadowsocksCipherListShort = append(shadowsocksCipherListShort, shadowaead_2022.List[0])
	passwordBytes := make([]byte, 32)
	rand.Read(passwordBytes)
	shadowsocksPassword32 = base64.StdEncoding.EncodeToString(passwordBytes)
	shadowsocksPassword16 = base64.StdEncoding.EncodeToString(passwordBytes[:16])
}

func testInboundShadowSocks(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, cipherList []string) {
	t.Parallel()
	for _, cipher := range cipherList {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
			inboundOptions.Cipher = cipher
			outboundOptions.Cipher = cipher
			testInboundShadowSocks0(t, inboundOptions, outboundOptions)
		})
	}
}

func testInboundShadowSocks0(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption) {
	t.Parallel()
	password := shadowsocksPassword32
	if strings.Contains(inboundOptions.Cipher, "-128-") {
		password = shadowsocksPassword16
	}
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "shadowsocks_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Password = password
	in, err := inbound.NewShadowSocks(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "shadowsocks_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = password

	out, err := outbound.NewShadowSocks(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	testSingMux(t, tunnel, out)
}

func TestInboundShadowSocks_Basic(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{}
	outboundOptions := outbound.ShadowSocksOption{}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherList)
}

func TestInboundShadowSocks_ShadowTlsv1(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   1,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "fingerprint": tlsFingerprint, "version": 1},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherListShort)
}

func TestInboundShadowSocks_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.PluginOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherListShort)
}

func TestInboundShadowSocks_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherListShort)
}
