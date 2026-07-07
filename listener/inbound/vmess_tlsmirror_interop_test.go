package inbound_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/tlsmirror"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

const v2rayTLSMirrorInteropRef = "v5.51.2"
const v2rayTLSMirrorInteropXNetRef = "bd5f1dcf71cf0d6d2424021d0a04f191396a46a7" // http2: initialize Transport on NewClientConn

var tlsMirrorInteropPrimaryKey = tlsmirror.GeneratePrimaryKey()

func TestInboundVMess_TLSMirror_V2RayInterop(t *testing.T) {
	if skip, _ := strconv.ParseBool(os.Getenv("SKIP_INTEROP_TEST")); skip {
		t.Skip("SKIP_INTEROP_TEST is set")
	}

	v2rayBin := tlsMirrorInteropV2RayBinary(t)

	tlsMirrorInteropTestCase(t, v2rayBin, "default", tlsMirrorInteropAdvanced{})
	tlsMirrorInteropTestCase(t, v2rayBin, "padding", tlsMirrorInteropAdvanced{
		config: tlsmirror.Config{
			TransportLayerPadding: tlsmirror.TransportLayerPadding{Enabled: true},
		},
		payloadSize: 128,
	})
	tlsMirrorInteropTestCase(t, v2rayBin, "watermark", tlsMirrorInteropAdvanced{
		config: tlsmirror.Config{
			SequenceWatermarkingEnabled: true,
		},
		payloadSize: 128,
	})
	tlsMirrorInteropTestCase(t, v2rayBin, "tls12 explicit nonce", tlsMirrorInteropAdvanced{
		config: tlsmirror.Config{
			ExplicitNonceCipherSuites: tlsmirror.RecommendedExplicitNonceCipherSuites,
		},
		configureCarrierTLS: func(config *tls.Config) {
			config.MinVersion = tls.VersionTLS12
			config.MaxVersion = tls.VersionTLS12
			config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		},
		tls12:       true,
		payloadSize: 128,
	})
	tlsMirrorInteropTestCase(t, v2rayBin, "advanced tls12 padding watermark", tlsMirrorInteropAdvanced{
		config: tlsmirror.Config{
			ExplicitNonceCipherSuites:   tlsmirror.RecommendedExplicitNonceCipherSuites,
			TransportLayerPadding:       tlsmirror.TransportLayerPadding{Enabled: true},
			SequenceWatermarkingEnabled: true,
		},
		configureCarrierTLS: func(config *tls.Config) {
			config.MinVersion = tls.VersionTLS12
			config.MaxVersion = tls.VersionTLS12
			config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		},
		tls12:       true,
		payloadSize: 128,
	})
	tlsMirrorInteropTestCase(t, v2rayBin, "connection enrolment", tlsMirrorInteropAdvanced{
		config: tlsmirror.Config{
			ConnectionEnrolment: &tlsmirror.ConnectionEnrolment{
				PrimaryIngressOutbound: "tlsmirror-enrollment",
			},
		},
		payloadSize: 128,
	})
	tlsMirrorInteropMihomoClientH2EmbeddedTrafficGenerator(t, v2rayBin)
}

type tlsMirrorInteropAdvanced struct {
	config              tlsmirror.Config
	configureCarrierTLS func(*tls.Config)
	tls12               bool
	payloadSize         int
}

type tlsMirrorInteropCarrier struct {
	addr          string
	fingerprint   string
	certChainHash string
}

func tlsMirrorInteropMihomoClientH2EmbeddedTrafficGenerator(t *testing.T, v2rayBin string) {
	t.Run("h2 embedded traffic/mihomo client to v2ray server", func(t *testing.T) {
		echoAddr := startTLSMirrorInteropEcho(t)
		forward := startTLSMirrorInteropCarrierHTTP2(t)
		v2rayPort := tlsMirrorInteropReservePort(t)
		config := tlsMirrorInteropServerConfig(t, v2rayPort.Port(), tlsMirrorInteropPort(forward.addr), userUUID, tlsMirrorInteropAdvanced{})

		startTLSMirrorInteropV2Ray(t, v2rayBin, config, v2rayPort, net.JoinHostPort("127.0.0.1", fmt.Sprint(v2rayPort.Port())))

		out, err := outbound.NewVmess(outbound.VmessOption{
			Name:        "vmess_tlsmirror_v2ray_server_h2",
			Server:      "127.0.0.1",
			Port:        v2rayPort.Port(),
			UUID:        userUUID,
			Cipher:      "auto",
			TLS:         true,
			ALPN:        []string{"h2"},
			ServerName:  "localhost",
			Fingerprint: forward.fingerprint,
			TLSMirrorOpts: outbound.TLSMirrorOptions{
				PrimaryKey: tlsMirrorInteropPrimaryKey,
				EmbeddedTrafficGenerator: outbound.TLSMirrorTrafficGenerator{Steps: []outbound.TLSMirrorTrafficStep{{
					Host:                         "localhost",
					Path:                         "/",
					Method:                       "GET",
					ConnectionReady:              true,
					ConnectionRecallExit:         true,
					H2DoNotWaitForDownloadFinish: true,
					WaitTime: outbound.TLSMirrorTimeSpec{
						BaseNanoseconds: uint64((10 * time.Millisecond).Nanoseconds()),
					},
					NextStep: []outbound.TLSMirrorTrafficTransferCandidate{{
						Weight:       1,
						GotoLocation: 0,
					}},
				}}},
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })

		conn, err := out.DialContext(context.Background(), tlsMirrorInteropMetadata(t, echoAddr))
		require.NoError(t, err)
		require.NoError(t, tlsMirrorInteropRoundTripConn(conn, 128))
	})
}

func tlsMirrorInteropTestCase(t *testing.T, v2rayBin, name string, advanced tlsMirrorInteropAdvanced) {
	t.Run(name+"/mihomo client to v2ray server", func(t *testing.T) {
		echoAddr := startTLSMirrorInteropEcho(t)
		forward := startTLSMirrorInteropCarrierTLS(t, advanced.configureCarrierTLS)
		v2rayPort := tlsMirrorInteropReservePort(t)
		config := tlsMirrorInteropServerConfig(t, v2rayPort.Port(), tlsMirrorInteropPort(forward.addr), userUUID, advanced)

		startTLSMirrorInteropV2Ray(t, v2rayBin, config, v2rayPort, net.JoinHostPort("127.0.0.1", fmt.Sprint(v2rayPort.Port())))

		out, err := outbound.NewVmess(outbound.VmessOption{
			Name:        "vmess_tlsmirror_v2ray_server",
			Server:      "127.0.0.1",
			Port:        v2rayPort.Port(),
			UUID:        userUUID,
			Cipher:      "auto",
			TLS:         true,
			ServerName:  "localhost",
			Fingerprint: forward.fingerprint,
			TLSMirrorOpts: outbound.TLSMirrorOptions{
				PrimaryKey:                  tlsMirrorInteropPrimaryKey,
				ExplicitNonceCipherSuites:   advanced.config.ExplicitNonceCipherSuites,
				TransportLayerPadding:       outbound.TLSMirrorTransportLayerPadding{Enabled: advanced.config.TransportLayerPadding.Enabled},
				ConnectionEnrolment:         tlsMirrorInteropOutboundConnectionEnrolment(advanced),
				SequenceWatermarkingEnabled: advanced.config.SequenceWatermarkingEnabled,
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })

		conn, err := out.DialContext(context.Background(), tlsMirrorInteropMetadata(t, echoAddr))
		require.NoError(t, err)
		require.NoError(t, tlsMirrorInteropRoundTripConn(conn, advanced.payloadSize))
	})

	t.Run(name+"/v2ray client to mihomo server", func(t *testing.T) {
		echoAddr := startTLSMirrorInteropEcho(t)
		forward := startTLSMirrorInteropCarrierTLS(t, advanced.configureCarrierTLS)
		v2rayPort := tlsMirrorInteropReservePort(t)

		in, err := inbound.NewVmess(&inbound.VmessOption{
			BaseOption: inbound.BaseOption{
				NameStr: "vmess_tlsmirror_v2ray_client",
				Listen:  "127.0.0.1",
				Port:    "0",
			},
			Users: []inbound.VmessUser{
				{Username: "test", UUID: userUUID},
			},
			TLSMirrorConfig: inbound.TLSMirrorConfig{
				PrimaryKey:                  tlsMirrorInteropPrimaryKey,
				Dest:                        forward.addr,
				ExplicitNonceCipherSuites:   advanced.config.ExplicitNonceCipherSuites,
				TransportLayerPadding:       inbound.TLSMirrorTransportLayerPadding{Enabled: advanced.config.TransportLayerPadding.Enabled},
				ConnectionEnrolment:         tlsMirrorInteropInboundConnectionEnrolment(advanced),
				SequenceWatermarkingEnabled: advanced.config.SequenceWatermarkingEnabled,
			},
		})
		require.NoError(t, err)

		tunnel := tlsMirrorInteropDirectTunnel(t)
		require.NoError(t, in.Listen(tunnel))
		t.Cleanup(func() { _ = in.Close() })
		inboundPort := tlsMirrorInteropParsePort(t, tlsMirrorInteropPort(in.Address()))

		config := tlsMirrorInteropClientConfig(t, v2rayPort.Port(), inboundPort, tlsMirrorInteropPort(echoAddr), userUUID, forward.certChainHash, advanced)
		startTLSMirrorInteropV2Ray(t, v2rayBin, config, v2rayPort, "")

		tlsMirrorInteropRoundTripWithRetry(t, func() (net.Conn, error) {
			return net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(v2rayPort.Port())))
		}, advanced.payloadSize)
	})
}

func tlsMirrorInteropV2RayBinary(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found, skip real v2ray tlsmirror interop test")
	}

	root := filepath.Join(os.TempDir(), "mihomo-v2ray-tlsmirror-interop", v2rayTLSMirrorInteropRef)
	binDir := filepath.Join(root, "bin")
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	v2rayBin := filepath.Join(binDir, "v2ray"+exe)
	if _, err := os.Stat(v2rayBin); err == nil {
		return v2rayBin
	}
	goVersion := tlsMirrorInteropGoVersion(t, goBin)
	goMajor, goMinor, ok := tlsMirrorInteropGoVersionMajorMinor(goVersion)
	if ok && goMajor == 1 && goMinor < 21 {
		t.Skipf("%s does not support GOTOOLCHAIN toolchain download, skip real v2ray tlsmirror interop test", goVersion)
	}

	require.NoError(t, os.RemoveAll(root))
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	tlsMirrorInteropGo(t, goBin, root, "mod", "init", "mihomo-v2ray-tlsmirror-interop")
	tlsMirrorInteropGo(t, goBin, root, "get", "github.com/v2fly/v2ray-core/v5@"+v2rayTLSMirrorInteropRef)
	if ok && (goMajor > 1 || goMajor == 1 && goMinor > 26) {
		tlsMirrorInteropGo(t, goBin, root, "get", "golang.org/x/net@"+v2rayTLSMirrorInteropXNetRef)
	}
	tlsMirrorInteropGo(t, goBin, root, "build", "-mod=mod", "-trimpath", "-o", v2rayBin, "github.com/v2fly/v2ray-core/v5/main")
	return v2rayBin
}

func tlsMirrorInteropGoVersion(t *testing.T, goBin string) string {
	t.Helper()
	cmd := exec.Command(goBin, "version")
	output, err := cmd.Output()
	require.NoError(t, err, "go version")
	return tlsMirrorInteropParseGoVersion(string(output))
}

func tlsMirrorInteropParseGoVersion(output string) string {
	for _, field := range strings.Fields(output) {
		if strings.HasPrefix(field, "go1.") {
			return field
		}
	}
	return ""
}

func tlsMirrorInteropGoVersionMajorMinor(version string) (int, int, bool) {
	version = strings.TrimPrefix(version, "go")
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorText := parts[1]
	for i, r := range minorText {
		if r < '0' || r > '9' {
			minorText = minorText[:i]
			break
		}
	}
	if minorText == "" {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func tlsMirrorInteropGo(t *testing.T, goBin, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(goBin, args...)
	cmd.Dir = dir
	cmd.Env = tlsMirrorInteropGoEnv()
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "go %s\n%s", strings.Join(args, " "), string(output))
}

func tlsMirrorInteropGoEnv() []string {
	env := os.Environ()
	hasGoToolchain := false
	for i, value := range env {
		if strings.HasPrefix(value, "GOTOOLCHAIN=") {
			env[i] = "GOTOOLCHAIN=auto"
			hasGoToolchain = true
		}
	}
	if !hasGoToolchain {
		env = append(env, "GOTOOLCHAIN=auto")
	}
	return env
}

func tlsMirrorInteropServerConfig(t *testing.T, listenPort int, forwardPort string, userID string, advanced tlsMirrorInteropAdvanced) []byte {
	t.Helper()
	forwardPortValue := tlsMirrorInteropParsePort(t, forwardPort)
	config := tlsMirrorInteropBaseConfig()
	config["inbounds"] = []any{map[string]any{
		"protocol": "vmess",
		"listen":   "127.0.0.1",
		"port":     listenPort,
		"settings": map[string]any{
			"users": []string{userID},
		},
		"streamSettings": tlsMirrorInteropStreamConfig(tlsMirrorInteropServerSettings(advanced, forwardPortValue), nil),
	}}
	config["outbounds"] = []any{tlsMirrorInteropDirectOutbound()}
	if advanced.config.ConnectionEnrolment != nil {
		config["router"] = map[string]any{
			"rule": []any{map[string]any{
				"tag": advanced.config.ConnectionEnrolment.PrimaryIngressOutbound,
				"domain": []any{map[string]any{
					"type":  "Full",
					"value": tlsMirrorInteropEnrollmentControlHost(t),
				}},
			}},
		}
	}
	return tlsMirrorInteropMarshalJSONConfig(t, config)
}

func tlsMirrorInteropClientConfig(t *testing.T, listenPort, serverPort int, targetPort string, userID, carrierCertHash string, advanced tlsMirrorInteropAdvanced) []byte {
	t.Helper()
	targetPortValue := tlsMirrorInteropParsePort(t, targetPort)
	config := tlsMirrorInteropBaseConfig()
	config["inbounds"] = []any{map[string]any{
		"protocol": "dokodemo-door",
		"listen":   "127.0.0.1",
		"port":     listenPort,
		"settings": map[string]any{
			"address":  "127.0.0.1",
			"port":     targetPortValue,
			"networks": "tcp",
		},
	}}
	config["outbounds"] = []any{
		map[string]any{
			"protocol":       "vmess",
			"tag":            "vmess-tlsmirror",
			"streamSettings": tlsMirrorInteropStreamConfig(tlsMirrorInteropClientSettings(advanced), tlsMirrorInteropSecuritySettings(advanced, carrierCertHash)),
			"settings": map[string]any{
				"address": "127.0.0.1",
				"port":    serverPort,
				"uuid":    userID,
			},
		},
		tlsMirrorInteropDirectOutbound(),
	}
	if advanced.config.ConnectionEnrolment != nil {
		controlAdvanced := advanced
		controlAdvanced.config.ConnectionEnrolment = nil
		config["outbounds"] = append(config["outbounds"].([]any), map[string]any{
			"protocol":       "vmess",
			"tag":            "vmess-tlsmirror-control",
			"streamSettings": tlsMirrorInteropStreamConfig(tlsMirrorInteropClientControlSettings(controlAdvanced), tlsMirrorInteropSecuritySettings(advanced, carrierCertHash)),
			"settings": map[string]any{
				"address": "127.0.0.1",
				"port":    serverPort,
				"uuid":    userID,
			},
		})
	}
	return tlsMirrorInteropMarshalJSONConfig(t, config)
}

func tlsMirrorInteropBaseConfig() map[string]any {
	return map[string]any{
		"log": map[string]any{
			"error": map[string]any{
				"type":  "Console",
				"level": "Debug",
			},
		},
	}
}

func tlsMirrorInteropStreamConfig(tlsMirrorSettings map[string]any, securitySettings map[string]any) map[string]any {
	config := map[string]any{
		"transport":         "tlsmirror",
		"transportSettings": tlsMirrorSettings,
	}
	if securitySettings != nil {
		config["security"] = "tls"
		config["securitySettings"] = securitySettings
	}
	return config
}

func tlsMirrorInteropServerSettings(advanced tlsMirrorInteropAdvanced, forwardPort int) map[string]any {
	settings := tlsMirrorInteropTLSMirrorSettings(advanced)
	settings["forwardAddress"] = "127.0.0.1"
	settings["forwardPort"] = forwardPort
	return settings
}

func tlsMirrorInteropClientSettings(advanced tlsMirrorInteropAdvanced) map[string]any {
	settings := tlsMirrorInteropTLSMirrorSettings(advanced)
	settings["carrierConnectionTag"] = "tlsmirror-carrier"
	settings["forwardTag"] = "direct"
	if advanced.config.ConnectionEnrolment != nil {
		settings["connectionEnrolment"].(map[string]any)["primaryEgressOutbound"] = "vmess-tlsmirror-control"
	}
	settings["embeddedTrafficGenerator"] = tlsMirrorInteropEmbeddedTrafficGeneratorSettings()
	return settings
}

func tlsMirrorInteropClientControlSettings(advanced tlsMirrorInteropAdvanced) map[string]any {
	settings := tlsMirrorInteropTLSMirrorSettings(advanced)
	settings["carrierConnectionTag"] = "tlsmirror-carrier-control"
	settings["forwardTag"] = "direct"
	settings["embeddedTrafficGenerator"] = tlsMirrorInteropEmbeddedTrafficGeneratorSettings()
	return settings
}

func tlsMirrorInteropEmbeddedTrafficGeneratorSettings() map[string]any {
	return map[string]any{
		"steps": []any{map[string]any{
			"host":                 "localhost",
			"path":                 "/",
			"method":               "GET",
			"connectionReady":      true,
			"connectionRecallExit": true,
			"waitTime": map[string]any{
				"baseNanoseconds": uint64(time.Second),
			},
			"nextStep": []any{map[string]any{
				"weight":       1,
				"gotoLocation": 0,
			}},
		}},
	}
}

func tlsMirrorInteropSecuritySettings(advanced tlsMirrorInteropAdvanced, carrierCertHash string) map[string]any {
	return map[string]any{
		"allowInsecureIfPinnedPeerCertificate": true,
		"pinnedPeerCertificateChainSha256":     []string{carrierCertHash},
		"serverName":                           "localhost",
		"minVersion":                           tlsMirrorInteropTLSVersion(advanced),
		"maxVersion":                           tlsMirrorInteropTLSVersion(advanced),
	}
}

func tlsMirrorInteropTLSMirrorSettings(advanced tlsMirrorInteropAdvanced) map[string]any {
	settings := map[string]any{
		"primaryKey":                  tlsMirrorInteropPrimaryKey,
		"sequenceWatermarkingEnabled": advanced.config.SequenceWatermarkingEnabled,
	}
	if advanced.config.ConnectionEnrolment != nil {
		settings["connectionEnrolment"] = map[string]any{
			"primaryIngressOutbound": advanced.config.ConnectionEnrolment.PrimaryIngressOutbound,
			"primaryEgressOutbound":  advanced.config.ConnectionEnrolment.PrimaryEgressOutbound,
		}
	}
	if advanced.config.TransportLayerPadding.Enabled {
		settings["transportLayerPadding"] = map[string]any{"enabled": true}
	}
	if advanced.tls12 {
		settings["explicitNonceCiphersuites"] = []uint32{0xc02b}
	}
	return settings
}

func tlsMirrorInteropOutboundConnectionEnrolment(advanced tlsMirrorInteropAdvanced) *outbound.TLSMirrorConnectionEnrolment {
	if advanced.config.ConnectionEnrolment == nil {
		return nil
	}
	return &outbound.TLSMirrorConnectionEnrolment{
		PrimaryIngressOutbound: advanced.config.ConnectionEnrolment.PrimaryIngressOutbound,
		PrimaryEgressOutbound:  advanced.config.ConnectionEnrolment.PrimaryEgressOutbound,
	}
}

func tlsMirrorInteropInboundConnectionEnrolment(advanced tlsMirrorInteropAdvanced) *inbound.TLSMirrorConnectionEnrolment {
	if advanced.config.ConnectionEnrolment == nil {
		return nil
	}
	return &inbound.TLSMirrorConnectionEnrolment{
		PrimaryIngressOutbound: advanced.config.ConnectionEnrolment.PrimaryIngressOutbound,
		PrimaryEgressOutbound:  advanced.config.ConnectionEnrolment.PrimaryEgressOutbound,
	}
}

func tlsMirrorInteropEnrollmentControlHost(t *testing.T) string {
	t.Helper()
	key, err := tlsmirror.DecodePrimaryKey(tlsMirrorInteropPrimaryKey)
	require.NoError(t, err)
	host, err := tlsmirror.ServerIdentifierHost(key)
	require.NoError(t, err)
	return host
}

func tlsMirrorInteropTLSVersion(advanced tlsMirrorInteropAdvanced) string {
	if advanced.tls12 {
		return "TLS1_2"
	}
	return "TLS1_3"
}

func tlsMirrorInteropDirectOutbound() map[string]any {
	return map[string]any{
		"protocol": "freedom",
		"tag":      "direct",
	}
}

func tlsMirrorInteropMarshalJSONConfig(t *testing.T, config map[string]any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	data = append(data, '\n')
	return data
}

func tlsMirrorInteropParsePort(t *testing.T, port string) int {
	t.Helper()
	value, err := strconv.Atoi(port)
	require.NoError(t, err)
	return value
}

func startTLSMirrorInteropV2Ray(t *testing.T, v2rayBin string, config []byte, port *tlsMirrorInteropReservedPort, waitAddr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, v2rayBin, "run", "-format=jsonv5")
	var output bytes.Buffer
	cmd.Stdin = bytes.NewReader(config)
	cmd.Stdout = &output
	cmd.Stderr = &output
	port.Release()
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	})

	if waitAddr == "" {
		time.Sleep(300 * time.Millisecond)
		return
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", waitAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("v2ray did not listen on %s\n%s", waitAddr, output.String())
}

func startTLSMirrorInteropCarrierTLS(t *testing.T, configure ...func(*tls.Config)) tlsMirrorInteropCarrier {
	t.Helper()
	certPEM, keyPEM, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	for _, configure := range configure {
		if configure != nil {
			configure(config)
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"))
				_, _ = io.Copy(io.Discard, reader)
			}()
		}
	}()
	return tlsMirrorInteropCarrier{
		addr:          ln.Addr().String(),
		fingerprint:   fingerprint,
		certChainHash: tlsMirrorInteropCertChainHash([]byte(certPEM)),
	}
}

func tlsMirrorInteropCertChainHash(certContent []byte) string {
	var hashValue []byte
	for {
		block, remain := pem.Decode(certContent)
		if block == nil {
			break
		}
		certHash := sha256.Sum256(block.Bytes)
		if hashValue == nil {
			hashValue = certHash[:]
		} else {
			chainHash := sha256.Sum256(append(hashValue, certHash[:]...))
			hashValue = chainHash[:]
		}
		certContent = remain
	}
	return base64.StdEncoding.EncodeToString(hashValue)
}

func startTLSMirrorInteropCarrierHTTP2(t *testing.T) tlsMirrorInteropCarrier {
	t.Helper()
	certPEM, keyPEM, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		Protocols: new(http.Protocols),
	}
	server.Protocols.SetHTTP2(true)
	server.Protocols.SetUnencryptedHTTP2(true)
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return tlsMirrorInteropCarrier{
		addr:          ln.Addr().String(),
		fingerprint:   fingerprint,
		certChainHash: tlsMirrorInteropCertChainHash([]byte(certPEM)),
	}
}

func startTLSMirrorInteropEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func tlsMirrorInteropDirectTunnel(t *testing.T) *TestTunnel {
	t.Helper()
	return &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			target, err := net.Dial("tcp", metadata.RemoteAddress())
			if err != nil {
				_ = conn.Close()
				return
			}
			N.Relay(target, conn)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			packet.Drop()
		},
		NatTableFn: func() C.NatTable {
			return nil
		},
		CloseFn: func() error {
			return nil
		},
		NewDialerFn: func() C.Dialer {
			return nil
		},
	}
}

func tlsMirrorInteropMetadata(t *testing.T, addr string) *C.Metadata {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	ip, err := netip.ParseAddr(host)
	require.NoError(t, err)
	portNum, err := net.LookupPort("tcp", port)
	require.NoError(t, err)
	return &C.Metadata{
		NetWork: C.TCP,
		DstIP:   ip,
		DstPort: uint16(portNum),
	}
}

func tlsMirrorInteropRoundTripWithRetry(t *testing.T, dial func() (net.Conn, error), payloadSize int) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, err := dial()
		if err == nil {
			err = tlsMirrorInteropRoundTripConn(conn, payloadSize)
		} else {
			err = fmt.Errorf("dial: %w", err)
		}
		if err == nil {
			return
		}
		lastErr = err
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			break
		}
		// v2ray-core registers the tlsmirror carrier outbound asynchronously on
		// first use, so slower builders may hit a startup-only timeout.
		time.Sleep(200 * time.Millisecond)
	}
	require.NoError(t, lastErr)
}

func tlsMirrorInteropRoundTripConn(conn net.Conn, payloadSize int) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if payloadSize == 0 {
		payloadSize = len("tlsmirror-interop-") * 256
	}
	payload := bytes.Repeat([]byte("x"), payloadSize)
	_, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	if err != nil {
		return fmt.Errorf("read full: %w", err)
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("unexpected payload: got %d bytes", len(got))
	}
	return nil
}

type tlsMirrorInteropReservedPort struct {
	ln   net.Listener
	port int
	once sync.Once
}

func tlsMirrorInteropReservePort(t *testing.T) *tlsMirrorInteropReservedPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := &tlsMirrorInteropReservedPort{
		ln:   ln,
		port: ln.Addr().(*net.TCPAddr).Port,
	}
	t.Cleanup(port.Release)
	return port
}

func (p *tlsMirrorInteropReservedPort) Port() int {
	return p.port
}

func (p *tlsMirrorInteropReservedPort) Release() {
	p.once.Do(func() {
		_ = p.ln.Close()
	})
}

func tlsMirrorInteropPort(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}
