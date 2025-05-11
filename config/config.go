package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	_ "unsafe"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/fakeip"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/dns"
	L "github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
	T "github.com/metacubex/mihomo/tunnel"

	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Mode                    T.TunnelMode `json:"mode"`
	LogLevel                log.LogLevel `json:"log-level"`
	IPv6                    bool         `json:"ipv6"`
	Interface               string       `json:"interface-name"`
	RoutingMark             int          `json:"routing-mark"`
	HealthCheckURL          string       `json:"health-check-url"`
	HealthCheckLazyDefault  bool         `json:"health-check-lazy-default"`
	TouchAfterLazyPassNum   int          `json:"touch-after-lazy-pass-num"`
	PreResolveProcessName   bool         `json:"pre-resolve-process-name"`
	TCPConcurrent           bool         `json:"tcp-concurrent"`
	Sniffing                bool         `json:"sniffing"`
	GlobalClientFingerprint string       `json:"global-client-fingerprint"`
	GlobalUA                string       `json:"global-ua"`
	ETagSupport             bool         `json:"etag-support"`
	KeepAliveIdle           int          `json:"keep-alive-idle"`
	KeepAliveInterval       int          `json:"keep-alive-interval"`
	DisableKeepAlive        bool         `json:"disable-keep-alive"`
}

// Inbound
type Inbound struct {
	Port              int            `json:"port"`
	SocksPort         int            `json:"socks-port"`
	RedirPort         int            `json:"redir-port"`
	TProxyPort        int            `json:"tproxy-port"`
	MixedPort         int            `json:"mixed-port"`
	Tun               LC.Tun         `json:"tun"`
	TuicServer        LC.TuicServer  `json:"tuic-server"`
	MixECConfig       string         `json:"mixec-config"`
	ShadowSocksConfig string         `json:"ss-config"`
	VmessConfig       string         `json:"vmess-config"`
	MTProxyConfig     string         `json:"mtproxy-config"`
	Authentication    []string       `json:"authentication"`
	SkipAuthPrefixes  []netip.Prefix `json:"skip-auth-prefixes"`
	LanAllowedIPs     []netip.Prefix `json:"lan-allowed-ips"`
	LanDisAllowedIPs  []netip.Prefix `json:"lan-disallowed-ips"`
	AllowLan          bool           `json:"allow-lan"`
	BindAddress       string         `json:"bind-address"`
	InboundTfo        bool           `json:"inbound-tfo"`
	InboundMPTCP      bool           `json:"inbound-mptcp"`
}

// Controller
type Controller struct {
	ExternalController     string
	ExternalControllerTLS  string
	ExternalControllerUnix string
	ExternalControllerPipe string
	ExternalUI             string
	ExternalDohServer      string
	Secret                 string
	Cors                   Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

// Experimental config
type Experimental struct {
	QUICGoDisableGSO bool
	QUICGoDisableECN bool
	IP4PEnable       bool
}

// NTP config
type NTP struct {
	Enable        bool
	Server        string
	Port          int
	Interval      int
	DialerProxy   string
	WriteToSystem bool
}

// DNS config
type DNS struct {
	Enable                bool
	IPv6                  bool
	NameServer            []dns.NameServer
	Fallback              []dns.NameServer
	FallbackIPFilter      []C.IpMatcher
	FallbackDomainFilter  []C.DomainMatcher
	Listen                string
	EnhancedMode          C.DNSMode
	DefaultNameserver     []dns.NameServer
	CacheAlgorithm        string
	FakeIPRange           *fakeip.Pool
	Hosts                 *trie.DomainTrie[netip.Addr]
	NameServerPolicy      []dns.Policy
	ProxyServerNameserver []dns.NameServer
	DirectNameServer      []dns.NameServer
	DirectFollowPolicy    bool
	SearchDomains         []string
}

// Profile config
type Profile struct {
	StoreSelected bool
	StoreFakeIP   bool
}

// TLS config
type TLS struct {
	Certificate     string
	PrivateKey      string
	CustomTrustCert []string
}

// Config is mihomo config manager
type Config struct {
	General       *General
	Controller    *Controller
	Experimental  *Experimental
	DNS           *DNS
	Hosts         *trie.DomainTrie[netip.Addr]
	Profile       *Profile
	Rules         []C.Rule
	SubRules      map[string][]C.Rule
	RuleProviders map[string]providerTypes.RuleProvider
	Users         []auth.AuthUser
	Proxies       map[string]C.Proxy
	Providers     map[string]providerTypes.ProxyProvider
	Listeners     map[string]C.InboundListener
	Tunnels       []LC.Tunnel
	Sniffer       *sniffer.Config
	TLS           *TLS
}

type RawCors struct {
	AllowOrigins        []string `yaml:"allow-origins" json:"allow-origins"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network" json:"allow-private-network"`
}

type RawDNS struct {
	Enable                       bool                                `yaml:"enable" json:"enable"`
	IPv6                         bool                                `yaml:"ipv6" json:"ipv6"`
	UseHosts                     bool                                `yaml:"use-hosts" json:"use-hosts"`
	UseSystemHosts               bool                                `yaml:"use-system-hosts" json:"use-system-hosts"`
	RespectRules                 bool                                `yaml:"respect-rules" json:"respect-rules"`
	NameServer                   []string                            `yaml:"nameserver" json:"nameserver"`
	Fallback                     []string                            `yaml:"fallback" json:"fallback"`
	FallbackFilter               RawFallbackFilter                   `yaml:"fallback-filter" json:"fallback-filter"`
	Listen                       string                              `yaml:"listen" json:"listen"`
	EnhancedMode                 C.DNSMode                           `yaml:"enhanced-mode" json:"enhanced-mode"`
	FakeIPRange                  string                              `yaml:"fake-ip-range" json:"fake-ip-range"`
	FakeIPFilter                 []string                            `yaml:"fake-ip-filter" json:"fake-ip-filter"`
	FakeIPFilterMode             C.FilterMode                        `yaml:"fake-ip-filter-mode" json:"fake-ip-filter-mode"`
	DefaultNameserver            []string                            `yaml:"default-nameserver" json:"default-nameserver"`
	CacheAlgorithm               string                              `yaml:"cache-algorithm" json:"cache-algorithm"`
	NameServerPolicy             *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy" json:"nameserver-policy"`
	ProxyServerNameserver        []string                            `yaml:"proxy-server-nameserver" json:"proxy-server-nameserver"`
	DirectNameServer             []string                            `yaml:"direct-nameserver" json:"direct-nameserver"`
	DirectNameServerFollowPolicy bool                                `yaml:"direct-nameserver-follow-policy" json:"direct-nameserver-follow-policy"`
	SearchDomains                []string                            `yaml:"search-domains" json:"search-domains"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip" json:"geoip"`
	GeoIPCode string   `yaml:"geoip-code" json:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr" json:"ipcidr"`
	Domain    []string `yaml:"domain" json:"domain"`
}

type RawNTP struct {
	Enable        bool   `yaml:"enable" json:"enable"`
	Server        string `yaml:"server" json:"server"`
	Port          int    `yaml:"port" json:"port"`
	Interval      int    `yaml:"interval" json:"interval"`
	DialerProxy   string `yaml:"dialer-proxy" json:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system" json:"write-to-system"`
}

type RawExperimental struct {
	QUICGoDisableGSO bool `yaml:"quic-go-disable-gso"`
	QUICGoDisableECN bool `yaml:"quic-go-disable-ecn"`
	IP4PEnable       bool `yaml:"dialer-ip4p-convert"`
}

type RawProfile struct {
	StoreSelected bool `yaml:"store-selected" json:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip" json:"store-fake-ip"`
}

type RawSniffer struct {
	Enable          bool     `yaml:"enable" json:"enable"`
	OverrideDest    bool     `yaml:"override-destination" json:"override-destination"`
	Sniffing        []string `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string `yaml:"force-domain" json:"force-domain"`
	SkipSrcAddress  []string `yaml:"skip-src-address" json:"skip-src-address"`
	SkipDstAddress  []string `yaml:"skip-dst-address" json:"skip-dst-address"`
	SkipDomain      []string `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool     `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool     `yaml:"parse-pure-ip" json:"parse-pure-ip"`

	Sniff map[string]RawSniffingConfig `yaml:"sniff" json:"sniff"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports" json:"ports"`
	OverrideDest *bool    `yaml:"override-destination" json:"override-destination"`
}

type RawTLS struct {
	Certificate     string   `yaml:"certificate" json:"certificate"`
	PrivateKey      string   `yaml:"private-key" json:"private-key"`
	CustomTrustCert []string `yaml:"custom-certifactes" json:"custom-certifactes"`
}

type RawConfig struct {
	Port                    int            `yaml:"port" json:"port"`
	SocksPort               int            `yaml:"socks-port" json:"socks-port"`
	RedirPort               int            `yaml:"redir-port" json:"redir-port"`
	TProxyPort              int            `yaml:"tproxy-port" json:"tproxy-port"`
	MixedPort               int            `yaml:"mixed-port" json:"mixed-port"`
	MixECConfig             string         `yaml:"mixec-config" json:"mix-ec-config"`
	ShadowSocksConfig       string         `yaml:"ss-config" json:"shadow-socks-config"`
	VmessConfig             string         `yaml:"vmess-config" json:"vmess-config"`
	MTProxyConfig           string         `yaml:"mtproxy-config" json:"mt-proxy-config"`
	InboundTfo              bool           `yaml:"inbound-tfo" json:"inbound-tfo"`
	InboundMPTCP            bool           `yaml:"inbound-mptcp" json:"inbound-mptcp"`
	Authentication          []string       `yaml:"authentication" json:"authentication"`
	SkipAuthPrefixes        []netip.Prefix `yaml:"skip-auth-prefixes" json:"skip-auth-prefixes"`
	LanAllowedIPs           []netip.Prefix `yaml:"lan-allowed-ips" json:"lan-allowed-i-ps"`
	LanDisAllowedIPs        []netip.Prefix `yaml:"lan-disallowed-ips" json:"lan-dis-allowed-i-ps"`
	AllowLan                bool           `yaml:"allow-lan" json:"allow-lan"`
	BindAddress             string         `yaml:"bind-address" json:"bind-address"`
	Mode                    T.TunnelMode   `yaml:"mode" json:"mode"`
	LogLevel                log.LogLevel   `yaml:"log-level" json:"log-level"`
	IPv6                    bool           `yaml:"ipv6" json:"ipv6"`
	ExternalController      string         `yaml:"external-controller" json:"external-controller"`
	ExternalControllerPipe  string         `yaml:"external-controller-pipe" json:"external-controller-pipe"`
	ExternalControllerUnix  string         `yaml:"external-controller-unix" json:"external-controller-unix"`
	ExternalControllerTLS   string         `yaml:"external-controller-tls" json:"external-controller-tls"`
	ExternalControllerCors  RawCors        `yaml:"external-controller-cors" json:"external-controller-cors"`
	ExternalUI              string         `yaml:"external-ui" json:"external-ui"`
	ExternalDohServer       string         `yaml:"external-doh-server" json:"external-doh-server"`
	Secret                  string         `yaml:"secret" json:"secret"`
	Interface               string         `yaml:"interface-name" json:"interface"`
	RoutingMark             int            `yaml:"routing-mark" json:"routing-mark"`
	Tunnels                 []LC.Tunnel    `yaml:"tunnels" json:"tunnels"`
	HealthCheckURL          string         `yaml:"health-check-url" json:"health-check-url"`
	HealthCheckLazyDefault  bool           `yaml:"health-check-lazy-default" json:"health-check-lazy-default"`
	TouchAfterLazyPassNum   int            `yaml:"touch-after-lazy-pass-num" json:"touch-after-lazy-pass-num"`
	PreResolveProcessName   bool           `yaml:"pre-resolve-process-name" json:"pre-resolve-process-name"`
	TCPConcurrent           bool           `yaml:"tcp-concurrent" json:"tcp-concurrent"`
	GlobalClientFingerprint string         `yaml:"global-client-fingerprint" json:"global-client-fingerprint"`
	GlobalUA                string         `yaml:"global-ua" json:"global-ua"`
	ETagSupport             bool           `yaml:"etag-support" json:"etag-support"`
	KeepAliveIdle           int            `yaml:"keep-alive-idle" json:"keep-alive-idle"`
	KeepAliveInterval       int            `yaml:"keep-alive-interval" json:"keep-alive-interval"`
	DisableKeepAlive        bool           `yaml:"disable-keep-alive" json:"disable-keep-alive"`

	ProxyProvider map[string]map[string]any `yaml:"proxy-providers" json:"proxy-provider"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers" json:"rule-provider"`
	Proxy         []map[string]any          `yaml:"proxies" json:"proxy"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups" json:"proxy-group"`
	Rule          []string                  `yaml:"rules" json:"rule"`
	SubRules      map[string][]string       `yaml:"sub-rules" json:"sub-rules"`
	Listeners     []map[string]any          `yaml:"listeners" json:"listeners"`
	Hosts         map[string]string         `yaml:"hosts" json:"hosts"`
	DNS           RawDNS                    `yaml:"dns" json:"dns"`
	NTP           RawNTP                    `yaml:"ntp" json:"ntp"`
	Tun           LC.Tun                    `yaml:"tun" json:"tun"`
	TuicServer    LC.TuicServer             `yaml:"tuic-server" json:"tuic-server"`
	Experimental  RawExperimental           `yaml:"experimental" json:"experimental"`
	Profile       RawProfile                `yaml:"profile" json:"profile"`
	Sniffer       RawSniffer                `yaml:"sniffer" json:"sniffer"`
	TLS           RawTLS                    `yaml:"tls" json:"tls"`
}

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func DefaultRawConfig() *RawConfig {
	rawCfg := &RawConfig{
		InboundTfo:             true,
		AllowLan:               false,
		BindAddress:            "*",
		LanAllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		Mode:                   T.Rule,
		Authentication:         []string{},
		LogLevel:               log.INFO,
		HealthCheckURL:         "",
		HealthCheckLazyDefault: true,
		TouchAfterLazyPassNum:  0,
		PreResolveProcessName:  false,
		TCPConcurrent:          true,
		GlobalUA:               "clash.meta/" + C.Version,
		ETagSupport:            true,
		DNS: RawDNS{
			Enable:      true,
			IPv6:        true,
			UseHosts:    true,
			FakeIPRange: "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"tcp://114.114.114.114",
				"223.5.5.5",
				"tcp://223.5.5.5",
				"8.8.8.8",
				"tcp://8.8.8.8",
				"1.0.0.1",
				"tcp://1.0.0.1",
				"system://",
			},
			NameServer: []string{
				"https://8.8.8.8/dns-query",
				"https://1.0.0.1/dns-query",
				"https://[2001:4860:4860::8888]/dns-query",
				"https://[2606:4700:4700::1111]/dns-query",
			},
			FakeIPFilter: []string{
				"dns.msftnsci.com",
				"www.msftnsci.com",
				"www.msftconnecttest.com",
			},
			FakeIPFilterMode: C.FilterBlackList,
		},
		Tun: LC.Tun{
			Enable:              false,
			Stack:               C.TunSystem,
			DNSHijack:           []string{},
			AutoDetectInterface: true,
			AutoRoute:           true,
			Inet4Address:        []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
		TuicServer: LC.TuicServer{
			Enable:                false,
			Token:                 nil,
			Users:                 nil,
			Certificate:           "",
			PrivateKey:            "",
			Listen:                "",
			CongestionController:  "",
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		},
		Experimental: RawExperimental{
			// https://github.com/quic-go/quic-go/issues/4178
			// Quic-go currently cannot automatically fall back on platforms that do not support ecn, so this feature is turned off by default.
			QUICGoDisableECN: true,
		},
		Profile: RawProfile{
			StoreSelected: true,
		},
		Sniffer: RawSniffer{
			Enable:          true,
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			ForceDnsMapping: true,
			ParsePureIp:     false,
			Sniff: map[string]RawSniffingConfig{
				snifferTypes.HTTP.String(): {Ports: []string{"80"}},
				snifferTypes.TLS.String():  {Ports: []string{"443"}},
			},
		},
		ExternalControllerCors: RawCors{
			AllowOrigins:        []string{"*"},
			AllowPrivateNetwork: true,
		},
	}
	rawCfg.DNS.RespectRules = true
	rawCfg.DNS.ProxyServerNameserver = rawCfg.DNS.DefaultNameserver
	rawCfg.DNS.DirectNameServer = rawCfg.DNS.DefaultNameserver
	return rawCfg
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := DefaultRawConfig()

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	// We need to temporarily apply some configuration in general and roll back after parsing the complete configuration.
	// The loading and downloading of geodata in the parseRules and parseRuleProviders rely on these.
	// This implementation is very disgusting, but there is currently no better solution
	rollback := temporaryUpdateGeneral(config.General)
	defer rollback()

	controller, err := parseController(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Controller = controller

	experimental, err := parseExperimental(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Experimental = experimental

	profile, err := parseProfile(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Profile = profile

	tlsCfg, err := parseTLS(rawCfg)
	if err != nil {
		return nil, err
	}
	config.TLS = tlsCfg

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	listener, err := parseListeners(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Listeners = listener

	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RuleProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, subRules, "rules")
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// verify tunnels
	for _, t := range config.Tunnels {
		if len(t.Proxy) > 0 {
			if _, ok := config.Proxies[t.Proxy]; !ok {
				return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
			}
		}
	}

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer, ruleProviders)
	if err != nil {
		return nil, err
	}

	return config, nil
}

//go:linkname temporaryUpdateGeneral
func temporaryUpdateGeneral(general *General) func()

func parseGeneral(cfg *RawConfig) (*General, error) {
	mihomoHttp.SetUA(cfg.GlobalUA)
	resource.SetETag(cfg.ETagSupport)

	externalUI := cfg.ExternalUI

	// checkout externalUI exist
	if externalUI != "" {
		externalUI = C.Path.Resolve(externalUI)

		if _, err := os.Stat(externalUI); os.IsNotExist(err) {
			return nil, fmt.Errorf("external-ui: %s not exist", externalUI)
		}
	}

	return &General{
		Inbound: Inbound{
			Port:              cfg.Port,
			SocksPort:         cfg.SocksPort,
			RedirPort:         cfg.RedirPort,
			TProxyPort:        cfg.TProxyPort,
			MixedPort:         cfg.MixedPort,
			Tun:               cfg.Tun,
			TuicServer:        cfg.TuicServer,
			MixECConfig:       cfg.MixECConfig,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			MTProxyConfig:     cfg.MTProxyConfig,
			AllowLan:          cfg.AllowLan,
			SkipAuthPrefixes:  cfg.SkipAuthPrefixes,
			LanAllowedIPs:     cfg.LanAllowedIPs,
			LanDisAllowedIPs:  cfg.LanDisAllowedIPs,
			BindAddress:       cfg.BindAddress,
			InboundTfo:        cfg.InboundTfo,
			InboundMPTCP:      cfg.InboundMPTCP,
		},
		Mode:                    cfg.Mode,
		LogLevel:                cfg.LogLevel,
		IPv6:                    cfg.IPv6,
		Interface:               cfg.Interface,
		RoutingMark:             cfg.RoutingMark,
		HealthCheckURL:          cfg.HealthCheckURL,
		HealthCheckLazyDefault:  cfg.HealthCheckLazyDefault,
		TouchAfterLazyPassNum:   cfg.TouchAfterLazyPassNum,
		PreResolveProcessName:   cfg.PreResolveProcessName,
		TCPConcurrent:           cfg.TCPConcurrent,
		GlobalClientFingerprint: cfg.GlobalClientFingerprint,
		GlobalUA:                cfg.GlobalUA,
		ETagSupport:             cfg.ETagSupport,
		KeepAliveIdle:           cfg.KeepAliveIdle,
		KeepAliveInterval:       cfg.KeepAliveInterval,
		DisableKeepAlive:        cfg.DisableKeepAlive,
	}, nil
}

func parseController(cfg *RawConfig) (*Controller, error) {
	if path := cfg.ExternalUI; path != "" && !C.Path.IsSafePath(path) {
		return nil, fmt.Errorf("path is not subpath of home directory: %s", path)
	}
	return &Controller{
		ExternalController:     cfg.ExternalController,
		ExternalUI:             cfg.ExternalUI,
		Secret:                 cfg.Secret,
		ExternalControllerPipe: cfg.ExternalControllerPipe,
		ExternalControllerUnix: cfg.ExternalControllerUnix,
		ExternalControllerTLS:  cfg.ExternalControllerTLS,
		ExternalDohServer:      cfg.ExternalDohServer,
		Cors: Cors{
			AllowOrigins:        cfg.ExternalControllerCors.AllowOrigins,
			AllowPrivateNetwork: cfg.ExternalControllerCors.AllowPrivateNetwork,
		},
	}, nil
}

func parseExperimental(cfg *RawConfig) (*Experimental, error) {
	return &Experimental{
		QUICGoDisableGSO: cfg.Experimental.QUICGoDisableGSO,
		QUICGoDisableECN: cfg.Experimental.QUICGoDisableECN,
		IP4PEnable:       cfg.Experimental.IP4PEnable,
	}, nil
}

func parseNTP(cfg *RawConfig) (*NTP, error) {
	return &NTP{
		Enable:        cfg.NTP.Enable,
		Server:        cfg.NTP.Server,
		Port:          cfg.NTP.Port,
		Interval:      cfg.NTP.Interval,
		DialerProxy:   cfg.NTP.DialerProxy,
		WriteToSystem: cfg.NTP.WriteToSystem,
	}, nil
}

func parseProfile(cfg *RawConfig) (*Profile, error) {
	return &Profile{
		StoreSelected: cfg.Profile.StoreSelected,
		StoreFakeIP:   cfg.Profile.StoreFakeIP,
	}, nil
}

func parseTLS(cfg *RawConfig) (*TLS, error) {
	return &TLS{
		Certificate:     cfg.TLS.Certificate,
		PrivateKey:      cfg.TLS.PrivateKey,
		CustomTrustCert: cfg.TLS.CustomTrustCert,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxyList := []string{}
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider
	healthCheckLazyDefault := cfg.HealthCheckLazyDefault
	healthCheckURL := cfg.HealthCheckURL

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
	}

	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName {
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping, healthCheckLazyDefault, healthCheckURL)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	//for _, provider := range providersMap {
	//	log.Infoln("Start initial provider %s", provider.Name())
	//	if err := provider.Initial(); err != nil {
	//		return nil, nil, fmt.Errorf("initial proxy provider %s error: %w", provider.Name(), err)
	//	}
	//}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		_, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, healthCheckLazyDefault)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		// --------------------------------
		// merge to outboundgroup.ParseProxyGroup()
		// --------------------------------
		//groupName := group.Name()
		//if _, exist := proxies[groupName]; exist {
		//	return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		//}
		//
		//proxies[groupName] = adapter.NewProxy(group)
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	// initial compatible provider
	//for _, pd := range providersMap {
	//	if pd.VehicleType() != providerTypes.Compatible {
	//		continue
	//	}
	//
	//	log.Infoln("Start initial compatible provider %s", pd.Name())
	//	if err := pd.Initial(); err != nil {
	//		return nil, nil, err
	//	}
	//}

	ps := []C.Proxy{}
	for _, v := range proxyList {
		if proxies[v].Type() == C.Pass {
			continue
		}
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 0, true, provider.ReservedName, provider.ReservedName)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]providerTypes.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
	return proxies, providersMap, nil
}

func parseListeners(cfg *RawConfig) (listeners map[string]C.InboundListener, err error) {
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {
		listener, err := L.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		if _, exist := mapping[listener.Name()]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", listener.Name())
		}

		listeners[listener.Name()] = listener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (ruleProviders map[string]providerTypes.RuleProvider, err error) {
	RP.SetTunnel(T.Tunnel)
	ruleProviders = map[string]providerTypes.RuleProvider{}
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, err
		}

		ruleProviders[name] = rp
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	//for _, ruleProvider := range providersMap {
	//	log.Infoln("Start initial ruleProvider %s", ruleProvider.Name())
	//	if err := ruleProvider.Initial(); err != nil {
	//		return nil, nil, fmt.Errorf("initial rule ruleProvider %s error: %w", ruleProvider.Name(), err)
	//	}
	//}

	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, subRules, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		subRules[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, err
	}

	return
}

func verifySubRule(subRules map[string][]C.Rule) error {
	for name := range subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range subRules[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := subRules[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, n, rule.Adapter())
			}
			if isInArray(rule.Adapter(), arr) {
				arr = append(arr, rule.Adapter())
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(arr, "->"))
			}

			if err := verifySubRuleCircularReferences(rule.Adapter(), subRules, arr); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload  string
			target   string
			params   []string
			ruleName = strings.ToUpper(rule[0])
		)

		l := len(rule)

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" || ruleName == "DOMAIN-REGEX" || ruleName == "PROCESS-NAME-REGEX" || ruleName == "PROCESS-PATH-REGEX" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
			if l < 2 {
				return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
			}
			if l < 4 {
				rule = append(rule, make([]string, 4-l)...)
			}
			if ruleName == "MATCH" {
				l = 2
			}
			if l >= 3 {
				l = 3
				payload = rule[1]
			}
			target = rule[l-1]
			params = rule[l:]
		}
		if _, ok := proxies[target]; !ok {
			if ruleName != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie[netip.Addr], error) {
	tree := trie.New[netip.Addr]()

	// add default hosts
	if err := tree.Insert("localhost", netip.AddrFrom4([4]byte{127, 0, 0, 1})); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, ipStr := range cfg.Hosts {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid IP", ipStr)
			}
			tree.Insert(domain, ip)
		}
	}
	tree.Optimize()

	return tree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", err
		}
		host = host + ":" + defPort
		if hostname, port, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(hostname, port), nil
}

func parseNameServer(servers []string, respectRules bool) ([]dns.NameServer, error) {
	nameservers := []dns.NameServer{}

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		proxyName := u.Fragment

		var addr, dnsNetType string
		params := map[string]string{}
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls" // DNS over TLS
		case "http", "https":
			addr, err = hostWithDefaultPort(u.Host, "443")
			dnsNetType = "https" // DNS over HTTPS
			if u.Scheme == "http" {
				addr, err = hostWithDefaultPort(u.Host, "80")
			}
			if err == nil {
				proxyName = ""
				clearURL := url.URL{Scheme: u.Scheme, Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
				dnsNetType = "https" // DNS over HTTPS
				if len(u.Fragment) != 0 {
					for _, s := range strings.Split(u.Fragment, "&") {
						arr := strings.Split(s, "=")
						if len(arr) == 0 {
							continue
						} else if len(arr) == 1 {
							proxyName = arr[0]
						} else if len(arr) == 2 {
							params[arr[0]] = arr[1]
						} else {
							params[arr[0]] = strings.Join(arr[1:], "=")
						}
					}
				}
			}
		case "system":
			dnsNetType = "system" // System DNS
		case "dhcp":
			addr = server[len("dhcp://"):] // some special notation cannot be parsed by url
			dnsNetType = "dhcp"            // UDP from DHCP
			if addr == "system" {          // Compatible with old writing "dhcp://system"
				dnsNetType = "system"
				addr = ""
			}
		case "rcode":
			dnsNetType = "rcode"
			addr = u.Host
			switch addr {
			case "success",
				"format_error",
				"server_failure",
				"name_error",
				"not_implemented",
				"refused":
			default:
				err = fmt.Errorf("unsupported RCode type: %s", addr)
			}
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		if respectRules && len(proxyName) == 0 {
			proxyName = dns.RespectRules
		}

		nameserver := dns.NameServer{
			Net:       dnsNetType,
			Addr:      addr,
			ProxyName: proxyName,
			Params:    params,
		}

		if slices.ContainsFunc(nameservers, nameserver.Equal) {
			continue // skip duplicates nameserver
		}

		nameservers = append(nameservers, nameserver)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false)
	}
}

func parsePureDNSServer(server string) string {
	addPre := func(server string) string {
		return "udp://" + server
	}

	if server == "system" {
		return "system://"
	}

	if ip, err := netip.ParseAddr(server); err != nil {
		if strings.Contains(server, "://") {
			return server
		}
		return addPre(server)
	} else {
		if ip.Is4() {
			return addPre(server)
		} else {
			return addPre("[" + server + "]")
		}
	}
}

func parseNameServerPolicy(nsPolicy *orderedmap.OrderedMap[string, any], ruleProviders map[string]providerTypes.RuleProvider, respectRules bool) ([]dns.Policy, error) {
	var policy []dns.Policy

	for pair := nsPolicy.Oldest(); pair != nil; pair = pair.Next() {
		k, v := pair.Key, pair.Value
		servers, err := utils.ToStringSlice(v)
		if err != nil {
			return nil, err
		}
		nameservers, err := parseNameServer(servers, respectRules)
		if err != nil {
			return nil, err
		}
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, ",") {
			if strings.Contains(kLower, "rule-set:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "rule-set:" + subkey
					policy = append(policy, dns.Policy{Domain: newKey, NameServers: nameservers})
				}
			} else {
				subkeys := strings.Split(k, ",")
				for _, subkey := range subkeys {
					policy = append(policy, dns.Policy{Domain: subkey, NameServers: nameservers})
				}
			}
		} else {
			if strings.Contains(kLower, "geosite:") {
				policy = append(policy, dns.Policy{Domain: "geosite:" + k[8:], NameServers: nameservers})
			} else if strings.Contains(kLower, "rule-set:") {
				policy = append(policy, dns.Policy{Domain: "rule-set:" + k[9:], NameServers: nameservers})
			} else {
				policy = append(policy, dns.Policy{Domain: k, NameServers: nameservers})
			}
		}
	}

	for idx, p := range policy {
		domain, nameservers := p.Domain, p.NameServers

		if strings.HasPrefix(domain, "rule-set:") {
			domainSetName := domain[9:]
			matcher, err := parseDomainRuleSet(domainSetName, "dns.nameserver-policy", ruleProviders)
			if err != nil {
				return nil, err
			}
			policy[idx] = dns.Policy{Matcher: matcher, NameServers: nameservers}
		} else {
			if _, valid := trie.ValidAndSplitDomain(domain); !valid {
				return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
			}
		}
	}

	return policy, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[netip.Addr], ruleProviders map[string]providerTypes.RuleProvider) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	if cfg.RespectRules && len(cfg.ProxyServerNameserver) == 0 {
		return nil, fmt.Errorf("if “respect-rules” is turned on, “proxy-server-nameserver” cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		IPv6:         cfg.IPv6,
		EnhancedMode: cfg.EnhancedMode,
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, cfg.RespectRules); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, cfg.RespectRules); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, ruleProviders, cfg.RespectRules); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver, false); err != nil {
		return nil, err
	}

	if dnsCfg.DirectNameServer, err = parseNameServer(cfg.DirectNameServer, false); err != nil {
		return nil, err
	}
	dnsCfg.DirectFollowPolicy = cfg.DirectNameServerFollowPolicy

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, false); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		if ns.Net == "system" {
			continue
		}
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("default nameserver should be pure IP")
		}
	}

	fakeIPRange, err := netip.ParsePrefix(cfg.FakeIPRange)
	T.SetFakeIPRange(fakeIPRange)
	if cfg.EnhancedMode == C.DNSFakeIP {
		if err != nil {
			return nil, err
		}

		var fakeIPTrie *trie.DomainTrie[struct{}]
		if len(dnsCfg.Fallback) != 0 {
			fakeIPTrie = trie.New[struct{}]()
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = fakeIPTrie.Insert(fb.Addr, struct{}{})
			}
		}

		// fake ip skip host filter
		host, err := parseDomain(cfg.FakeIPFilter, fakeIPTrie, "dns.fake-ip-filter", ruleProviders)
		if err != nil {
			return nil, err
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       fakeIPRange,
			Size:        1000,
			Host:        host,
			Mode:        cfg.FakeIPFilterMode,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	if len(cfg.Fallback) != 0 {
		if cfg.FallbackFilter.GeoIP {
			matcher, err := RC.NewGEOIP(cfg.FallbackFilter.GeoIPCode, "dns.fallback-filter.geoip", false, true)
			if err != nil {
				return nil, fmt.Errorf("load GeoIP dns fallback filter error, %w", err)
			}
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher.DnsFallbackFilter())
		}
		if len(cfg.FallbackFilter.IPCIDR) > 0 {
			cidrSet := cidr.NewIpCidrSet()
			for idx, ipcidr := range cfg.FallbackFilter.IPCIDR {
				err = cidrSet.AddIpCidrForString(ipcidr)
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %w", idx, err)
				}
			}
			err = cidrSet.Merge()
			if err != nil {
				return nil, err
			}
			matcher := cidrSet // dns.fallback-filter.ipcidr
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher)
		}
		if len(cfg.FallbackFilter.Domain) > 0 {
			domainTrie := trie.New[struct{}]()
			for idx, domain := range cfg.FallbackFilter.Domain {
				err = domainTrie.Insert(domain, struct{}{})
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackDomain[%d] format error: %w", idx, err)
				}
			}
			matcher := domainTrie.NewDomainSet() // dns.fallback-filter.domain
			dnsCfg.FallbackDomainFilter = append(dnsCfg.FallbackDomainFilter, matcher)
		}
	}

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	if cfg.CacheAlgorithm == "" || cfg.CacheAlgorithm == "lru" {
		dnsCfg.CacheAlgorithm = "lru"
	} else {
		dnsCfg.CacheAlgorithm = "arc"
	}

	if len(cfg.SearchDomains) != 0 {
		for _, domain := range cfg.SearchDomains {
			if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
				return nil, errors.New("search domains should not start or end with '.'")
			}
			if strings.Contains(domain, ":") {
				return nil, errors.New("search domains are for ipv4 only and should not contain ports")
			}
		}
		dnsCfg.SearchDomains = cfg.SearchDomains
	}

	return dnsCfg, nil
}

func parseAuthentication(rawRecords []string) []auth.AuthUser {
	users := []auth.AuthUser{}
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}

func parseSniffer(snifferRaw RawSniffer, ruleProviders map[string]providerTypes.RuleProvider) (*sniffer.Config, error) {
	snifferConfig := &sniffer.Config{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}
	loadSniffer := make(map[snifferTypes.Type]sniffer.SnifferConfig)

	if len(snifferRaw.Sniff) != 0 {
		for sniffType, sniffConfig := range snifferRaw.Sniff {
			find := false
			ports, err := utils.NewUnsignedRangesFromList[uint16](sniffConfig.Ports)
			if err != nil {
				return nil, err
			}
			overrideDest := snifferRaw.OverrideDest
			if sniffConfig.OverrideDest != nil {
				overrideDest = *sniffConfig.OverrideDest
			}
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(sniffType) {
					find = true
					loadSniffer[snifferType] = sniffer.SnifferConfig{
						Ports:        ports,
						OverrideDest: overrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", sniffType)
			}
		}
	} else {
		if snifferConfig.Enable && len(snifferRaw.Sniffing) != 0 {
			// Deprecated: Use Sniff instead
			log.Warnln("Deprecated: Use Sniff instead")
		}
		globalPorts, err := utils.NewUnsignedRangesFromList[uint16](snifferRaw.Ports)
		if err != nil {
			return nil, err
		}

		for _, snifferName := range snifferRaw.Sniffing {
			find := false
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(snifferName) {
					find = true
					loadSniffer[snifferType] = sniffer.SnifferConfig{
						Ports:        globalPorts,
						OverrideDest: snifferRaw.OverrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
			}
		}
	}

	snifferConfig.Sniffers = loadSniffer

	forceDomain, err := parseDomain(snifferRaw.ForceDomain, nil, "sniffer.force-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in force-domain, error:%w", err)
	}
	snifferConfig.ForceDomain = forceDomain

	skipSrcAddress, err := parseIPCIDR(snifferRaw.SkipSrcAddress, nil, "sniffer.skip-src-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-src-address, error:%w", err)
	}
	snifferConfig.SkipSrcAddress = skipSrcAddress

	skipDstAddress, err := parseIPCIDR(snifferRaw.SkipDstAddress, nil, "sniffer.skip-src-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-dst-address, error:%w", err)
	}
	snifferConfig.SkipDstAddress = skipDstAddress

	skipDomain, err := parseDomain(snifferRaw.SkipDomain, nil, "sniffer.skip-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-domain, error:%w", err)
	}
	snifferConfig.SkipDomain = skipDomain

	return snifferConfig, nil
}

func parseIPCIDR(addresses []string, cidrSet *cidr.IpCidrSet, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (matchers []C.IpMatcher, err error) {
	var matcher C.IpMatcher
	for _, ipcidr := range addresses {
		ipcidrLower := strings.ToLower(ipcidr)
		if strings.Contains(ipcidrLower, "geoip:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, country := range subkeys {
				matcher, err = RC.NewGEOIP(country, adapterName, false, false)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else if strings.Contains(ipcidrLower, "rule-set:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseIPRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if cidrSet == nil {
				cidrSet = cidr.NewIpCidrSet()
			}
			err = cidrSet.AddIpCidrForString(ipcidr)
			if err != nil {
				return nil, err
			}
		}
	}
	if !cidrSet.IsEmpty() {
		err = cidrSet.Merge()
		if err != nil {
			return nil, err
		}
		matcher = cidrSet
		matchers = append(matchers, matcher)
	}
	return
}

func parseDomain(domains []string, domainTrie *trie.DomainTrie[struct{}], adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (matchers []C.DomainMatcher, err error) {
	var matcher C.DomainMatcher
	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		if strings.Contains(domainLower, "rule-set:") {
			subkeys := strings.Split(domain, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseDomainRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if domainTrie == nil {
				domainTrie = trie.New[struct{}]()
			}
			err = domainTrie.Insert(domain, struct{}{})
			if err != nil {
				return nil, err
			}
		}
	}
	if !domainTrie.IsEmpty() {
		matcher = domainTrie.NewDomainSet()
		matchers = append(matchers, matcher)
	}
	return
}

func parseIPRuleSet(domainSetName string, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (C.IpMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case providerTypes.Domain:
			return nil, fmt.Errorf("rule provider type error, except ipcidr,actual %s", rp.Behavior())
		case providerTypes.Classical:
			log.Warnln("%s provider is %s, only matching it contain ip rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}

func parseDomainRuleSet(domainSetName string, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (C.DomainMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case providerTypes.IPCIDR:
			return nil, fmt.Errorf("rule provider type error, except domain,actual %s", rp.Behavior())
		case providerTypes.Classical:
			log.Warnln("%s provider is %s, only matching it contain domain rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}
