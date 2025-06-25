package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/nat"
	P "github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	queueCapacity  = 64  // chan capacity tcpQueue and udpQueue
	senderCapacity = 128 // chan capacity of PacketSender
)

var (
	udpInit       sync.Once
	udpQueues     []chan C.PacketAdapter
	natTable      = nat.New()
	rules         []C.Rule
	subRules      map[string][]C.Rule
	ruleProviders map[string]providerTypes.RuleProvider
	proxies       = make(map[string]C.Proxy)
	providers     map[string]provider.ProxyProvider
	configMux     sync.RWMutex

	// for compatibility, lazy init
	tcpQueue  chan C.ConnContext
	tcpInOnce sync.Once
	udpQueue  chan C.PacketAdapter
	udpInOnce sync.Once

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode = atomic.NewInt32Enum(P.FindProcessStrict)

	fakeIPRange netip.Prefix

	snifferDispatcher *sniffer.Dispatcher
	sniffingEnable    = false

	ruleUpdateCallback = utils.NewCallback[provider.RuleProvider]()
)

type tunnel struct{}

var Tunnel = tunnel{}
var _ C.Tunnel = Tunnel
var _ provider.Tunnel = Tunnel

func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	connCtx := icontext.NewConnContext(conn, metadata)
	handleTCPConn(connCtx)
}

func initUDP() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}

	udpQueues = make([]chan C.PacketAdapter, numUDPWorkers)
	for i := 0; i < numUDPWorkers; i++ {
		queue := make(chan C.PacketAdapter, queueCapacity)
		udpQueues[i] = queue
		go processUDP(queue)
	}
}

func (t tunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	udpInit.Do(initUDP)

	packetAdapter := C.NewPacketAdapter(packet, metadata)
	key := packetAdapter.Key()

	hash := utils.MapHash(key)
	queueNo := uint(hash) % uint(len(udpQueues))

	select {
	case udpQueues[queueNo] <- packetAdapter:
	default:
		packet.Drop()
	}
}

func (t tunnel) NatTable() C.NatTable {
	return natTable
}

func (t tunnel) Providers() map[string]provider.ProxyProvider {
	return providers
}

func (t tunnel) RuleProviders() map[string]provider.RuleProvider {
	return ruleProviders
}

func (t tunnel) RuleUpdateCallback() *utils.Callback[provider.RuleProvider] {
	return ruleUpdateCallback
}

func SetFakeIPRange(p netip.Prefix) {
	fakeIPRange = p
}

func FakeIPRange() netip.Prefix {
	return fakeIPRange
}

func SetSniffing(b bool) {
	if snifferDispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable
}

func UpdateSniffer(dispatcher *sniffer.Dispatcher) {
	configMux.Lock()
	snifferDispatcher = dispatcher
	sniffingEnable = dispatcher.Enable()
	configMux.Unlock()
}

// TCPIn return fan-in queue
// Deprecated: using Tunnel instead
func TCPIn() chan<- C.ConnContext {
	tcpInOnce.Do(func() {
		tcpQueue = make(chan C.ConnContext, queueCapacity)
		go func() {
			for connCtx := range tcpQueue {
				go handleTCPConn(connCtx)
			}
		}()
	})
	return tcpQueue
}

// UDPIn return fan-in udp queue
// Deprecated: using Tunnel instead
func UDPIn() chan<- C.PacketAdapter {
	udpInOnce.Do(func() {
		udpQueue = make(chan C.PacketAdapter, queueCapacity)
		go func() {
			for packet := range udpQueue {
				Tunnel.HandleUDPPacket(packet, packet.Metadata())
			}
		}()
	})
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

// RuleProviders return all compatible providers
func RuleProviders() map[string]providerTypes.RuleProvider {
	return ruleProviders
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRules map[string][]C.Rule, newProviders map[string]providerTypes.RuleProvider) {
	configMux.Lock()
	rules = newRules
	subRules = newSubRules
	ruleProviders = newProviders
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]provider.ProxyProvider {
	return providers
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

func FindProcessMode() P.FindProcessMode {
	return findProcessMode.Load()
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode P.FindProcessMode) {
	findProcessMode.Store(mode)
}

func fixMetadata(metadata *C.Metadata) {
	// first unmap dstIP
	metadata.DstIP = metadata.DstIP.Unmap()
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip.Unmap()
		metadata.Host = ""
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should lookup the hosts
				metadata.DstIP = node.Data()
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy]
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}
	var (
		resolved             bool
		attemptProcessLookup = metadata.Type != C.INNER
	)

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data()
		resolved = true
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if !resolved && metadata.Host != "" && !metadata.Resolved() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				ip, err := resolver.ResolveIP(ctx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				resolved = true
			}
		},
		FindProcess: func() {
			if attemptProcessLookup {
				attemptProcessLookup = false
				path, err := P.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort))
				if err != nil {
					log.Debugln("[Process] find process %s: %v", metadata.String(), err)
				} else {
					log.Debugln("[Process] %s from process %s", metadata.String(), path)
					metadata.ProcessPath = path
					metadata.Process = filepath.Base(path)
				}
			}
		},
	}

	switch FindProcessMode() {
	case P.FindProcessAlways:
		helper.FindProcess()
		helper.FindProcess = nil
	case P.FindProcessOff:
		helper.FindProcess = nil
	}

	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = match(metadata, helper)
	}
	return
}

// processUDP starts a loop to handle udp packet
func processUDP(queue chan C.PacketAdapter) {
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(packet C.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	if err := preHandleMetadata(metadata.Clone()); err != nil { // precheck without modify metadata
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	key := packet.Key()
	sender, loaded := natTable.GetOrCreate(key, func() C.PacketSender {
		sender := newPacketSender()
		if sniffingEnable && snifferDispatcher.Enable() {
			return snifferDispatcher.UDPSniff(packet, sender)
		}
		return sender
	})
	if !loaded {
		dial := func() (C.PacketConn, C.WriteBackProxy, error) {
			originMetadata := metadata  // save origin metadata
			metadata = metadata.Clone() // don't modify PacketAdapter's metadata

			if err := sender.DoSniff(metadata); err != nil {
				log.Warnln("[UDP] DoSniff error: %s", err.Error())
				return nil, nil, err
			}

			_ = preHandleMetadata(metadata) // error was pre-checked

			proxy, rule, err := resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				return nil, nil, err
			}

			dialMetadata := metadata.Pure()
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
			defer cancel()
			rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
				return proxy.ListenPacketContext(ctx, dialMetadata)
			}, func(err error) {
				logMetadataErr(metadata, rule, proxy, err)
			})
			if err != nil {
				return nil, nil, err
			}
			logMetadata(metadata, rule, rawPc)

			pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule, 0, 0, true)

			sender.AddMapping(originMetadata, dialMetadata)
			oAddrPort := dialMetadata.AddrPort()
			writeBackProxy := nat.NewWriteBackProxy(packet)

			go handleUDPToLocal(writeBackProxy, pc, sender, key, oAddrPort)
			return pc, writeBackProxy, nil
		}

		go func() {
			pc, proxy, err := dial()
			if err != nil {
				sender.Close()
				natTable.Delete(key)
				return
			}
			sender.Process(pc, proxy)
		}()
	}
	sender.Send(packet) // nonblocking
}

func handleTCPConn(connCtx C.ConnContext) {
	defer connCtx.Conn().Close()

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	preHandleFailed := false
	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		preHandleFailed = true
	}

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if sniffingEnable && snifferDispatcher.Enable() {
		// Try to sniff a domain when `preHandleMetadata` failed, this is usually
		// caused by a "Fake DNS record missing" error when enhanced-mode is fake-ip.
		if snifferDispatcher.TCPSniff(conn, metadata) {
			// we now have a domain name
			preHandleFailed = false
		}
	}

	// If both trials have failed, we can do nothing but give up
	if preHandleFailed {
		log.Debugln("[Metadata PreHandle] failed to sniff a domain for connection %s --> %s, give up",
			metadata.SourceDetail(), metadata.RemoteAddress())
		return
	}

	peekMutex := sync.Mutex{}
	if !conn.Peeked() {
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
			if dstIp := node.Data(); !FakeIPRange().Contains(dstIp) {
				dialMetadata.DstIP = node.Data()
				dialMetadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := retry(ctx, func(ctx context.Context) (remoteConn C.Conn, err error) {
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			return
		}

		if N.NeedHandshake(remoteConn) {
			defer func() {
				if err != nil {
					for _, chain := range remoteConn.Chains() {
						if chain == "REJECT" {
							err = nil
							return
						}
					}
					remoteConn = nil
				}
			}()
			peekMutex.Lock()
			defer peekMutex.Unlock()
			peekBytes, _ = conn.Peek(conn.Buffered())
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
		}
		return
	}, func(err error) {
		logMetadataErr(metadata, rule, proxy, err)
	})
	if err != nil {
		return
	}
	logMetadata(metadata, rule, remoteConn)

	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, int64(peekLen), 0, true)
	defer remoteConn.Close()

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	handleSocket(conn, remoteConn)
}

func logMetadataErr(metadata *C.Metadata, rule C.Rule, proxy C.ProxyAdapter, err error) {
	if rule == nil {
		log.Warnln("[%s] dial %s %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	} else {
		log.Warnln("[%s] dial %s (match %s/%s) %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	}
}

func logMetadata(metadata *C.Metadata, rule C.Rule, remoteConn C.Connection) {
	switch {
	case metadata.SpecialProxy != "":
		log.Infoln("[%s] %s --> %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), metadata.SpecialProxy)
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String())
		}
	case mode == Global:
		log.Infoln("[%s] %s --> %s using GLOBAL", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[%s] %s --> %s using DIRECT", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln("[%s] %s --> %s doesn't match any rule using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().Last())
	}
}

func match(metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	for _, rule := range getRules(metadata) {
		if matched, ada := rule.Match(metadata, helper); matched {
			adapter, ok := proxies[ada]
			if !ok {
				continue
			}

			// parse multi-layer nesting
			passed := false
			for adapter := adapter; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
				if adapter.Type() == C.Pass {
					passed = true
					break
				}
			}
			if passed {
				log.Debugln("%s match Pass rule", adapter.Name())
				continue
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%s UDP is not supported", adapter.Name())
				continue
			}

			return adapter, rule, nil
		}
	}

	return proxies["DIRECT"], nil, nil
}

func getRules(metadata *C.Metadata) []C.Rule {
	if sr, ok := subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return rules
	}
}

func shouldStopRetry(err error) bool {
	if errors.Is(err, resolver.ErrIPNotFound) {
		return true
	}
	if errors.Is(err, resolver.ErrIPVersion) {
		return true
	}
	if errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	return false
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	s := slowdown.New()
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if shouldStopRetry(err) {
				return
			}
			if s.Wait(ctx) == nil {
				continue
			} else {
				return
			}
		} else {
			break
		}
	}
	return
}
