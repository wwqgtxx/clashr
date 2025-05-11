package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/randv2"
	"golang.org/x/net/publicsuffix"
)

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

type LoadBalance struct {
	*outbound.Base
	disableUDP bool
	filter     string
	single     *singledo.Single[[]C.Proxy]
	providers  []provider.ProxyProvider
	strategyFn strategyFn
}

var errStrategy = errors.New("unsupported strategy")

func parseStrategy(config map[string]any) string {
	if strategy, ok := config["strategy"].(string); ok {
		return strategy
	}
	return "random"
}

func getKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}

	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if !metadata.DstIP.IsValid() {
		return ""
	}

	return metadata.DstIP.String()
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	defer func() {
		if err == nil {
			c.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)

	c, err = proxy.DialContext(ctx, metadata)
	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)
	return proxy.ListenPacketContext(ctx, metadata)
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

func strategyRandom() strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		aliveProxies := make([]C.Proxy, 0, len(proxies))
		for _, proxy := range proxies {
			if proxy.Alive() {
				aliveProxies = append(aliveProxies, proxy)
			}
		}
		aliveNum := int64(len(aliveProxies))
		if aliveNum == 0 {
			return proxies[0]
		}
		idx := randv2.Int64N(aliveNum)

		return aliveProxies[idx]
	}
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategyRoundRobin() strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		i := 0
		length := len(proxies)

		if touch {
			defer func() {
				idx = (idx + i) % length
			}()
		}

		for ; i < length; i++ {
			id := (idx + i) % length
			proxy := proxies[id]
			if proxy.Alive() {
				i++
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing() strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))
		buckets := int32(len(proxies))
		for i := 0; i < maxRetry; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := proxies[idx]
			if proxy.Alive() {
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range proxies {
			if proxy.Alive() {
				return proxy
			}
		}

		return proxies[0]
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := lb.proxies(touch)
	return lb.strategyFn(proxies, metadata, touch)
}

func (lb *LoadBalance) proxies(touch bool) []C.Proxy {
	elm, _, shared := lb.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(lb.providers, touch, lb.filter), nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		touchProviders(lb.providers)
	}

	return elm
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": lb.Type().String(),
		"all":  all,
	})
}

func NewLoadBalance(option *GroupCommonOption, providers []provider.ProxyProvider, strategy string) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch strategy {
	case "random":
		strategyFn = strategyRandom()
	case "consistent-hashing":
		strategyFn = strategyConsistentHashing()
	case "round-robin":
		strategyFn = strategyRoundRobin()
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, strategy)
	}
	return &LoadBalance{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.LoadBalance,
		}),
		single:     singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		providers:  providers,
		strategyFn: strategyFn,
		disableUDP: option.DisableUDP,
		filter:     option.Filter,
	}, nil
}
