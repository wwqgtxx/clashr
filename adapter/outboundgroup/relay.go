package outboundgroup

import (
	"context"
	"encoding/json"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
)

type Relay struct {
	*outbound.Base
	single    *singledo.Single[[]C.Proxy]
	providers []provider.ProxyProvider
	filter    string
}

// DialContext implements C.ProxyAdapter
func (r *Relay) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxies, chainProxies := r.proxies(metadata, true)

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().DialContext(ctx, metadata)
	case 1:
		return proxies[0].DialContext(ctx, metadata)
	}
	var d C.Dialer
	d = dialer.NewDialer()
	for _, proxy := range proxies[:len(proxies)-1] {
		d = proxydialer.New(proxy, d, false)
	}
	last := proxies[len(proxies)-1]
	conn, err := last.DialContextWithDialer(ctx, d, metadata)
	if err != nil {
		return nil, err
	}

	for i := len(chainProxies) - 2; i >= 0; i-- {
		conn.AppendToChains(chainProxies[i])
	}

	conn.AppendToChains(r)

	return conn, nil
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Relay) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	proxies, chainProxies := r.proxies(metadata, true)

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().ListenPacketContext(ctx, metadata)
	case 1:
		return proxies[0].ListenPacketContext(ctx, metadata)
	}

	var d C.Dialer
	d = dialer.NewDialer()
	for _, proxy := range proxies[:len(proxies)-1] {
		d = proxydialer.New(proxy, d, false)
	}
	last := proxies[len(proxies)-1]
	pc, err := last.ListenPacketWithDialer(ctx, d, metadata)
	if err != nil {
		return nil, err
	}

	for i := len(chainProxies) - 2; i >= 0; i-- {
		pc.AppendToChains(chainProxies[i])
	}

	pc.AppendToChains(r)

	return pc, nil
}

// SupportUDP implements C.ProxyAdapter
func (r *Relay) SupportUDP() bool {
	proxies, _ := r.proxies(nil, false)
	if len(proxies) == 0 { // C.Direct
		return true
	}
	for i := len(proxies) - 1; i >= 0; i-- {
		proxy := proxies[i]
		if !proxy.SupportUDP() {
			return false
		}
		if proxy.SupportUOT() {
			return true
		}
		switch proxy.SupportWithDialer() {
		case C.ALLNet:
		case C.UDP:
		default: // C.TCP and C.NONet
			return false
		}
	}
	return true
}

// MarshalJSON implements C.ProxyAdapter
func (r *Relay) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range r.rawProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": r.Type().String(),
		"all":  all,
	})
}

func (r *Relay) rawProxies(touch bool) []C.Proxy {
	elm, _, _ := r.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(r.providers, touch, r.filter), nil
	})

	return elm
}

func (r *Relay) proxies(metadata *C.Metadata, touch bool) ([]C.Proxy, []C.Proxy) {
	rawProxies := r.rawProxies(touch)

	var proxies []C.Proxy
	var chainProxies []C.Proxy
	var targetProxies []C.Proxy

	for n, proxy := range rawProxies {
		proxies = append(proxies, proxy)
		chainProxies = append(chainProxies, proxy)
		subproxy := proxy.Unwrap(metadata, touch)
		for subproxy != nil {
			chainProxies = append(chainProxies, subproxy)
			proxies[n] = subproxy
			subproxy = subproxy.Unwrap(metadata, touch)
		}
	}

	for _, proxy := range proxies {
		if proxy.Type() != C.Direct && proxy.Type() != C.Compatible {
			targetProxies = append(targetProxies, proxy)
		}
	}

	return targetProxies, chainProxies
}

func NewRelay(option *GroupCommonOption, providers []provider.ProxyProvider) *Relay {
	return &Relay{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.Relay,
		}),
		single:    singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		providers: providers,
		filter:    option.Filter,
	}
}
