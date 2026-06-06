package outboundgroup

import (
	"context"
	"encoding/json"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type Fallback struct {
	*outbound.Base
	disableUDP    bool
	filter        string
	single        *singledo.Single[[]C.Proxy]
	emptyFallback C.Proxy
	providers     []P.ProxyProvider
}

func (f *Fallback) Now() string {
	proxy := f.findAliveProxy(false)
	return proxy.Name()
}

// DialContext implements C.ProxyAdapter
func (f *Fallback) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxy := f.findAliveProxy(true)
	c, err := proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(f)
	} else {
		doHealthCheck(f.providers, proxy)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			doHealthCheck(f.providers, proxy)
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (f *Fallback) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := f.findAliveProxy(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(f)
	} else {
		doHealthCheck(f.providers, proxy)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (f *Fallback) SupportUDP() bool {
	if f.disableUDP {
		return false
	}

	proxy := f.findAliveProxy(false)
	return proxy.SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (f *Fallback) IsL3Protocol(metadata *C.Metadata) bool {
	return f.findAliveProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (f *Fallback) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range f.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":          f.Type().String(),
		"now":           f.Now(),
		"all":           all,
		"emptyFallback": f.emptyFallback.Name(),
	})
}

// Unwrap implements C.ProxyAdapter
func (f *Fallback) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxy := f.findAliveProxy(touch)
	return proxy
}

func (f *Fallback) proxies(touch bool) []C.Proxy {
	elm, _, shared := f.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(f.emptyFallback, f.providers, touch, f.filter), nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		f.Touch()
	}

	return elm
}

func (f *Fallback) findAliveProxy(touch bool) C.Proxy {
	proxies := f.proxies(touch)
	for _, proxy := range proxies {
		if proxy.Alive() && !provider.ProxyIsRed(proxy) {
			return proxy
		}
	}
	for _, proxy := range proxies {
		if proxy.Alive() {
			return proxy
		}
	}

	return proxies[0]
}

func (f *Fallback) Touch() {
	for _, pd := range f.providers {
		pd.Touch()
	}
}

func (f *Fallback) Providers() []P.ProxyProvider {
	return f.providers
}

func (f *Fallback) Proxies() []C.Proxy {
	return f.proxies(false)
}

func NewFallback(option *GroupCommonOption, emptyFallback C.Proxy, providers []P.ProxyProvider) *Fallback {
	return &Fallback{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: option.Name,
			Type: C.Fallback,
		}),
		single:        singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		emptyFallback: emptyFallback,
		providers:     providers,
		disableUDP:    option.DisableUDP,
		filter:        option.Filter,
	}
}
