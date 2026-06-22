package outboundgroup

import (
	"context"
	"encoding/json"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type URLTestOption struct {
	Tolerance uint16 `group:"tolerance,omitempty"`
}

type URLTest struct {
	*outbound.Base
	tolerance     uint16
	disableUDP    bool
	fastNode      C.Proxy
	filter        string
	single        *singledo.Single[[]C.Proxy]
	fastSingle    *singledo.Single[C.Proxy]
	emptyFallback C.Proxy
	providers     []P.ProxyProvider
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := u.fast(true)
	c, err = proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(u)
	} else {
		doHealthCheck(u.providers, proxy)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			doHealthCheck(u.providers, proxy)
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := u.fast(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(u)
	} else {
		doHealthCheck(u.providers, proxy)
	}
	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return u.fast(touch)
}

func (u *URLTest) proxies(touch bool) []C.Proxy {
	elm, _, _ := u.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(u.emptyFallback, u.providers, touch, u.filter), nil
	})

	return elm
}

func (u *URLTest) fast(touch bool) C.Proxy {
	elm, _, shared := u.fastSingle.Do(func() (C.Proxy, error) {
		proxies := u.proxies(touch)
		fast := proxies[0]
		min := fast.LastDelay()
		fastNotExist := true

		for _, proxy := range proxies[1:] {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.Alive() {
				continue
			}

			delay := proxy.LastDelay()
			if delay < min {
				fast = proxy
				min = delay
			}
		}

		// tolerance
		if u.fastNode == nil || fastNotExist || !u.fastNode.Alive() || u.fastNode.LastDelay() > fast.LastDelay()+u.tolerance {
			u.fastNode = fast
		}

		return u.fastNode, nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		u.Touch()
	}

	return elm.(C.Proxy)
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}

	return u.fast(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (u *URLTest) IsL3Protocol(metadata *C.Metadata) bool {
	return u.fast(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range u.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":          u.Type().String(),
		"now":           u.Now(),
		"all":           all,
		"emptyFallback": u.emptyFallback.Name(),
	})
}

func (u *URLTest) Touch() {
	for _, pd := range u.providers {
		pd.Touch()
	}
}

func (u *URLTest) Providers() []P.ProxyProvider {
	return u.providers
}

func (u *URLTest) Proxies() []C.Proxy {
	return u.proxies(false)
}

func NewURLTest(option GroupCommonOption, urlTestOption URLTestOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*URLTest, error) {
	urlTest := &URLTest{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: option.Name,
			Type: C.URLTest,
		}),
		single:        singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		fastSingle:    singledo.NewSingle[C.Proxy](time.Second * 10),
		emptyFallback: emptyFallback,
		providers:     providers,
		disableUDP:    option.DisableUDP,
		filter:        option.Filter,
		tolerance:     urlTestOption.Tolerance,
	}

	return urlTest, nil
}
