package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type Selector struct {
	*outbound.Base
	disableUDP    bool
	filter        string
	single        *singledo.Single[C.Proxy]
	selected      string
	emptyFallback C.Proxy
	providers     []P.ProxyProvider
}

// DialContext implements C.ProxyAdapter
func (s *Selector) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.selectedProxy(true).DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Selector) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := s.selectedProxy(true).ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(s)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (s *Selector) SupportUDP() bool {
	if s.disableUDP {
		return false
	}

	return s.selectedProxy(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Selector) IsL3Protocol(metadata *C.Metadata) bool {
	return s.selectedProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (s *Selector) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range getProvidersProxies(s.emptyFallback, s.providers, false, s.filter) {
		all = append(all, proxy.Name())
	}

	return json.Marshal(map[string]any{
		"type":          s.Type().String(),
		"now":           s.Now(),
		"all":           all,
		"emptyFallback": s.emptyFallback.Name(),
	})
}

func (s *Selector) Now() string {
	return s.selectedProxy(false).Name()
}

func (s *Selector) Set(name string) error {
	for _, proxy := range getProvidersProxies(s.emptyFallback, s.providers, false, s.filter) {
		if proxy.Name() == name {
			s.ForceSet(name)
			return nil
		}
	}

	return errors.New("proxy not exist")
}

func (s *Selector) ForceSet(name string) {
	s.selected = name
	s.single.Reset()
}

// Unwrap implements C.ProxyAdapter
func (s *Selector) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return s.selectedProxy(touch)
}

func (s *Selector) selectedProxy(touch bool) C.Proxy {
	elm, _, _ := s.single.Do(func() (C.Proxy, error) {
		proxies := getProvidersProxies(s.emptyFallback, s.providers, touch, s.filter)
		for _, proxy := range proxies {
			if proxy.Name() == s.selected {
				return proxy, nil
			}
		}

		return proxies[0], nil
	})

	return elm
}

func (s *Selector) Touch() {
	for _, pd := range s.providers {
		pd.Touch()
	}
}

func (s *Selector) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Selector) Proxies() []C.Proxy {
	return getProvidersProxies(s.emptyFallback, s.providers, false, s.filter)
}

func NewSelector(option *GroupCommonOption, emptyFallback C.Proxy, providers []P.ProxyProvider) *Selector {
	return &Selector{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: option.Name,
			Type: C.Selector,
		}),
		single:        singledo.NewSingle[C.Proxy](defaultGetProxiesDuration),
		emptyFallback: emptyFallback,
		providers:     providers,
		selected:      emptyFallback.Name(),
		disableUDP:    option.DisableUDP,
		filter:        option.Filter,
	}
}
