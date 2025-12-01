package outboundgroup

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupport type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errMissHealthCheck   = errors.New("`url` or `interval` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	Name       string   `group:"name"`
	Type       string   `group:"type"`
	Proxies    []string `group:"proxies,omitempty"`
	Use        []string `group:"use,omitempty"`
	URL        string   `group:"url,omitempty"`
	Interval   int      `group:"interval,omitempty"`
	Lazy       bool     `group:"lazy,omitempty"`
	DisableUDP bool     `group:"disable-udp,omitempty"`
	Filter     string   `group:"filter,omitempty"`

	// removed configs, only for error logging
	Interface   string `group:"interface-name,omitempty"`
	RoutingMark int    `group:"routing-mark,omitempty"`
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, healthCheckLazyDefault bool) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{
		Lazy: healthCheckLazyDefault,
	}
	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	if groupOption.RoutingMark != 0 {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if groupOption.Interface != "" {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}

	groupName := groupOption.Name

	providers := []P.ProxyProvider{}

	ignoreURLTest := false

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, errMissProxy
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			return nil, err
		}

		if _, ok := providersMap[groupName]; ok {
			return nil, errDuplicateProvider
		}

		// select don't need health check
		if groupOption.Type == "select" || groupOption.Type == "relay" {
			hc := provider.NewHealthCheck(ps, "", 0, true, groupOption.Type, groupName)
			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, err
			}

			providers = append(providers, pd)
			providersMap[groupName] = pd
		} else {
			if groupOption.URL == "" || groupOption.Interval == 0 {
				return nil, errMissHealthCheck
			}

			ignoreURLTest = true
			hc := provider.NewHealthCheck(ps, groupOption.URL, uint(groupOption.Interval), groupOption.Lazy, groupOption.Type, groupName)
			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, err
			}

			providers = append(providers, pd)
			providersMap[groupName] = pd
		}
	}

	if len(groupOption.Use) != 0 {
		list, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, err
		}
		providers = append(providers, list...)
	} else {
		groupOption.Filter = ""
	}

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupOption, providers, opts...)
	case "select":
		group = NewSelector(groupOption, providers)
	case "fallback":
		group = NewFallback(groupOption, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		return NewLoadBalance(groupOption, providers, strategy)
	case "relay":
		group = NewRelay(groupOption, providers)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}

	if _, exist := proxyMap[groupName]; exist {
		return nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
	}

	proxyMap[groupName] = adapter.NewProxyFromGroup(group, ignoreURLTest)

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]P.ProxyProvider, list []string) ([]P.ProxyProvider, error) {
	var ps []P.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == P.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}
