package outboundgroup

import (
	"errors"
	"fmt"

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
	Name          string   `group:"name"`
	Type          string   `group:"type"`
	Proxies       []string `group:"proxies,omitempty"`
	Use           []string `group:"use,omitempty"`
	URL           string   `group:"url,omitempty"`
	Interval      int      `group:"interval,omitempty"`
	EmptyFallback string   `group:"empty-fallback,omitempty"`
	Lazy          bool     `group:"lazy,omitempty"`
	DisableUDP    bool     `group:"disable-udp,omitempty"`
	Filter        string   `group:"filter,omitempty"`
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, healthCheckLazyDefault bool) (ProxyGroup, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := GroupCommonOption{
		Lazy: healthCheckLazyDefault,
	}
	if err := decoder.Decode(config, &groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	if _, ok := config["routing-mark"]; ok {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["interface-name"]; ok {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["dialer-proxy"]; ok {
		log.Errorln("The group [%s] with dialer-proxy configuration is not allowed, please set it directly on the proxy instead", groupOption.Name)
	}

	groupName := groupOption.Name

	if groupOption.EmptyFallback == "" {
		groupOption.EmptyFallback = "COMPATIBLE"
	}
	emptyFallback, ok := proxyMap[groupOption.EmptyFallback]
	if !ok {
		return nil, fmt.Errorf("%s: empty fallback proxy '%s' not found", groupName, groupOption.EmptyFallback)
	}
	if _, ok := emptyFallback.Adapter().(ProxyGroup); ok { // strictly forbidden to fill in a proxy group for empty-fallback
		return nil, fmt.Errorf("%s: empty fallback proxy '%s' not found", groupName, groupOption.EmptyFallback)
	}

	providers := []P.ProxyProvider{}

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

	switch groupOption.Type {
	case "url-test":
		opt := URLTestOption{}
		err := decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewURLTest(groupOption, opt, emptyFallback, providers)
	case "select":
		opt := SelectorOption{}
		err := decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewSelector(groupOption, opt, emptyFallback, providers)
	case "fallback":
		opt := FallbackOption{}
		err := decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewFallback(groupOption, opt, emptyFallback, providers)
	case "load-balance":
		opt := LoadBalanceOption{}
		err := decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewLoadBalance(groupOption, opt, emptyFallback, providers)
	case "relay":
		return nil, fmt.Errorf("%w: The group [%s] with relay type was removed, please using dialer-proxy instead", errType, groupName)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}
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
