package outboundgroup

import (
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/dlclark/regexp2"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

func getProvidersProxies(emptyFallback C.Proxy, providers []P.ProxyProvider, touch bool, filter string) []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range providers {
		if touch {
			provider.Touch()
		}
		proxies = append(proxies, provider.Proxies()...)
	}
	matchedProxies := []C.Proxy{}
	if len(filter) > 0 {
		var filterRegs []*regexp2.Regexp
		for _, filter := range strings.Split(filter, "`") {
			filterReg, err := regexp2.Compile(filter, regexp2.None)
			if err != nil {
				continue
			}
			filterRegs = append(filterRegs, filterReg)
		}
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range filterRegs {
			for _, p := range proxies {
				name := p.Name()
				if mat, _ := filterReg.MatchString(name); mat {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						matchedProxies = append(matchedProxies, p)
					}
				}
			}
		}
		// if no proxy matched, means bad filter, return all proxies
		if len(matchedProxies) > 0 {
			proxies = matchedProxies
		}
	}

	if len(proxies) == 0 {
		return append(proxies, emptyFallback)
	}
	return proxies
}

func doHealthCheck(providers []P.ProxyProvider, proxy C.Proxy) {
	for _, proxyProvider := range providers {
		for _, proxy2 := range proxyProvider.Proxies() {
			if proxy == proxy2 {
				go proxyProvider.HealthCheck()
			}
		}
	}
}
