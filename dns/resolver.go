package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
	ResetConnection()
}

type dnsCache interface {
	GetWithExpire(key string) (*D.Msg, time.Time, bool)
	SetWithExpire(key string, value *D.Msg, expire time.Time)
	Clear()
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	hosts                 *trie.DomainTrie[netip.Addr]
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []C.DomainMatcher
	fallbackIPFilters     []C.IpMatcher
	group                 singleflight.Group[*D.Msg]
	cache                 dnsCache
	policy                []dnsPolicy
	searchDomains         []string
	defaultResolver       *Resolver
}

// LookupIPPrimaryIPv4 request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) LookupIPPrimaryIPv4(ctx context.Context, host string) (ip []netip.Addr, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []netip.Addr, 1)

	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ip, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

// LookupIP request with TypeA and TypeAAAA
func (r *Resolver) LookupIP(ctx context.Context, host string) (ip []netip.Addr, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []netip.Addr, 1)

	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ip, err = r.lookupIP(ctx, host, D.TypeA)

	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ip = append(ip, ipv6s...)
	case <-time.After(100 * time.Millisecond):
		// wait ipv6 result
	}

	return ip, nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.MatchIp(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, rr := range msg.Answer {
		switch resource := rr.(type) {
		case *D.HTTPS:
			for _, value := range resource.Value {
				if echConfig, ok := value.(*D.SVCBECHConfig); ok {
					return echConfig.ECH, nil
				}
			}
		}
	}
	return nil, errors.New("no ECH config found in DNS records")
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	continueFetch := false
	defer func() {
		if continueFetch || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				_, _ = r.exchangeWithoutCache(ctx, m) // ignore result, just for putMsgToCache
			}()
		}
	}()

	q := m.Question[0]
	domain := msgToDomain(m)
	_, qTypeStr := msgToQtype(m)
	cacheM, expireTime, hit := r.cache.GetWithExpire(q.String())
	if hit {
		ips := msgToIP(cacheM)
		log.Debugln("[DNS] cache hit %s --> %s %s, expire at %s", domain, ips, qTypeStr, expireTime.Format("2006-01-02 15:04:05"))
		now := time.Now()
		msg = cacheM.Copy()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			continueFetch = true
		} else {
			// updating TTL by subtracting common delta time from each DNS record
			updateMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m)
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := m.Question[0]

	retryNum := 0
	retryMax := 3
	fn := func() (result *D.Msg, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout) // reset timeout in singleflight
		defer cancel()
		cache := false

		defer func() {
			if err != nil {
				result = &D.Msg{}
				result.Opcode = retryNum
				retryNum++
				return
			}

			msg := result

			if cache {
				// OPT RRs MUST NOT be cached, forwarded, or stored in or loaded from master files.
				msg.Extra = lo.Filter(msg.Extra, func(rr D.RR, index int) bool {
					return rr.Header().Rrtype != D.TypeOPT
				})
				putMsgToCache(r.cache, q.String(), q, msg)
			}
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			cache = true
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			result, cache, err = batchExchange(ctx, matched, m)
			return
		}
		result, cache, err = batchExchange(ctx, r.main, m)
		return
	}

	ch := r.group.DoChan(q.String(), fn)

	var result singleflight.Result[*D.Msg]

	select {
	case result = <-ch:
		break
	case <-ctx.Done():
		select {
		case result = <-ch: // maybe ctxDone and chFinish in same time, get DoChan's result as much as possible
			break
		default:
			go func() { // start a retrying monitor in background
				result := <-ch
				ret, err, shared := result.Val, result.Err, result.Shared
				if err != nil && !shared && ret.Opcode < retryMax { // retry
					r.group.DoChan(q.String(), fn)
				}
			}()
			return nil, ctx.Err()
		}
	}

	ret, err, shared := result.Val, result.Err, result.Shared
	if err != nil && !shared && ret.Opcode < retryMax { // retry
		r.group.DoChan(q.String(), fn)
	}

	if err == nil {
		msg = ret
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := r.msgToDomain(m)
	if domain == "" {
		return nil
	}

	for _, policy := range r.policy {
		if dnsClients := policy.Match(domain); len(dnsClients) > 0 {
			return dnsClients
		}
	}
	return nil
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := r.msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.MatchDomain(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	fallbackMsg := r.asyncExchange(ctx, r.fallback, m)
	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg = res.Msg // no need to wait for fallback result
				err = res.Error
				return msg, err
			}
		}
	}

	res = <-fallbackMsg
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) ([]netip.Addr, error) {

	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return nil, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	ips := msgToIP(msg)
	if len(ips) != 0 {
		return ips, nil
	} else if len(r.searchDomains) == 0 {
		return nil, resolver.ErrIPNotFound
	}

	// query provided search domains serially
	for _, domain := range r.searchDomains {
		q := &D.Msg{}
		q.SetQuestion(D.Fqdn(fmt.Sprintf("%s.%s", host, domain)), dnsType)
		msg, err := r.ExchangeContext(ctx, q)
		if err != nil {
			return nil, err
		}
		ips := msgToIP(msg)
		if len(ips) != 0 {
			return ips, nil
		}
	}

	return nil, resolver.ErrIPNotFound
}

func (r *Resolver) msgToDomain(msg *D.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimRight(msg.Question[0].Name, ".")
	}

	return ""
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, _, err := batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// Invalid return this resolver can or can't be used
func (r *Resolver) Invalid() bool {
	if r == nil {
		return false
	}
	return len(r.main) > 0
}

func (r *Resolver) ClearCache() {
	if r != nil && r.cache != nil {
		r.cache.Clear()
	}
}

func (r *Resolver) ResetConnection() {
	if r != nil {
		for _, c := range r.main {
			c.ResetConnection()
		}
		for _, c := range r.fallback {
			c.ResetConnection()
		}
		if dr := r.defaultResolver; dr != nil {
			dr.ResetConnection()
		}
	}
}

type NameServer struct {
	Net          string
	Addr         string
	ProxyAdapter C.ProxyAdapter
	ProxyName    string
	Params       map[string]string
}

func (ns NameServer) Equal(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	if ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) {
		return true
	}
	return false
}

type Policy struct {
	Domain      string
	Matcher     C.DomainMatcher
	NameServers []NameServer
}

type Config struct {
	Main, Fallback       []NameServer
	Default              []NameServer
	ProxyServer          []NameServer
	DirectServer         []NameServer
	DirectFollowPolicy   bool
	IPv6                 bool
	EnhancedMode         C.DNSMode
	FallbackIPFilter     []C.IpMatcher
	FallbackDomainFilter []C.DomainMatcher
	Pool                 *fakeip.Pool
	Hosts                *trie.DomainTrie[netip.Addr]
	Policy               []Policy
	SearchDomains        []string
	CacheAlgorithm       string
}

func (config Config) newCache() dnsCache {
	if config.CacheAlgorithm == "" || config.CacheAlgorithm == "lru" {
		return lru.New(lru.WithSize[string, *D.Msg](4096), lru.WithStale[string, *D.Msg](true))
	} else {
		return arc.New(arc.WithSize[string, *D.Msg](4096))
	}
}

type Resolvers struct {
	*Resolver
	ProxyResolver  *Resolver
	DirectResolver *Resolver
}

func (rs Resolvers) ClearCache() {
	rs.Resolver.ClearCache()
	rs.ProxyResolver.ClearCache()
	rs.DirectResolver.ClearCache()
}

func (rs Resolvers) ResetConnection() {
	rs.Resolver.ResetConnection()
	rs.ProxyResolver.ResetConnection()
	rs.DirectResolver.ResetConnection()
}

func NewResolver(config Config) (rs Resolvers) {
	defaultResolver := &Resolver{
		main:  transform(config.Default, nil),
		cache: config.newCache(),
	}

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP
				}
			}
			// not in cache
			dc := transform([]NameServer{ns}, defaultResolver)
			if len(dc) > 0 {
				dc := dc[0]
				nameServerCache = append(nameServerCache, struct {
					NameServer
					dnsClient
				}{NameServer: ns, dnsClient: dc})
				result = append(result, dc)
			}
		}
		return
	}

	r := &Resolver{
		ipv6:          config.IPv6,
		main:          cacheTransform(config.Main),
		cache:         config.newCache(),
		hosts:         config.Hosts,
		searchDomains: config.SearchDomains,
	}
	r.defaultResolver = defaultResolver
	rs.Resolver = r

	if len(config.ProxyServer) != 0 {
		rs.ProxyResolver = &Resolver{
			ipv6:          config.IPv6,
			main:          cacheTransform(config.ProxyServer),
			cache:         config.newCache(),
			hosts:         config.Hosts,
			searchDomains: config.SearchDomains,
		}
	}

	if len(config.DirectServer) != 0 {
		rs.DirectResolver = &Resolver{
			ipv6:          config.IPv6,
			main:          cacheTransform(config.DirectServer),
			cache:         config.newCache(),
			hosts:         config.Hosts,
			searchDomains: config.SearchDomains,
		}
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
		r.fallbackIPFilters = config.FallbackIPFilter
		r.fallbackDomainFilters = config.FallbackDomainFilter
	}

	if len(config.Policy) != 0 {
		r.policy = make([]dnsPolicy, 0)

		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertPolicy := func(policy dnsPolicy) {
			if triePolicy != nil {
				triePolicy.Optimize()
				r.policy = append(r.policy, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
			if policy != nil {
				r.policy = append(r.policy, policy)
			}
		}

		for _, policy := range config.Policy {
			if policy.Matcher != nil {
				insertPolicy(domainMatcherPolicy{matcher: policy.Matcher, dnsClients: cacheTransform(policy.NameServers)})
			} else {
				if triePolicy == nil {
					triePolicy = trie.New[[]dnsClient]()
				}
				_ = triePolicy.Insert(policy.Domain, cacheTransform(policy.NameServers))
			}
		}
		insertPolicy(nil)

		if rs.DirectResolver != nil && config.DirectFollowPolicy {
			rs.DirectResolver.policy = r.policy
		}
	}

	return
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go
