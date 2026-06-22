package common

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/exp/slices"
)

type GEOIP struct {
	Base
	country     string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

var _ C.Rule = (*GEOIP)(nil)

func (g *GEOIP) RuleType() C.RuleType {
	if g.isSourceIP {
		return C.SrcGEOIP
	}
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !g.noResolveIP && !g.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if g.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	if g.country == "lan" {
		return g.isLan(ip), g.adapter
	}

	if g.isSourceIP {
		if metadata.SrcGeoIP != nil {
			return slices.Contains(metadata.SrcGeoIP, g.country), g.adapter
		}
	} else {
		if metadata.DstGeoIP != nil {
			return slices.Contains(metadata.DstGeoIP, g.country), g.adapter
		}
	}
	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	if g.isSourceIP {
		metadata.SrcGeoIP = codes
	} else {
		metadata.DstGeoIP = codes
	}
	if slices.Contains(codes, g.country) {
		return true, g.adapter
	}
	return false, ""
}

// MatchIp implements C.IpMatcher
func (g *GEOIP) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.country == "lan" {
		return g.isLan(ip)
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	return slices.Contains(codes, g.country)
}

// MatchIp implements C.IpMatcher
func (g dnsFallbackFilter) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.isLan(ip) { // compatible with original behavior
		return false
	}

	if g.country == "lan" {
		return !g.isLan(ip)
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	return !slices.Contains(codes, g.country)
}

type dnsFallbackFilter struct {
	*GEOIP
}

func (g *GEOIP) DnsFallbackFilter() C.IpMatcher { // for dns.fallback-filter.geoip
	return dnsFallbackFilter{GEOIP: g}
}

func (g *GEOIP) isLan(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast()
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func (g *GEOIP) GetCountry() string {
	return g.country
}

func (g *GEOIP) GetRecodeSize() int {
	return 0
}

func NewGEOIP(country string, adapter string, isSrc, noResolveIP bool) (*GEOIP, error) {
	country = strings.ToLower(country)

	geoip := &GEOIP{
		Base:        Base{},
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}
	return geoip, nil
}

var _ C.Rule = (*GEOIP)(nil)
