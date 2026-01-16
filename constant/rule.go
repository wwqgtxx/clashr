package constant

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	DomainRegex
	DomainWildcard
	GEOIP
	SrcGEOIP
	IPCIDR
	SrcIPCIDR
	IPSuffix
	SrcIPSuffix
	SrcPort
	DstPort
	InPort
	DSCP
	InUser
	InName
	InType
	ProcessName
	ProcessPath
	ProcessNameRegex
	ProcessPathRegex
	ProcessNameWildcard
	ProcessPathWildcard
	Network
	Type_
	IPSet
	MATCH
	RuleSet
	DomainTree
	IpCidrTree
	SubRules
	AND
	OR
	NOT
)

type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case DomainSuffix:
		return "DomainSuffix"
	case DomainKeyword:
		return "DomainKeyword"
	case DomainRegex:
		return "DomainRegex"
	case DomainWildcard:
		return "DomainWildcard"
	case GEOIP:
		return "GeoIP"
	case SrcGEOIP:
		return "SrcGeoIP"
	case IPCIDR:
		return "IPCIDR"
	case SrcIPCIDR:
		return "SrcIPCIDR"
	case IPSuffix:
		return "IPSuffix"
	case SrcIPSuffix:
		return "SrcIPSuffix"
	case SrcPort:
		return "SrcPort"
	case DstPort:
		return "DstPort"
	case InPort:
		return "InPort"
	case InUser:
		return "InUser"
	case InName:
		return "InName"
	case InType:
		return "InType"
	case Network:
		return "Network"
	case DSCP:
		return "DSCP"
	case Type_:
		return "Type"
	case ProcessName:
		return "ProcessName"
	case ProcessPath:
		return "ProcessPath"
	case ProcessNameRegex:
		return "ProcessNameRegex"
	case ProcessPathRegex:
		return "ProcessPathRegex"
	case ProcessNameWildcard:
		return "ProcessNameWildcard"
	case ProcessPathWildcard:
		return "ProcessPathWildcard"
	case IPSet:
		return "IPSet"
	case MATCH:
		return "Match"
	case RuleSet:
		return "RuleSet"
	case DomainTree:
		return "DomainTree"
	case IpCidrTree:
		return "IpCidrTree"
	case SubRules:
		return "SubRules"
	case AND:
		return "AND"
	case OR:
		return "OR"
	case NOT:
		return "NOT"
	default:
		return "Unknown"
	}
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata, helper RuleMatchHelper) (bool, string)
	Adapter() string
	Payload() string
	ProviderNames() []string
}

type RuleMatchHelper struct {
	ResolveIP   func()
	FindProcess func()
}

