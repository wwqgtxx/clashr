package rules

import (
	"strings"

	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

type DomainTree struct {
	domain  string
	adapter string
	dt      *trie.DomainTrie
	insertN int
}

func (d *DomainTree) InsertN() int {
	return d.insertN
}

func (d *DomainTree) RuleType() C.RuleType {
	return C.DomainTree
}

func (d *DomainTree) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	return d.dt.Search(metadata.Host) != nil
}

func (d *DomainTree) Adapter() string {
	return d.adapter
}

func (d *DomainTree) Payload() string {
	return d.domain
}

func (d *DomainTree) ShouldResolveIP() bool {
	return false
}

func (d *DomainTree) Insert(domain string) error {
	domain = strings.ToLower(domain)
	err := d.dt.Insert(domain, "")
	if err != nil {
		return err
	}
	d.insertN++
	return nil
}

func newEmptyDomainTree() *DomainTree {
	dt := trie.New()
	return &DomainTree{
		dt:      dt,
		insertN: 0,
	}
}

func NewDomainTree(domain string, adapter string) (*DomainTree, error) {
	dt := newEmptyDomainTree()
	dt.adapter = adapter
	dt.domain = domain
	err := dt.Insert(domain)
	return dt, err
}
