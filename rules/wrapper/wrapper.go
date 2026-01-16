package wrapper

import (
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type RuleWrapper struct {
	C.Rule
	disabled  atomic.Bool
	hitCount  atomic.Uint64
	hitAt     atomic.Int64 // unix microsecond
	missCount atomic.Uint64
	missAt    atomic.Int64 // unix microsecond
}

func (r *RuleWrapper) IsDisabled() bool {
	return r.disabled.Load()
}

func (r *RuleWrapper) SetDisabled(v bool) {
	r.disabled.Store(v)
}

func (r *RuleWrapper) HitCount() uint64 {
	return r.hitCount.Load()
}

func (r *RuleWrapper) HitAt() time.Time {
	return time.UnixMicro(r.hitAt.Load())
}

func (r *RuleWrapper) MissCount() uint64 {
	return r.missCount.Load()
}

func (r *RuleWrapper) MissAt() time.Time {
	return time.UnixMicro(r.missAt.Load())
}

func (r *RuleWrapper) Unwrap() C.Rule {
	return r.Rule
}

func (r *RuleWrapper) Hit() {
	r.hitCount.Add(1)
	r.hitAt.Store(time.Now().UnixMicro())
}

func (r *RuleWrapper) Miss() {
	r.missCount.Add(1)
	r.missAt.Store(time.Now().UnixMicro())
}

func (r *RuleWrapper) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if r.IsDisabled() {
		return false, ""
	}
	ok, adapter := r.Rule.Match(metadata, helper)
	if ok {
		r.Hit()
	} else {
		r.Miss()
	}
	return ok, adapter
}

func NewRuleWrapper(rule C.Rule) C.RuleWrapper {
	return &RuleWrapper{Rule: rule}
}
