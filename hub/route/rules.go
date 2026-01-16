package route

import (
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	r.Patch("/disable", disableRules)
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`

	// from RuleWrapper
	Disabled  bool      `json:"disabled,omitempty"`
	HitCount  uint64    `json:"hitCount,omitempty"`
	HitAt     time.Time `json:"hitAt,omitempty"`
	MissCount uint64    `json:"missCount,omitempty"`
	MissAt    time.Time `json:"missAt,omitempty"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := tunnel.Rules()

	rules := make([]Rule, 0, len(rawRules))
	for index, rule := range rawRules {
		r := Rule{
			Index:   index,
			Type:    rule.RuleType().String(),
			Payload: rule.Payload(),
			Proxy:   rule.Adapter(),
		}
		if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
			r.Disabled = ruleWrapper.IsDisabled()
			r.HitCount = ruleWrapper.HitCount()
			r.HitAt = ruleWrapper.HitAt()
			r.MissCount = ruleWrapper.MissCount()
			r.MissAt = ruleWrapper.MissAt()
			rule = ruleWrapper.Unwrap() // unwrap RuleWrapper
		}
		rules = append(rules, r)
	}

	render.JSON(w, r, render.M{
		"rules": rules,
	})
}

// disableRules disable or enable rules by their indexes.
func disableRules(w http.ResponseWriter, r *http.Request) {
	// key: rule index, value: disabled
	var payload map[int]bool
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if len(payload) != 0 {
		rules := tunnel.Rules()
		for index, disabled := range payload {
			if index < 0 || index >= len(rules) {
				continue
			}
			rule := rules[index]
			if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
				ruleWrapper.SetDisabled(disabled)
			}
		}
	}

	render.NoContent(w, r)
}
