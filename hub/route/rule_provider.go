package route

import (
	"context"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ruleProviderRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseRuleProviderName, findRuleProviderByName)
		r.Get("/", getRuleProvider)
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(w http.ResponseWriter, r *http.Request) {
	providers := tunnel.RuleProviders()
	render.JSON(w, r, render.M{
		"providers": providers,
	})
}

func getRuleProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.RuleProvider)
	render.JSON(w, r, provider)
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.RuleProvider)
	if err := provider.Update(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func parseRuleProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findRuleProviderByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProviderName).(string)
		providers := tunnel.RuleProviders()
		provider, exist := providers[name]
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
