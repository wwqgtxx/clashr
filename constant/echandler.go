package constant

import "github.com/metacubex/http"

var ecHandler http.Handler

func SetECHandler(h http.Handler) {
	ecHandler = h
}

func GetECHandler() http.Handler {
	return ecHandler
}
