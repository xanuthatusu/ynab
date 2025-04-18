package server

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Port    int
	Address string
}

func New(logger *logrus.Logger, config *Config) http.Handler {
	mux := http.NewServeMux()
	var handler http.Handler = mux
	// handler = someMiddleware(handler)
	return handler
}
