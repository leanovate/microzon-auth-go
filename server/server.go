package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/leanovate/microzon-auth-go/tokens"
	"github.com/untoldwind/routing"
)

type Server struct {
	config       *config.ServerConfig
	store        store.Store
	tokenManager *tokens.TokenManager
	listener     net.Listener
	logger       logging.Logger
}

func NewServer(config *config.ServerConfig, store store.Store, tokenManager *tokens.TokenManager, logger logging.Logger) *Server {
	return &Server{
		config:       config,
		store:        store,
		tokenManager: tokenManager,
		logger:       logger.WithContext(map[string]interface{}{"package": "server"}),
	}
}

func (s *Server) Start() error {
	ip := net.ParseIP(s.config.BindAddress)

	if ip == nil {
		return fmt.Errorf("Failed to parse IP: %v", s.config.BindAddress)
	}
	bindAddr := &net.TCPAddr{IP: ip, Port: s.config.HttpPort}

	var err error
	s.listener, err = net.Listen(bindAddr.Network(), bindAddr.String())
	if err != nil {
		return err
	}

	go http.Serve(s.listener, s.routeHandler())

	s.logger.Infof("Started http server on %s", bindAddr.String())
	return nil
}

func (s *Server) Stop() {
	s.logger.Info("Stopping http server ...")
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *Server) routeHandler() http.Handler {
	return routing.NewRouteHandler(
		routing.PrefixSeq("/v1",
			s.TokensResource(),
			CertificatesRoutes(s.store, s.logger),
			RevocationsRoutes(s.store, s.logger),
			s.InternalRoutes(),
		),
		SendError(s.logger, NotFound()),
	)
}
