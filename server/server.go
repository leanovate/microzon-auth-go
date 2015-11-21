package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
)

type Server struct {
	config   *config.ServerConfig
	store    store.Store
	listener net.Listener
	logger   logging.Logger
}

func NewServer(config *config.ServerConfig, store store.Store, logger logging.Logger) *Server {
	return &Server{
		config: config,
		store:  store,
		logger: logger.WithContext(map[string]interface{}{"package": "server"}),
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
			s.CertificatesRoutes(),
			s.RevokationsRoutes(),
			s.InternalRoutes(),
		),
	)
}

func wrap(logger logging.Logger, handler func(req *http.Request) (interface{}, error)) func(resp http.ResponseWriter, req *http.Request) {
	f := func(resp http.ResponseWriter, req *http.Request) {
		logger := logger.WithContext(map[string]interface{}{"url": req.URL, "method": req.Method})
		start := time.Now()
		defer func() {
			logger.Debugf("http: Request (%v)", time.Now().Sub(start))
		}()
		obj, err := handler(req)
		if err != nil {
			sendError(logger, resp, req, err)
			return
		}
		if obj != nil {
			var buf []byte
			buf, err = json.Marshal(obj)
			if err != nil {
				sendError(logger, resp, req, err)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Write(buf)
		} else {
			resp.WriteHeader(http.StatusNoContent)
		}
	}
	return f
}

func sendError(logger logging.Logger, resp http.ResponseWriter, req *http.Request, err error) {
	logger.ErrorErr(err)
	code := 500
	errMsg := err.Error()
	switch err.(type) {
	case *HTTPError:
		code = err.(*HTTPError).Status
		errMsg = err.(*HTTPError).Message
	}
	resp.WriteHeader(code)
	resp.Write([]byte(errMsg))
	return
}
