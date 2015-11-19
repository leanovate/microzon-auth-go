package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/untoldwind/routing"
)

type internalResource struct {
	logger logging.Logger
}

type StatusVO struct {
	Version string `json:"version"`
}

func (s *Server) InternalRoutes() routing.Matcher {
	resource := &internalResource{
		logger: s.logger.WithContext(map[string]interface{}{"resource": "internal"}),
	}
	return routing.PrefixSeq("/internal",
		routing.PrefixSeq("/status",
			routing.EndSeq(
				routing.GETFunc(wrap(resource.logger, resource.Status)),
				routing.MethodNotAllowed,
			),
		),
	)
}

func (r *internalResource) Status(req *http.Request) (interface{}, error) {
	return &StatusVO{
		Version: config.Version(),
	}, nil
}
