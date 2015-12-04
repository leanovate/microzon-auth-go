package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/untoldwind/routing"
	"runtime"
)

type internalResource struct {
	logger logging.Logger
}

type StatusVO struct {
	Version string `json:"version"`
}

type HealthVO struct {
	MaxProcs     int
	NumGoroutine int
	Memory       runtime.MemStats
}

func (s *Server) InternalRoutes() routing.Matcher {
	resource := &internalResource{
		logger: s.logger.WithContext(map[string]interface{}{"resource": "internal"}),
	}
	return routing.PrefixSeq("/internal",
		routing.PrefixSeq("/status",
			routing.EndSeq(
				routing.GETFunc(wrap(resource.logger, resource.Status)),
				SendError(s.logger, MethodNotAllowed()),
			),
		),
		routing.PrefixSeq("/health",
			routing.EndSeq(
				routing.GETFunc(wrap(resource.logger, resource.Health)),
				SendError(s.logger, MethodNotAllowed()),
			),
		),
		routing.PrefixSeq("/gc",
			routing.EndSeq(
				routing.PUTFunc(wrap(resource.logger, resource.TriggerGC)),
				SendError(s.logger, MethodNotAllowed()),
			),
		),
	)
}

func (r *internalResource) Status(req *http.Request) (interface{}, error) {
	return &StatusVO{
		Version: config.Version(),
	}, nil
}

func (r *internalResource) Health(req *http.Request) (interface{}, error) {
	health := HealthVO{
		MaxProcs:     runtime.GOMAXPROCS(0),
		NumGoroutine: runtime.NumGoroutine(),
	}

	runtime.ReadMemStats(&health.Memory)

	return health, nil
}

func (r *internalResource) TriggerGC(req *http.Request) (interface{}, error) {
	runtime.GC()

	return nil, nil
}
