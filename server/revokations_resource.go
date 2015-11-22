package server

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
	"net/http"
)

type revokationssResource struct {
	store  store.Store
	logger logging.Logger
}

func (s *Server) RevokationsRoutes() routing.Matcher {
	resource := &revokationssResource{
		store:  s.store,
		logger: s.logger.WithContext(map[string]interface{}{"resource": "revokations"}),
	}
	return routing.PrefixSeq("/revokations",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryRevokations)),
			SendError(s.logger, MethodNotAllowed()),
		),
	)
}

func (r *revokationssResource) QueryRevokations(req *http.Request) (interface{}, error) {
	sinceVersion, err := queryParamUint(req, "since_version", 0)
	if err != nil {
		return nil, BadRequest()
	}
	return r.store.ListRevokations(sinceVersion)
}
