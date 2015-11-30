package server

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
	"net/http"
	"time"
)

type revocationssResource struct {
	store  store.Store
	logger logging.Logger
}

func RevocationsRoutes(store store.Store, parent logging.Logger) routing.Matcher {
	logger := parent.WithContext(map[string]interface{}{"resource": "revocations"})
	resource := &revocationssResource{
		store:  store,
		logger: logger,
	}
	return routing.PrefixSeq("/revocations",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryRevocations)),
			SendError(logger, MethodNotAllowed()),
		),
	)
}

func (r *revocationssResource) QueryRevocations(req *http.Request) (interface{}, error) {
	sinceVersion, err := queryParamUint(req, "since_version", 0)
	if err != nil {
		return nil, BadRequest()
	}
	wait, err := queryParamBool(req, "wait", false)
	if err != nil {
		return nil, BadRequest()
	}
	timeout, err := queryParamUint(req, "timeout", 0)
	if err != nil {
		return nil, BadRequest()
	}

	if wait {
		observer := r.store.ObserveRevocationsVersion(sinceVersion, time.Duration(timeout)*time.Second)
		<-observer
	}
	return r.store.ListRevocations(sinceVersion)
}
