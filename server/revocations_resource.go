package server

import (
	"encoding/json"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/untoldwind/routing"
	"net/http"
	"time"
)

type revocationssResource struct {
	revocationsManager *revocations.RevocationsManager
	logger             logging.Logger
}

func RevocationsRoutes(revocationsManager *revocations.RevocationsManager, parent logging.Logger) routing.Matcher {
	logger := parent.WithContext(map[string]interface{}{"resource": "revocations"})
	resource := &revocationssResource{
		revocationsManager: revocationsManager,
		logger:             logger,
	}
	return routing.PrefixSeq("/revocations",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryRevocations)),
			SendError(logger, MethodNotAllowed()),
		),
		routing.PrefixSeq("/stream",
			routing.EndSeq(
				routing.GETFunc(resource.StreamRevocations),
				SendError(logger, MethodNotAllowed()),
			),
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
		<-r.revocationsManager.Observe.AddObserverWithTimeout(revocations.ObserveState(sinceVersion), time.Duration(timeout)*time.Second)
	}
	return r.revocationsManager.GetRevocationsSinceVersion(sinceVersion, 200), nil
}

func (r *revocationssResource) StreamRevocations(resp http.ResponseWriter, req *http.Request) {
	sinceVersion, err := queryParamUint(req, "since_version", 0)
	if err != nil {
		encodeError(r.logger, resp, req, BadRequest())
		return
	}

	resp.WriteHeader(200)
	encoder := json.NewEncoder(resp)

	for {
		<-r.revocationsManager.Observe.AddObserver(revocations.ObserveState(sinceVersion))

		chunk := r.revocationsManager.GetRevocationsSinceVersion(sinceVersion, 10)
		sinceVersion = chunk.LastVersion
		for _, revocation := range chunk.Revocations {
			encoder.Encode(revocation)
		}
		if flusher, ok := resp.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}
