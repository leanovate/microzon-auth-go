package server

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/leanovate/microzon-auth-go/tokens"
	"github.com/untoldwind/routing"
	"net/http"
	"time"
)

type tokensResource struct {
	store  store.Store
	logger logging.Logger
}

func (s *Server) TokensResource() routing.Matcher {
	resource := &tokensResource{
		store:  s.store,
		logger: s.logger.WithContext(map[string]interface{}{"resource": "tokens"}),
	}
	return routing.PrefixSeq("/tokens",
		routing.EndSeq(
			routing.POSTFunc(wrap(resource.logger, resource.CreateToken)),
			routing.MethodNotAllowed,
		),
	)
}

func (r *tokensResource) CreateToken(req *http.Request) (interface{}, error) {
	selfCert, err := r.store.SelfCerificate()
	if err != nil {
		return nil, err
	}
	return tokens.NewTokenInfo("realm", "user", time.Now().Add(15*time.Minute), selfCert)
}
