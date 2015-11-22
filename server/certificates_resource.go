package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
)

type certificatesResource struct {
	store  store.Store
	logger logging.Logger
}

func (s *Server) CertificatesRoutes() routing.Matcher {
	resource := &certificatesResource{
		store:  s.store,
		logger: s.logger.WithContext(map[string]interface{}{"resource": "certificates"}),
	}
	return routing.PrefixSeq("/certificates",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryCertificates)),
			SendError(s.logger, MethodNotAllowed()),
		),
		routing.StringPart(
			func(x5t string) routing.Matcher {
				return routing.EndSeq(
					routing.GETFunc(wrap(resource.logger, resource.GetCertBySki(x5t))),
					SendError(s.logger, MethodNotAllowed()),
				)
			},
		),
	)
}

func (r *certificatesResource) QueryCertificates(req *http.Request) (interface{}, error) {
	return r.store.AllCertificates()
}

func (r *certificatesResource) GetCertBySki(x5t string) func(req *http.Request) (interface{}, error) {
	return func(req *http.Request) (interface{}, error) {
		cert, err := r.store.CertificateByThumbprint(x5t)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, NotFound()
		}
		return cert, nil
	}
}
